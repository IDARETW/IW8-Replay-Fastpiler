"""Dependency-free UPnP IGD mapping for the authenticated workstation listener."""
from __future__ import annotations

import ipaddress
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape


class GatewayError(RuntimeError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fields(xml):
    root = ET.fromstring(xml)
    return {node.tag.rsplit('}', 1)[-1]: node.text or '' for node in root.iter()}


class Gateway:
    def __init__(self, control, service):
        self.control, self.service = control, service
        address = urllib.parse.urlsplit(control).hostname
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect((address, 1900))
            self.lan_address = route.getsockname()[0]

    def call(self, action, **arguments):
        values = ''.join(f'<{key}>{escape(str(value))}</{key}>' for key, value in arguments.items())
        body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:{action} xmlns:u="{self.service}">{values}</u:{action}>'
                '</s:Body></s:Envelope>').encode()
        request = urllib.request.Request(self.control, data=body, headers={
            'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': f'"{self.service}#{action}"'})
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                return _fields(response.read(1 << 20))
        except urllib.error.HTTPError as error:
            fields = _fields(error.read(1 << 20))
            raise GatewayError(fields.get('errorDescription', 'UPnP gateway rejected the request'),
                               int(fields['errorCode']) if fields.get('errorCode', '').isdigit() else None) from error

    def mapping(self, port):
        try:
            result = self.call('GetSpecificPortMappingEntry', NewRemoteHost='',
                               NewExternalPort=port, NewProtocol='TCP')
        except GatewayError as error:
            if error.code == 714:
                return None
            raise
        return dict(client=result.get('NewInternalClient'), port=int(result['NewInternalPort']),
                    description=result.get('NewPortMappingDescription', ''),
                    enabled=result.get('NewEnabled') in ('1', 'true'),
                    lease_seconds=int(result.get('NewLeaseDuration', '0')))


def discover_gateway(timeout=3):
    request = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
               'MX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n').encode()
    locations = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as discovery:
        discovery.settimeout(timeout)
        discovery.sendto(request, ('239.255.255.250', 1900))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            discovery.settimeout(max(0.01, end - time.monotonic()))
            try:
                data, _ = discovery.recvfrom(65535)
            except socket.timeout:
                break
            headers = dict(line.split(':', 1) for line in data.decode('latin1').split('\r\n') if ':' in line)
            location = next((value.strip() for key, value in headers.items() if key.lower() == 'location'), None)
            if location:
                locations.add(location)
    for location in sorted(locations):
        parsed = urllib.parse.urlsplit(location)
        try:
            local = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            continue
        if parsed.scheme != 'http' or not (local.is_private or local.is_link_local):
            continue
        with urllib.request.urlopen(location, timeout=8) as response:
            root = ET.fromstring(response.read(1 << 20))
        base = next((node.text for node in root.iter() if node.tag.rsplit('}', 1)[-1] == 'URLBase'), location)
        for node in root.iter():
            if node.tag.rsplit('}', 1)[-1] != 'service':
                continue
            fields = {child.tag.rsplit('}', 1)[-1]: child.text for child in node}
            service = fields.get('serviceType', '')
            if service.startswith(('urn:schemas-upnp-org:service:WANIPConnection:',
                                   'urn:schemas-upnp-org:service:WANPPPConnection:')):
                control = urllib.parse.urljoin(base or location, fields['controlURL'])
                return Gateway(control, service)
    raise GatewayError('No UPnP Internet gateway was discovered')


def expose_workstation(port, gateway=None):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Workstation port must be 1..65535')
    gateway = gateway or discover_gateway()
    current = gateway.mapping(port)
    descriptions = ('Replay recompiler workstation',)
    if current and (current['client'] != gateway.lan_address or current['port'] != port or
                    current['description'] not in descriptions):
        raise GatewayError('External TCP port is owned by another mapping')
    arguments = dict(NewRemoteHost='', NewExternalPort=port, NewProtocol='TCP',
                     NewInternalPort=port, NewInternalClient=gateway.lan_address, NewEnabled=1,
                     NewPortMappingDescription=descriptions[0], NewLeaseDuration=604800)
    try:
        gateway.call('AddPortMapping', **arguments)
    except GatewayError as error:
        if error.code != 725:  # Some routers accept only permanent leases.
            raise
        gateway.call('AddPortMapping', **{**arguments, 'NewLeaseDuration': 0})
    mapping = gateway.mapping(port)
    if not mapping or mapping['client'] != gateway.lan_address or mapping['port'] != port or not mapping['enabled']:
        raise GatewayError('UPnP mapping readback differs from the workstation listener')
    external = gateway.call('GetExternalIPAddress')['NewExternalIPAddress']
    ipaddress.ip_address(external)
    return dict(public_url=f'http://{external}:{port}/', lan_address=gateway.lan_address,
                port=port, protocol='TCP', control_url=gateway.control, mapping=mapping,
                basic_auth=True, router_mapping_verified=True,
                external_http_verified=False, updated_at=int(time.time()))
