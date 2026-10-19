"""A UPnP renewal must not replace another service's router mapping."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workstation.network import GatewayError, expose_workstation


class FakeGateway:
    lan_address = '192.168.1.124'
    control = 'http://192.168.1.1/control'

    def __init__(self, current=None, permanent=False, wrong_readback=False):
        self.current, self.permanent, self.wrong_readback = current, permanent, wrong_readback
        self.calls = []

    def mapping(self, port):
        return self.current

    def call(self, action, **values):
        self.calls.append((action, values))
        if action == 'GetExternalIPAddress':
            return {'NewExternalIPAddress': '198.51.100.9'}
        if self.permanent and values['NewLeaseDuration']:
            raise GatewayError('OnlyPermanentLeasesSupported', 725)
        self.current = dict(client='192.168.1.9' if self.wrong_readback else self.lan_address,
                            port=values['NewInternalPort'], enabled=True,
                            description=values['NewPortMappingDescription'],
                            lease_seconds=values['NewLeaseDuration'])
        return {}


class WorkstationNetworkTests(unittest.TestCase):
    def test_known_viewer_mapping_renews_and_claims_only_router_proof(self):
        gateway = FakeGateway(dict(client=FakeGateway.lan_address, port=8126, enabled=True,
                                   description='Replay recompiler workstation', lease_seconds=604800))
        result = expose_workstation(8126, gateway)
        self.assertTrue(result['router_mapping_verified'])
        self.assertFalse(result['external_http_verified'])
        self.assertEqual(result['mapping']['description'], 'Replay recompiler workstation')

    def test_another_service_mapping_is_preserved(self):
        for client, description in (('192.168.1.9', 'Replay recompiler workstation'),
                                    (FakeGateway.lan_address, 'Another service')):
            gateway = FakeGateway(dict(client=client, port=8126, description=description))
            with self.assertRaisesRegex(GatewayError, 'owned by another'):
                expose_workstation(8126, gateway)
            self.assertEqual(gateway.calls, [])

    def test_router_permanent_lease_fallback_and_readback_failure(self):
        result = expose_workstation(8126, FakeGateway(permanent=True))
        self.assertEqual(result['mapping']['lease_seconds'], 0)
        with self.assertRaisesRegex(GatewayError, 'readback'):
            expose_workstation(8126, FakeGateway(wrong_readback=True))


if __name__ == '__main__':
    unittest.main()
