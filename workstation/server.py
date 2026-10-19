"""Replay workstation HTTP API; filesystem paths never come from browser URLs."""
from __future__ import annotations

import argparse
import base64
from contextlib import nullcontext
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import threading
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT))
from workstation.backend_identity import BackendChangedError, BackendSnapshot

# Capture before importing the compiler/editor modules. Lazy imports are also
# covered, so they cannot introduce a newer implementation into this process.
BACKEND = BackendSnapshot(ROOT)
from workstation.project import Project, atomic_json, digest
from workstation.config import load_paths
from workstation.toolchain import apply_codec_environment
from workstation_sources import SourceWorkspace
import workstation_asset_codecs as codecs

WEB = Path(__file__).parent / 'web'


class WorkstationHTTPServer(ThreadingHTTPServer):
    # Windows SO_REUSEADDR can admit a second listener on the same endpoint.
    # Only one workstation may own the port and its session token.
    allow_reuse_address = False

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def server_close(self):
        app = getattr(self, "app", None)
        tree = getattr(app, "_workspace_tree", None)
        catalog = getattr(tree, "catalog", None)
        if catalog is not None:
            catalog.close()
        metadata = getattr(app, '_asset_metadata', None)
        if metadata is not None:
            metadata.close()
        cpp_index = getattr(getattr(app, 'sources', None), '_cpp_index', None)
        code_search = getattr(app, '_code_search', None)
        if code_search is not None:
            code_search.close()
        if cpp_index is not None:
            cpp_index.close()
        super().server_close()


class Application:
    def __init__(self, root, cache, game, sqlite, credentials=None, acts=None):
        self.backend = BACKEND
        self.backend.require_current()
        self.project = Project(root, cache, game, sqlite, acts)
        apply_codec_environment(self.project.codec_environment)
        self.sources = SourceWorkspace(root, Path(cache) / 'sources', sqlite)
        self.csrf = secrets.token_urlsafe(32)
        self.credentials = credentials
        self.acts = acts
        self.fastfiles = None
        self.global_sources = None
        self.sound_workspace = None
        self._workspace_tree = None
        self._code_search = None
        self._asset_metadata = None
        self._asset_metadata_lock = threading.Lock()
        self._workspace_tree_lock = threading.Lock()
        self.fastfile_lock = threading.RLock()
        # Start the metadata-only catalog asynchronously; startup and the
        # root/Code folders do not wait for FF inventory work.
        self.workspace_tree()
        self.sources.cpp_index().start()
        self.code_search().start()

    def metadata(self):
        """Display-only native asset index, separate from editor freshness."""
        if self._asset_metadata is None:
            with self._asset_metadata_lock:
                if self._asset_metadata is None:
                    from workstation_asset_metadata import AssetMetadataIndex
                    self._asset_metadata = AssetMetadataIndex(self.archives())
        return self._asset_metadata

    @property
    def asset_metadata(self):
        return self.metadata()

    def archives(self):
        if self.fastfiles is None:
            from workstation_fastfiles import FastfileWorkspace
            self.fastfiles = FastfileWorkspace(self.project.root, self.project.cache / 'fastfiles', self.project.game / 'zone', acts_path=self.acts,
                replay_executable=self.project.game / 'game_dx12_ship_replay.exe',
                lua_acts_path=self.project.lua_acts)
        return self.fastfiles

    def globals(self):
        if self.global_sources is None:
            from workstation_global_sources import GlobalSourceWorkspace
            self.global_sources = GlobalSourceWorkspace(self.project.root, self.project.cache,
                self.project.sqlite, self.project.game / 'game_dx12_ship_replay.exe')
        return self.global_sources

    def sounds(self):
        if self.sound_workspace is None:
            from workstation.soundbanks import SoundBankWorkspace
            self.sound_workspace = SoundBankWorkspace(self.archives(), self.project.cache)
        return self.sound_workspace

    def workspace_tree(self):
        if self._workspace_tree is None:
            with self._workspace_tree_lock:
                if self._workspace_tree is None:
                    from workstation.tree import WorkspaceTree
                    self._workspace_tree = WorkspaceTree(self)
        return self._workspace_tree

    def code_search(self):
        if self._code_search is None:
            from workstation.code_search import CodeSearchIndex
            self._code_search = CodeSearchIndex(self.sources)
        return self._code_search

    def mark_tree_dirty(self, *families):
        if self._code_search is not None:
            self._code_search.wake.set()
        tree = self._workspace_tree
        if tree is not None and tree.catalog is not None:
            tree.catalog.mark_dirty(*families)

    def status(self):
        catalog = self.sources._catalog or self.sources._load_catalog()
        capabilities = codecs.capability_report()
        from workstation_shader_crud import STAGE_NAMES
        capabilities['shader']['row_create_types'] = sorted(STAGE_NAMES)
        capabilities['shader']['row_remove'] = True
        capabilities['shader']['row_remove_types'] = sorted(STAGE_NAMES)
        capabilities['shader']['row_remove_policy'] = ('one exclusive final type-12/14/15/16/17 shader root, owned strings and DXBC child at exact serialized EOF; '
            'shared/inbound ownership is rejected and a full native reread with retained shader semantics is required')
        capabilities['shader']['reason'] += (' Authored compute, vertex, hull, domain and pixel shader rows are created only from stage-matched SM5 assembly through the exact type-specific native stream schedule. '
            'Removal is limited to one exclusive final shader row at exact EOF after complete native reread.')
        capabilities['sfx']['reason'] += (' Trace-linked resident SAB codec-8 entries support PCM16 WAV preview/export, '
            'import with authored duration, sample rate and mono/stereo channel dimensions, volume edits and '
            'revisioned replacement-bank packaging. Gain and export use the selected saved draft. '
            'Audible playback of these changes, other codecs and streamed/hybrid rows remain unverified.')
        capabilities['image']['row_create'] = True
        capabilities['image']['row_create_types'] = [19]
        capabilities['image']['row_remove'] = True
        capabilities['image']['row_create_policy'] = (
            'Strict 2D DDS rows can be appended using a compatible trace-proven inline template; a complete native append/remove round trip passed')
        capabilities['image']['row_remove_policy'] = (
            'Removal is supported only for an exclusive final inline image row ending at exact serialized EOF; a complete native append/remove round trip passed')
        capabilities['localize']['mixed_image_lua_append'] = True
        capabilities['gsc']['row_create'] = True
        capabilities['gsc']['row_create_policy'] = ('single inline ScriptFile append with complete native reread; '
            'inline strings or the configured-tool-bound class-0 opcode-0x18 field subset only')
        capabilities['gsc']['row_remove'] = True
        capabilities['gsc']['row_remove_policy'] = ('one exclusive final inline ScriptFile row ending at exact serialized EOF; '
            'retained inbound/shared references are rejected and a complete native reread is required')
        capabilities['gsc']['reason'] += (' The workstation also supports one new inline ScriptFile row when '
            'the complete source cursor covers the bytecode; nonzero field tokens are limited to the pinned '
            'class-0 opcode-0x18 subset, and other unresolved canonical/source/import IDs are rejected. '
            'Removal is limited to one exclusive final inline row at exact EOF, with no inbound/shared references. '
            'Rename is unsupported. New-script execution is not yet verified.')
        return {'project': str(self.project.root), 'game': str(self.project.game), 'cache': str(self.project.cache),
                'sqlite': str(self.project.sqlite), 'functions': len(catalog['functions']),
                'symbols': len(catalog.get('symbols', [])), 'image_sha256': catalog['image_sha256'],
                'active_job': self.project.active_job, 'asset_codecs': capabilities,
                'backend': self.backend.status(),
                'csrf': self.csrf, 'defaults': {'frontend': 'Native Replay', 'animation': 'No replacements selected'}}


class Handler(BaseHTTPRequestHandler):
    server_version = 'ReplayWorkstation/1'

    def log_message(self, format, *args):
        # Polling the build queue should not drown compiler diagnostics.
        if args and 'POST ' in str(args[0]):
            super().log_message(format, *args)

    @property
    def app(self):
        return self.server.app

    def authorized(self):
        if self.app.credentials is None or self.client_address[0] in ('127.0.0.1', '::1'):
            return True
        expected = 'Basic ' + base64.b64encode((self.app.credentials['username'] + ':' + self.app.credentials['password']).encode()).decode()
        if hmac.compare_digest(self.headers.get('Authorization', ''), expected):
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Replay workstation", charset="UTF-8"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        return False

    def send_json(self, value, status=200):
        data = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path, download=False, *, ranges=False):
        if not path.is_file():
            raise FileNotFoundError('File is missing')
        size = path.stat().st_size
        start, end = 0, size - 1
        requested_range = self.headers.get('Range') if ranges else None
        if requested_range:
            match = re.fullmatch(r'bytes=(\d*)-(\d*)', requested_range)
            valid = bool(match and any(match.groups()) and size)
            if valid:
                first, last = match.groups()
                if first:
                    start, end = int(first), min(int(last), size - 1) if last else size - 1
                else:
                    length = int(last)
                    start, end = max(0, size - length), size - 1
                    valid = length > 0
                valid = valid and 0 <= start <= end < size
            if not valid:
                self.send_response(416)
                self.send_header('Content-Range', f'bytes */{size}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        self.send_response(206 if requested_range else 200)
        self.send_header('Content-Type', mimetypes.guess_type(path.name)[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(end - start + 1))
        if ranges:
            self.send_header('Accept-Ranges', 'bytes')
        if requested_range:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        self.send_header('Cache-Control', 'no-store' if path.suffix == '.html' else 'no-cache')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if download:
            self.send_header('Content-Disposition', f'attachment; filename="{path.name}"')
        self.end_headers()
        with path.open('rb') as stream:
            stream.seek(start)
            remaining = end - start + 1
            try:
                while remaining:
                    chunk = stream.read(min(1 << 20, remaining))
                    if not chunk:
                        raise OSError('Served file was truncated during transfer')
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                # A stopped audio preview cancels its HTTP request normally.
                return

    def do_GET(self):
        if not self.authorized():
            return
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        q = {key: values[0] for key, values in urllib.parse.parse_qs(parsed.query).items()}
        try:
            if path == '/api/status':
                result = self.app.status()
            elif path == '/api/sources':
                with self.app.project.mutation_lock:
                    if q.get('kind') == 'global':
                        rows = self.app.globals().list_editable()
                        needle = q.get('q', '').casefold()
                        rows = [dict(id=r['id'], name=r['name'], kind='global', variants=['global-initializer'], type_name=r['type_name'])
                                for r in rows if needle in f"{r['id']} {r['name']} {r['type_name']}".casefold()]
                        offset, limit = int(q.get('offset', 0)), int(q.get('limit', 100))
                        if offset < 0 or not 1 <= limit <= 1000:
                            raise ValueError('Invalid global page range')
                        items, total = rows[offset:offset+limit], len(rows)
                    else:
                        items, total = self.app.sources.list_sources(q.get('q', ''), int(q.get('offset', 0)), int(q.get('limit', 100)), q.get('kind', 'function'))
                result = {'items': items, 'total': total}
            elif path == '/api/source':
                with self.app.project.mutation_lock:
                    result = self.app.globals().get_source(q['id']) if q.get('variant') == 'global-initializer' else self.app.sources.get_source(q['id'], q.get('variant', 'cpp'))
            elif path == '/api/source-index':
                result = self.app.sources.cpp_index().status()
            elif path == '/api/changes':
                from workstation.change_review import list_changes
                with self.app.project.mutation_lock:
                    result = list_changes(self.app)
            elif path == '/api/asset-changes':
                from workstation.asset_review import list_asset_changes
                with self.app.fastfile_lock:
                    result = list_asset_changes(self.app)
            elif path == '/api/change':
                if q.get('kind') in ('asset', 'sound'):
                    from workstation.asset_review import get_asset_change, get_audio_change
                    with self.app.fastfile_lock:
                        reader = get_asset_change if q['kind'] == 'asset' else get_audio_change
                        result = reader(self.app, q['id'])
                else:
                    from workstation.change_review import get_change
                    with self.app.project.mutation_lock:
                        result = get_change(self.app, q.get('kind', 'source'), q['id'], q.get('variant', 'cpp'))
            elif path == '/api/source/context':
                from workstation.cross_references import inspect_symbol
                with self.app.project.mutation_lock:
                    result = inspect_symbol(self.app.sources, identity=q.get('id'), query=q.get('q', ''),
                                            offset=int(q.get('offset', 0)), limit=int(q.get('limit', 12)))
            elif path == '/api/files':
                result = {'items': self.app.project.authored_files()}
            elif path == '/api/workspace/tree':
                tree = self.app.workspace_tree()
                node_id = q.get('node')
                node = tree.decode_node(node_id)
                kind = node['kind']
                if tree.catalog is not None:
                    # Catalog-backed rows are immutable display snapshots. The
                    # background validator owns parser locks; tree reads stay fast.
                    lock = nullcontext()
                elif kind in {'root', 'code'}:
                    lock = nullcontext()
                elif kind in {'code-group', 'code-prefix', 'authored', 'authored-dir'}:
                    lock = self.app.project.mutation_lock
                elif kind in {'assets', 'zone-dir', 'zone', 'asset-type', 'asset-dir'}:
                    lock = self.app.fastfile_lock
                else:
                    raise ValueError('Unsupported workspace tree node')
                with lock:
                    result = tree.get(node_id, q.get('q', ''),
                        int(q.get('offset', 0)), int(q.get('limit', 100)),
                        _decoded_node=node)
            elif path == '/api/file':
                with self.app.project.mutation_lock:
                    result = self.app.project.read_file(q['path'])
            elif path == '/api/workspace/search':
                search = self.app.code_search() if q.get('mode') == 'code' else self.app.workspace_tree()
                result = search.search(q.get('q', ''),
                    int(q.get('offset', 0)), int(q.get('limit', 100)))
            elif path == '/api/workspace/asset-index':
                result = self.app.metadata().snapshot()
                result.pop('files', None)
                result.pop('identity', None)
            elif path == '/api/fastfiles':
                with self.app.fastfile_lock:
                    result = self.app.archives().list_fastfiles(q.get('q', ''), int(q.get('offset', 0)), int(q.get('limit', 100)))
                if isinstance(result, tuple):
                    result = {'items': result[0], 'total': result[1]}
            elif path == '/api/assets':
                with self.app.fastfile_lock:
                    result = self.app.archives().list_assets(q['zone'], q.get('q', ''), int(q.get('offset', 0)), int(q.get('limit', 100)))
                if isinstance(result, tuple):
                    result = {'items': result[0], 'total': result[1]}
            elif path == '/api/asset':
                with self.app.fastfile_lock:
                    archives = self.app.archives()
                    asset_id = q['id']
                    native_id = re.fullmatch(r'([0-9a-f]{64}):([0-9]+)', asset_id)
                    if native_id:
                        metadata = getattr(self.app, 'asset_metadata', None)
                        basic_asset = metadata.read_only_asset(asset_id) if metadata is not None else None
                        if basic_asset is not None:
                            return self.send_json(basic_asset)
                        zone_id = native_id[1]
                        receipts = list(archives.cache_root.glob(f'*/{zone_id}/decode-receipt.json'))
                        if not receipts:
                            return self.send_json({'error': 'This asset payload is not cached yet.',
                                'code': 'asset_payload_cache_missing', 'zone_id': zone_id,
                                'asset_id': asset_id}, 400)
                        if len(receipts) > 1:
                            return self.send_json({'error': 'The decoded zone cache has ambiguous receipts.',
                                'code': 'asset_payload_cache_ambiguous', 'zone_id': zone_id,
                                'asset_id': asset_id}, 400)
                    from workstation_fastfiles import UnsupportedAssetGraphError
                    try:
                        result = archives.get_asset(q['id'])
                    except UnsupportedAssetGraphError as error:
                        # A native table identity remains browsable even when
                        # its payload family has no typed editor. Do not pass
                        # through malformed/failed codec validation here:
                        # only the explicit unsupported-graph signal reaches
                        # this read-only metadata fallback.
                        zone_id, _, index = q['id'].rpartition(':')
                        if not index.isdecimal():
                            raise ValueError(str(error)) from error
                        page = archives.list_assets(zone_id, offset=int(index), limit=1)
                        row = page['items'][0] if page['items'] else {}
                        if row.get('asset_id') != q['id'] or row.get('index') != int(index):
                            raise ValueError(str(error)) from error
                        if row.get('type_id') == 21:
                            type_name = 'soundbank'
                            payload_format = 'Native SoundBank aliases and resident SAB entries'
                            package_status = ('Audio edits below are saved separately and compile into a replacement SAB bank; '
                                              'native SndAlias XAsset editing is unavailable.')
                        else:
                            type_name = row.get('native_type_name') or f"type-{row.get('type_id')}"
                            payload_format = 'Native XAsset table identity only'
                            package_status = ('This XAsset is visible by its native table identity. A typed payload reader/editor '
                                              'is not available for this asset, so no payload bytes are presented as editable.')
                        result = dict(row, type=type_name, content=None, language='plaintext',
                            revision=None, editable=False, archive_writable=False,
                            payload_format=payload_format, package_status=package_status)
            elif path == '/api/asset-edits':
                with self.app.fastfile_lock:
                    result = self.app.archives().list_pending_edits(q.get('zone'), q.get('q', ''), int(q.get('offset', 0)), int(q.get('limit', 100)))
            elif path == '/api/sounds':
                with self.app.fastfile_lock:
                    result = self.app.sounds().list_entries(q['path'])
                    result['drafts'] = self.app.sounds().drafts.list_drafts(result['zone_id'])
            elif path in ('/api/sound/export', '/api/sound/wav'):
                with self.app.fastfile_lock:
                    sounds = self.app.sounds()
                    result = (sounds.export_draft_wav(q['zone'], q['asset'], int(q['file']), q['revision'])
                        if q.get('draft') == '1' else sounds.export_wav(q['zone'], q['asset'], int(q['file'])))
                    if path == '/api/sound/wav':
                        audio_path = Path(result['wav_path'])
                        if digest(audio_path) != result['wav_sha256']:
                            raise ValueError('Cached audio differs from its decode receipt; export again')
                if path == '/api/sound/wav':
                    return self.send_file(audio_path, q.get('download') == '1', ranges=True)
            elif path == '/api/sound/drafts':
                with self.app.fastfile_lock:
                    result = {'items': self.app.sounds().drafts.list_drafts(q.get('zone'))}
            elif path == '/api/jobs':
                result = {'items': self.app.project.jobs()}
            elif path == '/api/job':
                result = self.app.project.job(q['id'])
            elif path == '/api/log':
                result = self.app.project.log(q['id'], int(q.get('offset', 0)))
            elif path == '/api/download':
                job = self.app.project.job(q['job'])
                if job['status'] != 'succeeded':
                    raise ValueError('Build has not passed verification')
                artifact = next(a for a in job['artifacts'] if a['name'] == q['name'])
                if digest(artifact['path']) != artifact['sha256']:
                    raise ValueError('The replacement file changed after verification; compile again')
                return self.send_file(Path(artifact['path']), True)
            else:
                relative = 'index.html' if path == '/' else path.lstrip('/')
                static = (WEB / relative).resolve()
                if not static.is_relative_to(WEB):
                    raise ValueError('Invalid web file path')
                return self.send_file(static)
            self.send_json(result)
        except (KeyError, ValueError, FileNotFoundError, NotImplementedError) as error:
            self.send_json({'error': str(error)}, 400)
        except Exception as error:
            self.send_json({'error': str(error)}, 500)

    def do_POST(self):
        if not self.authorized():
            return
        if not hmac.compare_digest(self.headers.get('X-Replay-Token', ''), self.app.csrf):
            return self.send_json({'error': 'Reload this workstation tab before saving'}, 403)
        origin = self.headers.get('Origin')
        if origin and urllib.parse.urlsplit(origin).netloc != self.headers.get('Host'):
            return self.send_json({'error': 'Request origin differs from workstation'}, 403)
        try:
            self.app.backend.require_current()
            path = urllib.parse.urlsplit(self.path).path
            length = int(self.headers.get('Content-Length', 0))
            body_limit = (128 if path == '/api/sound/save' else 32) * 1024 * 1024
            if length < 1 or length > body_limit:
                raise ValueError(f'Request body must be 1 byte to {body_limit // (1024 * 1024)} MiB')
            body = json.loads(self.rfile.read(length))
            if path == '/api/fastfile/extract':
                with self.app.fastfile_lock:
                    self.app.backend.require_current()
                    result = self.app.archives().extract(body['path'])
                self.app.mark_tree_dirty('asset_directories', 'inventories')
                return self.send_json(result)
            with self.app.project.mutation_lock:
                # A request may have waited on a large body or another build.
                self.app.backend.require_current()
                if path == '/api/build':
                    result = self.app.project.start_build(body.get('profile', 'current'))
                elif path == '/api/source/check':
                    from workstation_cpp_sources import compile_check
                    with self.app.project.mutation_lock:
                        source = self.app.sources.get_source(body['id'], 'cpp')
                        if not source.get('editable') or not source.get('symbol'):
                            raise ValueError('Select an editable recovered function')
                        if body.get('revision') != source.get('revision'):
                            raise ValueError('Recovery inputs changed; reload the source before validating')
                        result = compile_check(self.app.project.root, body['content'], source['symbol'], source['language'])
                elif path == '/api/file/check':
                    from workstation.code_diagnostics import check_file
                    result = check_file(self.app.project, body['path'], body['content'], body['revision'])
                elif path == '/api/source/save':
                    self.app.project.ensure_mutable()
                    result = self.app.globals().save_source(body['id'], body['content'], body.get('revision')) if body.get('variant') == 'global-initializer' else self.app.sources.save_source(body['id'], body['content'], body.get('revision'), body.get('variant', 'cpp'))
                    self.app.mark_tree_dirty('globals' if body.get('variant') == 'global-initializer' else 'functions', 'symbols')
                elif path == '/api/source/create':
                    self.app.project.ensure_mutable()
                    result = self.app.sources.create_source(body['name'], body['language'], body['content'])
                    self.app.mark_tree_dirty('functions', 'symbols')
                elif path == '/api/source/remove':
                    self.app.project.ensure_mutable()
                    result = self.app.globals().restore_source(body['id'], body['revision']) if body.get('variant') == 'global-initializer' else self.app.sources.remove_source(body['id'], body['revision'], body.get('variant', 'cpp'))
                    self.app.mark_tree_dirty('globals' if body.get('variant') == 'global-initializer' else 'functions', 'symbols')
                elif path == '/api/file/save':
                    self.app.project.ensure_mutable()
                    current_file = self.app.project.read_file(body['path'])
                    if current_file['revision'] != body['revision']:
                        raise ValueError('Revision conflict; reload the source file')
                    tracked = next(((identity, variant) for identity, variants in self.app.sources._state()['sources'].items()
                                    for variant, entry in variants.items() if entry['path'] == current_file['path']), None)
                    if tracked:
                        identity, variant = tracked
                        current_source = self.app.sources.get_source(identity, variant)
                        self.app.sources.save_source(identity, body['content'], current_source['revision'], variant)
                        result = self.app.project.read_file(body['path'])
                    else:
                        result = self.app.project.save_file(body['path'], body['content'], body['revision'])
                    self.app.mark_tree_dirty('authored', 'functions', 'symbols')
                elif path == '/api/asset/save':
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        result = self.app.archives().save_asset(**body)
                    self.app.mark_tree_dirty('inventories')
                elif path == '/api/asset/recompile':
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        result = self.app.archives().recompile_asset(**body)
                    self.app.mark_tree_dirty('inventories')
                elif path == '/api/asset/create':
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        result = self.app.archives().create_asset(**body)
                    self.app.mark_tree_dirty('inventories')
                elif path == '/api/asset/discard':
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        result = self.app.archives().discard_asset_edit(**body)
                    self.app.mark_tree_dirty('inventories')
                elif path == '/api/asset/restore':
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        result = self.app.archives().restore_asset_edit(**body)
                    self.app.mark_tree_dirty('inventories')
                elif path == '/api/asset/remove':
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        result = self.app.archives().remove_asset(**body)
                    self.app.mark_tree_dirty('inventories')
                elif path in ('/api/sound/save', '/api/sound/gain', '/api/sound/discard'):
                    self.app.project.ensure_mutable()
                    with self.app.fastfile_lock:
                        sounds = self.app.sounds()
                        if path == '/api/sound/discard':
                            result = sounds.discard(body['zone_id'], int(body['file_id']), body['revision'])
                        elif path == '/api/sound/gain':
                            result = sounds.stage_gain(body['zone_id'], body['asset_id'], int(body['file_id']),
                                body['gain'], body.get('revision'))
                        else:
                            wav = base64.b64decode(body['wav_base64'], validate=True)
                            result = sounds.stage_wav(body['zone_id'], body['asset_id'], int(body['file_id']),
                                wav, body.get('revision'))
                    self.app.mark_tree_dirty('inventories')
                else:
                    raise ValueError('Unknown workstation action')
            self.send_json(result)
        except BackendChangedError as error:
            self.send_json({'error': str(error), 'restart_required': True}, 409)
        except (KeyError, ValueError, FileNotFoundError, NotImplementedError) as error:
            self.send_json({'error': str(error)}, 400)
        except Exception as error:
            self.send_json({'error': str(error)}, 500)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--game', type=Path)
    parser.add_argument('--sqlite', type=Path)
    parser.add_argument('--acts', type=Path, help='Replay-compatible ACTS CLI; its adjacent dependency closure is hashed')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8126)
    parser.add_argument('--credentials', type=Path)
    parser.add_argument('--upnp', action='store_true', help='Map the authenticated listener through the local UPnP gateway')
    args = parser.parse_args()
    defaults = load_paths(args.root)
    args.game = (args.game or defaults['game']).resolve()
    args.sqlite = (args.sqlite or (args.game / 'game_dx12_ship_replay.exe.sqlite' if '--game' in sys.argv else defaults['sqlite'])).resolve()
    args.cache = (args.cache or defaults['cache']).resolve()
    args.acts = args.acts or defaults['acts']
    credentials = json.loads(args.credentials.read_text()) if args.credentials else None
    if args.host not in ('127.0.0.1', 'localhost', '::1') and credentials is None:
        parser.error('An external listener requires a private credentials file')
    if args.upnp and (credentials is None or args.host in ('127.0.0.1', 'localhost', '::1')):
        parser.error('--upnp requires an external listener and a private credentials file')
    server = WorkstationHTTPServer((args.host, args.port), Handler)
    try:
        server.app = Application(args.root, args.cache, args.game, args.sqlite, credentials, args.acts)
        server.app.metadata().start()
        if args.upnp:
            from workstation.network import expose_workstation
            mapping = expose_workstation(args.port)
            atomic_json(args.cache / 'network.json', mapping)
            print(f'UPnP workstation: {mapping["public_url"]}', flush=True)
    except Exception:
        server.server_close()
        raise
    print(f'Replay workstation: http://{args.host}:{args.port}', flush=True)
    atomic_json(args.cache / 'server.json', {'pid': os.getpid(), 'host': args.host, 'port': args.port, 'project': str(args.root.resolve())})
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
