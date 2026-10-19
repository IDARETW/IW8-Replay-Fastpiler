"""Local workstation paths; this file contains no credentials or game data."""
import json
import os
from pathlib import Path


def load_paths(root):
    root = Path(root).resolve()
    config = root / 'replay-project.local.json'
    document = json.loads(config.read_text(encoding='utf-8-sig')) if config.is_file() else {}
    if document and document.get('schema') != 1:
        raise ValueError('Unsupported local workstation configuration schema')
    game = Path(document.get('game') or os.environ.get('REPLAY_GAME_ROOT') or r'E:\IW8\Builds\1.20-replay').expanduser().resolve()
    sqlite = Path(document.get('sqlite') or os.environ.get('REPLAY_SQLITE') or game / 'game_dx12_ship_replay.exe.sqlite').expanduser().resolve()
    cache = Path(document.get('cache') or os.environ.get('REPLAY_WORKSTATION_CACHE') or
                 Path(os.environ.get('LOCALAPPDATA', Path.home() / '.cache')) / 'ReplayCompilerWorkstation').expanduser().resolve()
    build_root_value = os.environ.get('REPLAY_WORKSTATION_BUILD_ROOT') or document.get('build_root')
    build_root = Path(build_root_value).expanduser() if build_root_value else root
    if not build_root.is_absolute():
        build_root = root / build_root
    build_root = build_root.resolve()
    publication_root_value = os.environ.get('REPLAY_WORKSTATION_OUTPUT_ROOT') or document.get('publication_root')
    publication_root = Path(publication_root_value).expanduser() if publication_root_value else root / 'output'
    if not publication_root.is_absolute():
        publication_root = root / publication_root
    publication_root = publication_root.resolve()
    acts_value = os.environ.get('REPLAY_ACTS') or document.get('acts')
    acts = Path(acts_value).expanduser().resolve() if acts_value else None
    lua_acts_value = os.environ.get('REPLAY_LUA_ACTS') or document.get('lua_acts')
    lua_acts = Path(lua_acts_value).expanduser().resolve() if lua_acts_value else None
    proxy_value = document.get('proxy_source')
    proxy_source = None
    if proxy_value:
        candidate = Path(proxy_value).expanduser()
        proxy_source = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    return {'game': game, 'sqlite': sqlite, 'cache': cache, 'acts': acts,
            'build_root': build_root, 'publication_root': publication_root,
            'lua_acts': lua_acts,
            'tools': document.get('tools', {}), 'proxy_source': proxy_source,
}
