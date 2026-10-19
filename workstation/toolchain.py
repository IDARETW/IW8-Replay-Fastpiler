"""Resolve codec configuration into a reproducible child-process environment."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re


TOOL_ENVIRONMENT = {
    'gsc': 'REPLAY_GSC_TOOL',
    'luajit_decompiler': 'REPLAY_LUAJIT_DECOMPILER',
    'dxbc': 'REPLAY_DXBC_TOOL',
    'texconv': 'REPLAY_TEXCONV',
    'sab_generator': 'REPLAY_SAB_GENERATOR',
    'script_source_pack': 'REPLAY_SCRIPT_SOURCE_PACK',
    'script_string_decryptor': 'REPLAY_SCRIPT_STRING_DECRYPTOR',
    'zonetool_source': 'REPLAY_ZONETOOL_SOURCE',
    'cxx': 'REPLAY_CXX',
}


def resolve_codec_environment(root, game, acts=None, tools=None, environment=None,
                              proxy_source=None, lua_acts=None):
    """Resolve paths relative to the checkout and preserve explicit overrides.

    Overrides are deliberate local choices, never function-address settings.
    Hashes from setup receipts bind source-built or public-release tool choices.
    """
    root, game = Path(root).resolve(), Path(game).resolve()
    environment = os.environ if environment is None else environment
    tools = tools or {}
    if not isinstance(tools, dict) or set(tools) - set(TOOL_ENVIRONMENT):
        raise ValueError('Unsupported workstation codec tool configuration')
    result = {'REPLAY_EXECUTABLE': str(game / 'game_dx12_ship_replay.exe')}
    if acts:
        result['REPLAY_ACTS'] = str(Path(acts).resolve())
        result['REPLAY_ACTS_PROFILE'] = str(Path(acts).resolve().with_name('replay120_lua_native.json'))
    selected_lua_acts = environment.get('REPLAY_LUA_ACTS') or lua_acts
    if selected_lua_acts:
        candidate = Path(selected_lua_acts).expanduser()
        candidate = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f'Configured Lua compiler executable is unavailable: {candidate}')
        native_reader = Path(acts).resolve() if acts else None
        if native_reader is None or candidate != native_reader:
            result['REPLAY_LUA_ACTS'] = str(candidate)
            result['REPLAY_LUA_ACTS_PROFILE'] = str(candidate.with_name('replay120_lua_native.json'))
    proxy_value = environment.get('REPLAY_PROXY_SOURCE') or proxy_source
    if proxy_value:
        candidate = Path(proxy_value).expanduser()
        proxy_path = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        if not proxy_path.is_dir() or not any(proxy_path.glob('*.cpp')):
            raise ValueError(f'Configured Replay proxy source is unavailable or has no C++ sources: {proxy_path}')
        result['REPLAY_PROXY_SOURCE'] = str(proxy_path)
    for name, variable in TOOL_ENVIRONMENT.items():
        entry = tools.get(name) or {}
        if isinstance(entry, str):
            entry = {'path': entry}
        if not isinstance(entry, dict) or set(entry) - {'path', 'sha256'}:
            raise ValueError(f'Invalid codec tool configuration: {name}')
        override = environment.get(variable)
        path_value = override or entry.get('path')
        if not path_value:
            continue
        path = Path(path_value).expanduser()
        path = (root / path).resolve() if not path.is_absolute() else path.resolve()
        directory = name in ('script_string_decryptor', 'zonetool_source')
        if not (path.is_dir() if directory else path.is_file()):
            raise FileNotFoundError(f'Configured codec tool is unavailable: {path}')
        if name == 'zonetool_source' and not (path / 'src/zonetool/iw8/iw8_zone.cpp').is_file():
            raise ValueError('Configured ZoneTool directory lacks the native IW8 writer source')
        expected = (environment.get(variable + '_SHA256') if override else entry.get('sha256'))
        if expected:
            if directory:
                if name == 'script_string_decryptor':
                    raise ValueError('String transform source hashes are validated by its pinned bootstrap manifest')
                raise ValueError('Directory source hashes must be validated by their source-build manifests')
            if not isinstance(expected, str) or re.fullmatch(r'[0-9a-fA-F]{64}', expected) is None:
                raise ValueError(f'Invalid SHA-256 for codec tool: {name}')
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected.casefold():
                raise ValueError(f'Configured codec tool hash mismatch: {name}')
            result[variable + '_SHA256'] = expected.casefold()
        result[variable] = str(path)
    for variable in ('REPLAY_ACTS_PROFILE', 'REPLAY_LUA_ACTS_PROFILE'):
        profile = environment.get(variable)
        if profile:
            result[variable] = str(Path(profile).expanduser().resolve())
    return result


def apply_codec_environment(environment):
    """Activate one immutable configuration before any asset codecs are used."""
    allowed = {'REPLAY_EXECUTABLE', 'REPLAY_ACTS', 'REPLAY_ACTS_PROFILE',
               'REPLAY_LUA_ACTS', 'REPLAY_LUA_ACTS_PROFILE', 'REPLAY_PROXY_SOURCE'}
    allowed |= set(TOOL_ENVIRONMENT.values())
    allowed |= {value + '_SHA256' for value in TOOL_ENVIRONMENT.values()}
    if not isinstance(environment, dict) or set(environment) - allowed:
        raise ValueError('Worker codec environment contains unsupported settings')
    for key, value in environment.items():
        if not isinstance(value, str) or not value:
            raise ValueError('Worker codec environment settings must be nonempty strings')
        os.environ[key] = value
