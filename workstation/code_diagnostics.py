"""Temporary compiler diagnostics for authored files; no source is saved."""
from pathlib import Path
import subprocess
import tempfile


def check_file(project, relative, content, revision):
    from workstation_cpp_sources import compiler_identity
    selected = project.read_file(relative)
    if selected['revision'] != revision:
        raise ValueError('Saved file changed; reload it before validating this buffer')
    if selected['language'] not in ('cpp', 'c'):
        raise ValueError('Live compiler diagnostics support C and C++ files')
    language = selected['language']
    compiler = compiler_identity()
    with tempfile.TemporaryDirectory(prefix='replay-editor-diagnostics-') as folder:
        candidate = Path(folder) / ('candidate.c' if language == 'c' else 'candidate.cpp')
        candidate.write_text(content, encoding='utf-8', newline='\n')
        command = [compiler['path'], '--target=x86_64-pc-windows-msvc', '-x', 'c' if language == 'c' else 'c++',
                   '-std=c17' if language == 'c' else '-std=c++20', '-fsyntax-only', str(candidate),
                   '-ffreestanding', '-Wall', '-Wextra', '-Werror', '-fno-color-diagnostics',
                   '-I', str(project.source_path(relative).parent), '-I', str(project.root / 'src')]
        if language != 'c':
            command += ['-fno-exceptions', '-fno-rtti']
        if Path(relative).suffix.lower() in ('.h', '.hpp'):
            command += ['-Wno-pragma-once-outside-header']
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if compiler_identity() != compiler:
            raise ValueError('Compiler changed while validating this buffer')
        return dict(compiled=result.returncode == 0,
                    diagnostics=(result.stdout + result.stderr).replace(str(candidate), 'candidate').strip()[:24000],
                    target='x86_64-pc-windows-msvc', scope='C/C++ syntax and type checking; no link or game build')
