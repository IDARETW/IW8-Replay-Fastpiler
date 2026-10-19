from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build
import coff
import native_operand_references as refs


class NativeOperandReferencesTests(unittest.TestCase):
    def test_displacement_and_immediate_on_one_instruction_retain_both_relocations(self):
        immediate = dict(rva=0x1000, operand=1, kind='immediate', target=0x3000)
        displacement = dict(rva=0x1000, operand=0, kind='displacement', target=0x2000)
        added = refs.merge([immediate], [displacement])
        grouped = refs.group([immediate] + added)
        source = refs.symbolize('dword ptr [rbx + 0x2000], 0x3000', grouped[0x1000], 0x1000)
        with tempfile.TemporaryDirectory(prefix='replay-native-operands-') as directory:
            path = Path(directory) / 'two-operands.s'
            target = path.with_suffix('.obj')
            path.write_text('.intel_syntax noprefix\n.text\nmov ' + source + '\nret\n', encoding='ascii')
            subprocess.run([str(build.LLVM / 'clang.exe'), '--target=x86_64-pc-windows-msvc',
                            '-c', str(path), '-o', str(target)], check=True, capture_output=True, text=True)
            obj = coff.read(target)
            text = next(s for s in obj['sections'] if s['name'] == '.text')
            targets = [(at, obj['symbols'][symbol]['name'], kind) for at, symbol, kind in text['relocations']]
            self.assertEqual(targets, [(2, 'replay_rva_00002000', 3), (6, 'replay_rva_00003000', 3)])

    def test_conflicting_same_operand_is_rejected(self):
        original = dict(rva=0x1000, operand=0, kind='displacement', target=0x2000)
        with self.assertRaisesRegex(ValueError, 'Conflicting native operand'):
            refs.merge([original], [dict(original, target=0x3000)])
        self.assertEqual(refs.merge([original], [dict(original)]), [])
        with self.assertRaisesRegex(ValueError, 'Duplicate native operand'):
            refs.group([original, dict(original)])


if __name__ == '__main__':
    unittest.main()
