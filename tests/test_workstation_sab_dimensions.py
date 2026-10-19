"""Authored WAV dimensions must survive draft editing and native SAB packing."""
from pathlib import Path
import hashlib
import io
import os
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import workstation_sab_editor as sab
from workstation_sab_drafts import SoundBankDraftStore
from workstation.soundbanks import SoundBankWorkspace


def bank_fixture(np, sf):
    pcm = np.arange(128, dtype=np.int16)[:, None]
    encoded = io.BytesIO()
    sf.write(encoded, pcm, 22050, format='FLAC', subtype='PCM_16')
    _, payload = sab._flac_frames(encoded.getvalue())
    data = bytearray(sab.DATA_START)
    struct.pack_into('<4I', data, 0, sab.MAGIC, 10, sab.ENTRY_SIZE, sab.CHECKSUM_SIZE)
    struct.pack_into('<I', data, 20, 2)
    struct.pack_into('<I', data, 28, 16)
    data[56:72] = b'opaque checksum!'
    rows = []
    for file_id in (77, 88):
        offset = len(data)
        data.extend(payload)
        data.extend(b'GAP!')
        row = bytearray(44)
        sab.ROW.pack_into(row, 0, file_id, len(payload), 0, 128, 0,
                          offset, 22050, 1, 1, 8)
        row[35:] = b'reserved!'
        rows.append(row)
    index = sab._align(len(data))
    data.extend(bytes(index - len(data)))
    for row in rows:
        data.extend(row)
    checksums = len(data)
    data.extend(b'A' * 16 + b'B' * 16 + b'trailer')
    struct.pack_into('<3Q', data, 32, len(data), index, checksums)
    struct.pack_into('<I', data, 679, len(data) - sab.HEADER_SIZE)
    return bytes(data)


class SabDimensionsTests(unittest.TestCase):
    def test_authored_dimensions_package_and_gain_uses_saved_draft(self):
        dependency = os.environ.get('REPLAY_SOUNDFILE_ROOT')
        np, sf = sab._soundfile(dependency)
        original = bank_fixture(np, sf)
        authored_pcm = np.column_stack((np.arange(333, dtype=np.int16),
                                       -np.arange(333, dtype=np.int16)))
        wav_stream = io.BytesIO()
        sf.write(wav_stream, authored_pcm, 32000, format='WAV', subtype='PCM_16')
        wav = wav_stream.getvalue()
        with tempfile.TemporaryDirectory(prefix='sab-dimensions-') as temporary:
            folder = Path(temporary)
            base, patch = folder / 'base.sabs', folder / 'patch_base.sabs'
            base.write_bytes(original)
            patch_data = bytearray(original)
            parsed = sab.parse_sab(original)
            for row in parsed.rows:
                struct.pack_into('<I', patch_data, parsed.index_offset + row.index * 44,
                                 row.file_id + 1000)
            patch.write_bytes(patch_data)
            store = SoundBankDraftStore(folder / 'cache')
            result = store.stage_entry(zone_id='fixture', base_sab=base, patch_sab=patch,
                file_id=77, linked_alias={'file_id':77, 'asset_file_name':'fixture.flac',
                'source_identity_sha256':'a' * 64}, wav_bytes=wav, soundfile_root=dependency)
            expected = {'rate':32000, 'channels':2, 'frames':333}
            self.assertEqual(result['authored_dimensions'], expected)
            self.assertEqual(store.list_drafts('fixture')[0]['authored_dimensions'], expected)
            published = store.package_zone(zone_id='fixture', output_dir=folder / 'output',
                soundfile_root=dependency, expected_snapshot=store.pending_snapshot('fixture'))
            output = Path(published['output']['path']).read_bytes()
            reread = sab.parse_sab(output)
            changed, retained = reread.rows
            self.assertEqual((changed.rate, changed.channels, changed.frames), (32000, 2, 333))
            self.assertEqual(changed.raw[33:], parsed.rows[0].raw[33:])
            self.assertEqual(output[retained.offset:retained.offset + retained.extent_size],
                             original[parsed.rows[1].offset:parsed.rows[1].offset + parsed.rows[1].extent_size])
            self.assertEqual(parsed.checksums, reread.checksums)
            decoded, rate = sf.read(io.BytesIO(sab._wrap_frames(
                output[changed.offset:changed.offset + changed.size], changed.rate,
                changed.channels, changed.frames)), dtype='int16', always_2d=True)
            self.assertEqual(rate, 32000)
            self.assertTrue(np.array_equal(decoded, authored_pcm))
            with self.assertRaises(FileExistsError):
                store.package_zone(zone_id='fixture', output_dir=folder / 'output',
                    soundfile_root=dependency, expected_snapshot=store.pending_snapshot('fixture'))
            self.assertEqual(Path(published['output']['path']).read_bytes(), output)
            collision = folder / 'receipt-collision'
            collision.mkdir()
            old_receipt = collision / 'base.sab-draft-receipt.json'
            old_receipt.write_bytes(b'owner receipt')
            with self.assertRaises(FileExistsError):
                store.package_zone(zone_id='fixture', output_dir=collision,
                    soundfile_root=dependency, expected_snapshot=store.pending_snapshot('fixture'))
            self.assertFalse((collision / 'base.sabs').exists())
            self.assertEqual(old_receipt.read_bytes(), b'owner receipt')

            class DraftWorkspace:
                soundfile_root = dependency
                def export_draft_wav(self, zone, asset, file_id, revision):
                    if revision != result['revision']:
                        raise AssertionError('wrong saved revision')
                    current, row, _ = store._read_current(zone, file_id)
                    return {'wav_path':str(current.parent / row['wav_payload_name'])}
                def export_wav(self, *_args):
                    raise AssertionError('gain must use the saved draft')
                def stage_wav(self, zone, asset, file_id, data, revision):
                    self.saved = data
                    return {'revision':revision}
            workspace = DraftWorkspace()
            SoundBankWorkspace.stage_gain(workspace, 'fixture', 'fixture:0', 77, 0.5,
                                           result['revision'])
            self.assertEqual(sab._validate_pcm16_wav(workspace.saved), (32000, 2, 333))
            gained, _ = sf.read(io.BytesIO(workspace.saved), dtype='int16', always_2d=True)
            self.assertTrue(np.array_equal(gained, np.rint(authored_pcm * 0.5).astype(np.int16)))
            self.assertEqual(hashlib.sha256(base.read_bytes()).digest(), hashlib.sha256(original).digest())


if __name__ == '__main__':
    unittest.main()
