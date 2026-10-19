import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from trace_scene_graph import BLOCK, BLOCK_BASE, reserve_insert_pointer


class InsertPointerReservationTests(unittest.TestCase):
    def setUp(self):
        self.stream5 = BLOCK_BASE + 5 * BLOCK

    def test_stream5_active_aligned_advances_active_and_saved_positions(self):
        positions = {5: self.stream5 + 0x20}
        slot, before, after, updated, active = reserve_insert_pointer(
            positions, 5, self.stream5 + 0x20)
        self.assertEqual((slot, before, after),
                         (self.stream5 + 0x20, self.stream5 + 0x20, self.stream5 + 0x28))
        self.assertEqual(updated[5], after)
        self.assertEqual(active, after)
        self.assertEqual(positions[5], self.stream5 + 0x20)

    def test_stream5_active_unaligned_rounds_up_before_reserving(self):
        positions = {5: self.stream5 + 0x21}
        slot, before, after, updated, active = reserve_insert_pointer(
            positions, 5, self.stream5 + 0x21)
        self.assertEqual((slot, before, after),
                         (self.stream5 + 0x28, self.stream5 + 0x21, self.stream5 + 0x30))
        self.assertEqual(updated[5], after)
        self.assertEqual(active, after)

    def test_other_stream_active_updates_only_saved_stream5_cursor(self):
        positions = {1: BLOCK_BASE + BLOCK + 0x80, 5: self.stream5 + 0x21}
        active_before = BLOCK_BASE + BLOCK + 0x88
        slot, before, after, updated, active = reserve_insert_pointer(
            positions, 1, active_before)
        self.assertEqual((slot, before, after),
                         (self.stream5 + 0x28, self.stream5 + 0x21, self.stream5 + 0x30))
        self.assertEqual(updated[5], after)
        self.assertEqual(active, active_before)
        self.assertEqual(updated[1], positions[1])
        self.assertEqual(positions[5], self.stream5 + 0x21)

    def test_rejects_slot_past_stream5_end(self):
        positions = {5: self.stream5 + BLOCK - 4}
        with self.assertRaisesRegex(ValueError, 'outside stream 5'):
            reserve_insert_pointer(positions, 1, BLOCK_BASE + BLOCK + 1)


if __name__ == '__main__':
    unittest.main()
