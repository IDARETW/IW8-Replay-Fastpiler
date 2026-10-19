from __future__ import annotations

import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_stringtable import validate_complete_stream5_allocations


def span(start: int, size: int, sequence: int, *, origin: str = "unclassified_load",
         owner_archive: int = 0) -> dict:
    return dict(origin=origin, archive_offset=owner_archive, size=size,
                event_sequence=sequence,
                destination_stream_location={"stream": 5, "offset": start})


def full_index(preamble: list[dict], asset_spans: list[dict]) -> dict:
    all_spans = [*preamble, *asset_spans]
    return dict(status="native-read-spans-indexed", xasset_count=1,
                preamble_spans=preamble,
                assets=[dict(index=0, read_spans=asset_spans)],
                physical_load_count_by_stream={5: len(all_spans)},
                physical_load_bytes_by_stream={5: sum(item["size"] for item in all_spans)})


class Stream5AllocationContextTests(unittest.TestCase):
    def test_full_stream5_spans_may_be_adjacent_and_include_nonstring_loads(self):
        result = validate_complete_stream5_allocations(full_index(
            [span(0, 4, 2, origin="string_data")],
            [span(4, 3, 8, origin="unclassified_load")]))
        self.assertEqual(result["status"], "complete-disjoint-stream5-allocations")
        self.assertEqual(result["physical_span_count"], 2)
        self.assertEqual(result["physical_bytes"], 7)
        self.assertEqual(result["max_stream5_offset"], 7)
        self.assertEqual(len(result["spans_sha256"]), 64)

    def test_nonstring_overlap_is_rejected_even_when_string_data_does_not_overlap(self):
        with self.assertRaisesRegex(ValueError, "allocations overlap"):
            validate_complete_stream5_allocations(full_index(
                [span(0, 4, 2, origin="string_data")],
                [span(3, 2, 8, origin="unclassified_load")]))

    def test_selected_asset_projection_cannot_claim_complete_stream_context(self):
        index = full_index([], [span(0, 2, 3)])
        index["xasset_count"] = 2
        with self.assertRaisesRegex(ValueError, "unfiltered complete XAsset"):
            validate_complete_stream5_allocations(index)

    def test_stream_metrics_must_match_all_projected_allocations(self):
        index = full_index([], [span(0, 2, 3)])
        index["physical_load_bytes_by_stream"][5] = 1
        with self.assertRaisesRegex(ValueError, "physical-read totals"):
            validate_complete_stream5_allocations(index)


if __name__ == "__main__":
    unittest.main()
