from pathlib import Path
import struct
import tempfile
import unittest

from anvil_auditor.region import HEADER_BYTES, SECTOR_BYTES, inspect_region


def make_region(path: Path, entries: list[tuple[int, int, int, int]]) -> None:
    """entries: (slot, sector offset, sector count, compression type)."""
    data = bytearray(HEADER_BYTES + SECTOR_BYTES * 2)
    for slot, offset, count, compression in entries:
        struct.pack_into(">I", data, slot * 4, (offset << 8) | count)
        struct.pack_into(">I", data, offset * SECTOR_BYTES, 2)
        data[offset * SECTOR_BYTES + 4] = compression
    path.write_bytes(data)


class RegionTests(unittest.TestCase):
    def test_empty_region(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.0.0.mca"
            path.write_bytes(bytes(HEADER_BYTES))
            result = inspect_region(path)
            self.assertEqual(result.allocated_slots, 0)
            self.assertEqual(result.errors, 0)
            self.assertEqual((result.region_x, result.region_z), (0, 0))

    def test_valid_chunk_and_compression(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.-2.4.mca"
            make_region(path, [(0, 2, 1, 2)])
            result = inspect_region(path)
            self.assertEqual(result.allocated_slots, 1)
            self.assertEqual(result.errors, 0)
            self.assertEqual(result.chunks[0]["compression"], "zlib")

    def test_out_of_bounds_allocation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.0.0.mca"
            make_region(path, [(0, 3, 2, 2)])
            result = inspect_region(path)
            self.assertIn("out_of_bounds", {item.code for item in result.findings})

    def test_overlapping_slots(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.0.0.mca"
            make_region(path, [(0, 2, 1, 2), (1, 2, 1, 2)])
            result = inspect_region(path)
            self.assertIn("sector_overlap", {item.code for item in result.findings})

    def test_short_header(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.0.0.mca"
            path.write_bytes(b"short")
            result = inspect_region(path)
            self.assertIn("short_header", {item.code for item in result.findings})

    def test_unknown_compression_is_warning(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.0.0.mca"
            make_region(path, [(0, 2, 1, 9)])
            result = inspect_region(path)
            self.assertEqual(result.errors, 0)
            self.assertIn("unknown_compression", {item.code for item in result.findings})


if __name__ == "__main__":
    unittest.main()
