"""Read-only parser for the fixed header and chunk records of .mca files."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import struct

HEADER_BYTES = 8192
SECTOR_BYTES = 4096
SLOT_COUNT = 1024
COMPRESSION_NAMES = {1: "gzip", 2: "zlib", 3: "uncompressed"}


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    slot: int | None = None


@dataclass
class RegionReport:
    path: str
    region_x: int | None
    region_z: int | None
    file_bytes: int
    allocated_slots: int = 0
    findings: list[Finding] = field(default_factory=list)
    chunks: list[dict] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(item.severity == "error" for item in self.findings)

    @property
    def warnings(self) -> int:
        return sum(item.severity == "warning" for item in self.findings)

    def to_dict(self) -> dict:
        value = asdict(self)
        value["errors"] = self.errors
        value["warnings"] = self.warnings
        return value


def _region_coordinates(path: Path) -> tuple[int | None, int | None]:
    stem = path.stem
    parts = stem.split(".")
    if len(parts) == 4 and parts[0] == "r":
        try:
            return int(parts[1]), int(parts[2])
        except ValueError:
            pass
    return None, None


def inspect_region(path: Path) -> RegionReport:
    """Inspect a region file without modifying it."""
    size = path.stat().st_size
    rx, rz = _region_coordinates(path)
    report = RegionReport(str(path), rx, rz, size)
    if size < HEADER_BYTES:
        report.findings.append(Finding("error", "short_header", "File is smaller than the 8 KiB region header"))
        return report

    file_sectors = (size + SECTOR_BYTES - 1) // SECTOR_BYTES
    occupied: dict[int, int] = {}
    with path.open("rb") as source:
        header = source.read(HEADER_BYTES)
        for slot in range(SLOT_COUNT):
            offset, count = struct.unpack_from(">I", header, slot * 4)
            sector_offset = offset >> 8
            sector_count = offset & 0xFF
            if sector_offset == 0 and sector_count == 0:
                continue
            report.allocated_slots += 1
            if sector_offset == 0 or sector_count == 0:
                report.findings.append(Finding("error", "invalid_location", "Offset and sector count must both be non-zero", slot))
                continue
            if sector_offset < 2:
                report.findings.append(Finding("error", "header_overlap", "Chunk data overlaps the region header", slot))
                continue
            end_sector = sector_offset + sector_count
            if end_sector > file_sectors:
                report.findings.append(Finding("error", "out_of_bounds", "Chunk allocation extends beyond end of file", slot))
            overlaps = [other for sector, other in occupied.items() if sector_offset < sector + 1 and sector < end_sector]
            # Check every sector because corrupt records may claim multiple sectors.
            overlaps = sorted({occupied[sector] for sector in range(sector_offset, end_sector) if sector in occupied})
            if overlaps:
                report.findings.append(Finding("error", "sector_overlap", f"Allocated sectors overlap slot(s) {overlaps}", slot))
            for sector in range(sector_offset, min(end_sector, file_sectors)):
                occupied.setdefault(sector, slot)
            entry = {"slot": slot, "sector_offset": sector_offset, "sector_count": sector_count}
            record_position = sector_offset * SECTOR_BYTES
            if record_position + 5 <= size:
                source.seek(record_position)
                length_data = source.read(4)
                length = struct.unpack(">I", length_data)[0]
                compression_data = source.read(1)
                compression = compression_data[0] & 0x7F if compression_data else 0
                external = bool(compression_data and compression_data[0] & 0x80)
                entry.update({"record_length": length, "compression": COMPRESSION_NAMES.get(compression, "unknown"), "external_stream": external})
                available = sector_count * SECTOR_BYTES
                if length < 1:
                    report.findings.append(Finding("error", "invalid_length", "Chunk record length must include a compression byte", slot))
                elif length + 4 > available:
                    report.findings.append(Finding("error", "length_exceeds_allocation", "Chunk record length exceeds allocated sectors", slot))
                if compression not in COMPRESSION_NAMES:
                    report.findings.append(Finding("warning", "unknown_compression", f"Unrecognized compression type {compression}", slot))
                if external:
                    report.findings.append(Finding("warning", "external_stream", "Chunk uses an external .mcc payload; payload was not inspected", slot))
            else:
                report.findings.append(Finding("error", "missing_record_header", "Chunk record header is outside the file", slot))
            report.chunks.append(entry)
    return report
