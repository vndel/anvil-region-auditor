# Anvil Region Auditor

A read-only Python CLI for inventorying and checking Minecraft Java Edition Anvil region files (`.mca`). It reports region and chunk-slot counts, validates location-table sector bounds and overlap, inspects compression headers, and can emit JSON or CSV.

It never writes to the world directory. Treat findings as diagnostic hints, not proof that a chunk can be fully decoded by every Minecraft version.

## Requirements

- Python 3.10+
- No third-party dependencies

## Usage

```sh
python -m anvil_auditor /path/to/world --format text
python -m anvil_auditor /path/to/world --format json --output audit.json
python -m anvil_auditor /path/to/world/region --format csv --output chunks.csv
```

Pass a world directory to discover `region/`, `entities/`, and `poi/` subdirectories. Or pass a single region directory. Symlinked files are skipped by default. Use `--include-entities` and `--include-poi` to include those directories.

Exit codes: `0` no structural errors, `1` structural findings, `2` invalid arguments or I/O failure. Unknown compression types are warnings, not structural errors.

## Safety and limitations

- Opened inputs are read-only; output files should be written outside the world directory.
- Run against a stopped server or a consistent filesystem snapshot. A live world can change during scanning.
- Sector-table validation detects common out-of-bounds and overlap faults but does not decompress or semantically parse NBT.
- Compression types recognized: gzip, zlib, and uncompressed. LZ4 or future format extensions are reported as unknown.
- An empty location slot is not necessarily evidence that a chunk was never generated.

## Development

```sh
python -m unittest discover -s tests -v
```

MIT licensed.