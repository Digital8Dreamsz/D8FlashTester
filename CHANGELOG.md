# Changelog

All notable changes to D8 Flash Tester.

## v2.7
- Read-only `ATA IDENTIFY` unmasking: when a USB bridge/adapter is detected,
  query the real drive's model/serial/firmware through it (no writes, no erase).

## v2.6
- USB bridge/adapter detection. Labels enclosures instead of reporting the
  adapter as the drive; adds media type and bus type via MSFT_PhysicalDisk.

## v2.5
- Device metadata: model, USB VID/PID + mapped vendor, serial. Flags a possible
  brand/vendor-ID mismatch. Removable-drive TRIM pre-warning (no more hard error
  on flash that can't be trimmed).

## v2.4
- Report export in three formats: .txt, .json, and a styled .html with the block
  map and throughput graph embedded. Format dropdown next to Save Report.

## v2.3
- Detects raw/unformatted drives (including partitionless USB disks) and adds a
  Format tool (exFAT / NTFS / FAT32).

## v2.2
- Drive tools panel: Benchmark, Optimize/TRIM, Cap-to-real-size, Secure wipe,
  with a live throughput graph.

## v2.1
- Segmented phase progress bar; app icon.

## v2.0
- RAW device mode: sparse probing across the full claimed capacity, with wrap
  forensics and sector-precision size pinpointing.

## v1.0
- Initial release: filesystem fraud test with pattern write/verify, cache-defeating
  I/O, block map, and verdict.
