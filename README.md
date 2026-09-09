# D8 Flash Tester

**Catch fake-capacity USB flash drives and SD cards — and tell the honest truth about the ones you own.**

Made by **Digital8Dreamz**.

Counterfeit "512GB" sticks that are really a few hundred MB are everywhere on
marketplaces. They lie to Windows about their size, so a normal copy-and-check
looks fine until your data silently disappears past the real capacity. D8 Flash
Tester writes a verifiable pattern across the drive and reads it back with the
OS cache defeated, so a fake has nowhere to hide.

Its guiding rule: **it never reports anything it did not actually measure.**

---

## What it does

- **Fraud detection (two modes)**
  - *Filesystem* — safe, no admin. Fills free space with a deterministic pattern
    and verifies it, reporting the real usable size.
  - *RAW device* — full claimed capacity, sector-accurate. Classifies fakes as
    *void* (returns zeros), *wrap* (overwrites earlier data), *corruption*, or
    *write-refused*, and pins the true size to sector precision. **Destructive —
    erases the target disk. Needs admin.**
- **Drive tools** — Benchmark (read/write throughput), Optimize/TRIM (the
  flash-safe optimize, never a defrag), Cap-to-real-size (repartition a fake down
  to its true capacity), Secure wipe (zero-fill), and Format.
- **Device metadata** — model, USB VID/PID + vendor, serial. Flags when a "brand"
  drive reports a generic controller vendor, and labels USB bridge/adapter
  enclosures instead of pretending the adapter is the drive. Where a bridge
  allows it, a read-only `ATA IDENTIFY` unmasks the real drive inside.
- **Reports** — export any result as **.txt**, **.json**, or a styled **.html**
  page with the block map and throughput graph embedded.

## Requirements

- Windows 10 or 11 (x64)
- [.NET 9 SDK](https://dotnet.microsoft.com/download) to build from source

## Build & run

```
dotnet build -c Release
```

The app appears in `bin\Release\net9.0-windows\`. Run `D8FlashTester.exe`.

To produce a single self-contained .exe you can share:

```
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Safety

- **RAW test, Cap, Secure wipe, and Format erase data** and require admin. They
  refuse the system disk and lock/dismount the target's volumes first, and make
  you type the drive/disk name to confirm.
- The *Filesystem* test and *Benchmark* are non-destructive.
- The metadata `ATA IDENTIFY` query is **read-only** — it asks the drive for its
  name and nothing else.

## Support the project

If this saved you from a fake drive — or you just want to help a solo developer
keep building — you can leave a tip: ko-fi.com/digital8dreamsz
## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Digital8Dreamz.
