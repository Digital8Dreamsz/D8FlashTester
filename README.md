# D8 Flash Tester

**Catch fake USB drives and SD cards — the ones that lie about their capacity.**

A free Windows tool that detects counterfeit flash storage by actually writing and verifying data across the *whole* claimed size, defeating the controller tricks that fool naive testers. If a "512GB" drive really holds 8GB, this tells you — and tells you the true usable size to the sector.

Built by [Digital8Dreamz](https://ko-fi.com/digital8dreamsz) · Windows · C# / .NET 9 · MIT licensed

---

## Why this exists

Cheap "high-capacity" flash drives are one of the most common online scams. A $9 "512GB" drive is almost always a small chip (often 8–32GB) behind a controller that's been firmware-patched to *report* a huge fake size. Writes past the real chip either vanish, return zeros, or wrap around and silently destroy earlier data — so the drive looks fine until you actually need the files back.

Most "testers" out there are unreliable (they get fooled by caching) or, worse, bundled with malware. D8 Flash Tester is a single, open-source, standalone tool that does the job honestly.

---

## Download & run

1. Go to the [**Releases**](../../releases) page and download `D8FlashTester.exe` from the latest release.
2. Double-click it. That's it — no installer, no .NET download, nothing to set up.

> **"Windows protected your PC"?**
> Because the app isn't code-signed (signing certificates cost money), Windows SmartScreen may warn you the first time. This is expected for small independent tools. Click **More info → Run anyway**. The source code is right here in this repo if you want to read or build it yourself.

The first launch pauses a second or two while the self-contained runtime unpacks — normal.

---

## Requirements

- **Windows 10 or 11** (64-bit)
- Nothing else. The `.exe` is fully self-contained — no .NET runtime install required.
- **Administrator** is only needed for the *destructive* features (RAW test, Cap, Secure wipe); the app will offer to relaunch elevated when you use one. The safe Filesystem test and Benchmark run without admin.

---

## Features

### Fraud detection — two modes

- **Filesystem test** *(safe, no admin)*
  Fills the drive's free space with a deterministic pattern, then reads it back with **cache-bypassing reads** so you're testing the chip, not RAM. Reports the true usable size, the failure type, and read/write speeds. Tests free space only — for a full verdict, format the drive first so the whole claimed size is empty.

- **RAW device test** *(admin, destructive)*
  Talks directly to the physical disk and drops unique markers **across the entire claimed capacity** — detecting a fake in *seconds* without filling the whole drive. Recovers the exact real size using wrap forensics, or binary-searches the capacity boundary down to sector precision for "void" fakes.

### Drive tools — for good drives

- **Benchmark** — non-destructive read/write throughput with a live MB/s graph.
- **Optimize (TRIM)** — runs Windows' real TRIM engine (`Optimize-Volume -ReTrim`), bracketed by a before/after benchmark so you can *see* whether it helped. This is the correct, flash-safe "optimize" — never a defrag, which only burns write cycles on flash.
- **Cap to real size** — repartition a confirmed fake down to its true usable capacity so it's safe to actually use.
- **Secure wipe** — full zero-fill of a disk.

### Everywhere

- Cache is always defeated: writes use write-through, reads bypass the OS cache.
- Live segmented progress bar, per-region block map, and a savable text report.

---

## How to use it

1. Plug in the drive.
2. Pick it from the **Drive** dropdown (the app refuses your system disk).
3. For a quick honest check, leave **Filesystem** selected and hit **Start Test**. For the fastest full-capacity verdict on a disposable/suspect drive, switch to **RAW** (this erases the drive).
4. Read the verdict. If it's fake, **Cap to real size** will make it usable at its true capacity.

> ⚠️ **Destructive operations erase data.** The RAW test, Cap, and Secure wipe wipe the target disk — genuine or not. They refuse your system disk and make you type the drive number and tick a confirmation box first, but **always double-check you picked the right drive.** Test empty or already-suspect media.

---

## How it works (the short version)

The whole trick to catching a fake is **defeating cache**. Naive testers write a file and read it straight back, so Windows or the drive's controller serves the read from RAM and the fake looks genuine.

D8 Flash Tester writes a position-derived pattern (each 8-byte slot holds a value derived from its own byte offset, so nothing needs to be stored in memory and any location is independently regenerable), then reads it back with unbuffered I/O that bypasses the OS cache entirely. Past the real chip size the pattern breaks, and *how* it breaks names the scam:

- **Zeros** → capacity void (the space simply doesn't exist).
- **Wrong-but-valid pattern** → writes wrapped over earlier data; the exact real size is recovered by reversing the pattern function.
- **Refused writes** → the controller gave up before its claimed end.

For void-type fakes, a binary search then pins the true boundary to sector precision in a handful of steps.

---

## Build from source

Requires the [.NET 9 SDK](https://dotnet.microsoft.com/download).

```powershell
git clone https://github.com/Digital8Dreamsz/D8FlashTester.git
cd D8FlashTester
dotnet publish -c Release -r win-x64
```

The standalone single-file exe is written to:

```
bin\Release\net9.0-windows\win-x64\publish\D8FlashTester.exe
```

For an ARM64 build, use `-r win-arm64`.

---

## Disclaimer

This tool performs low-level disk operations and several features **permanently erase data**. It's provided as-is, with no warranty of any kind. You are responsible for selecting the correct drive. The author is not liable for data loss. Always back up anything you care about before testing storage.

---

## License

[MIT](LICENSE) © Digital8Dreamz

---

## Support

If this saved you from a fake drive — or from losing data to one — you can leave a tip at **[ko-fi.com/digital8dreamsz](https://ko-fi.com/digital8dreamsz)**. Stars on the repo and bug reports are just as welcome.
