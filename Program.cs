// ===========================================================================
//  D8 Flash Tester v2.7  -  Digital8Dreamz
//  Fake-capacity / NAND fraud detector + drive tools for USB drives & SD cards.
//
//  FRAUD TEST MODES:
//   1) Filesystem (safe, no admin) - fills free space with a deterministic
//      pattern, verifies with unbuffered reads. Tests only free space.
//   2) Raw device (admin, DESTRUCTIVE) - sparse markers across the FULL claimed
//      capacity via \\.\PhysicalDriveN. Wrap forensics recover the exact real
//      size; void-type fakes get a binary-search boundary to sector precision.
//
//  DRIVE TOOLS (top-right panel, for good drives):
//   - Benchmark       : non-destructive read/write throughput, live graph.
//   - Optimize (TRIM) : the correct flash "defrag" - Optimize-Volume -ReTrim,
//                       bracketed by a before/after benchmark so the graph
//                       shows whether it helped. (Never a real defrag - that
//                       only burns write cycles on flash.)
//   - Cap to real size: repartition a confirmed fake down to its true capacity.
//   - Secure wipe     : raw zero-fill.
//
//  Cache is always defeated: writes WRITE_THROUGH, reads NO_BUFFERING.
//
//  WARNING: Raw test, Cap, and Wipe are destructive and need admin. They refuse
//  the system disk and lock/dismount the target's volumes first.
// ===========================================================================

using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace D8FlashTester;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    public static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}

// ---------------------------------------------------------------------------
//  Native interop.
// ---------------------------------------------------------------------------
internal static class Native
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
    public const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
    public const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    public const uint FILE_BEGIN = 0;

    public const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080;
    public const uint IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C;
    public const uint IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000;
    public const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    public const uint IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014;
    public const uint FSCTL_LOCK_VOLUME = 0x00090018;
    public const uint FSCTL_UNLOCK_VOLUME = 0x0009001C;
    public const uint FSCTL_DISMOUNT_VOLUME = 0x00090020;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurity,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplate);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadFile(SafeFileHandle hFile, IntPtr lpBuffer,
        uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteFile(SafeFileHandle hFile, IntPtr lpBuffer,
        uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFilePointerEx(SafeFileHandle hFile, long liDistanceToMove,
        out long lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceW(string lpRootPathName,
        out uint lpSectorsPerCluster, out uint lpBytesPerSector,
        out uint lpNumberOfFreeClusters, out uint lpTotalNumberOfClusters);

    public static int FsSectorSize(string root)
    {
        try { if (GetDiskFreeSpaceW(root, out _, out uint bps, out _, out _) && bps > 0) return (int)bps; }
        catch { }
        return 4096;
    }

    public static int VolumeToDiskNumber(string letter)
    {
        string vol = $"\\\\.\\{letter.TrimEnd('\\', ':')}:";
        using var h = CreateFileW(vol, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
            OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return -1;
        IntPtr outb = Marshal.AllocHGlobal(16);
        try
        {
            if (DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, IntPtr.Zero, 0, outb, 16, out _, IntPtr.Zero))
                return Marshal.ReadInt32(outb, 4);
            return -1;
        }
        finally { Marshal.FreeHGlobal(outb); }
    }

    public static long DiskLength(SafeFileHandle hDisk)
    {
        IntPtr outb = Marshal.AllocHGlobal(8);
        try
        {
            if (DeviceIoControl(hDisk, IOCTL_DISK_GET_LENGTH_INFO, IntPtr.Zero, 0, outb, 8, out _, IntPtr.Zero))
                return Marshal.ReadInt64(outb, 0);
            return -1;
        }
        finally { Marshal.FreeHGlobal(outb); }
    }

    public static int DiskSectorSize(SafeFileHandle hDisk)
    {
        IntPtr outb = Marshal.AllocHGlobal(24);
        try
        {
            if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, IntPtr.Zero, 0, outb, 24, out _, IntPtr.Zero))
            {
                int bps = Marshal.ReadInt32(outb, 20);
                if (bps > 0) return bps;
            }
            return 512;
        }
        finally { Marshal.FreeHGlobal(outb); }
    }

    public static string DeviceModel(SafeFileHandle hDisk, out bool isUsb)
    {
        isUsb = false;
        IntPtr inb = Marshal.AllocHGlobal(12);
        int outSize = 1024;
        IntPtr outb = Marshal.AllocHGlobal(outSize);
        try
        {
            Marshal.WriteInt32(inb, 0, 0);
            Marshal.WriteInt32(inb, 4, 0);
            Marshal.WriteInt32(inb, 8, 0);
            if (!DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, inb, 12, outb, (uint)outSize, out _, IntPtr.Zero))
                return "(unknown device)";
            int productIdOffset = Marshal.ReadInt32(outb, 16);
            int busType = Marshal.ReadInt32(outb, 28);
            isUsb = busType == 0x07;
            string model = "(unknown)";
            if (productIdOffset > 0 && productIdOffset < outSize)
                model = Marshal.PtrToStringAnsi(outb + productIdOffset)?.Trim() ?? "(unknown)";
            return $"{model} [{BusName(busType)}]";
        }
        finally { Marshal.FreeHGlobal(inb); Marshal.FreeHGlobal(outb); }
    }

    private static string BusName(int b) => b switch
    {
        0x01 => "SCSI",
        0x03 => "ATA",
        0x04 => "1394",
        0x07 => "USB",
        0x08 => "RAID",
        0x09 => "iSCSI",
        0x0A => "SAS",
        0x0B => "SATA",
        0x0C => "SD",
        0x0D => "MMC",
        0x11 => "NVMe",
        _ => $"bus{b}"
    };
}

// ---------------------------------------------------------------------------
//  SCSI pass-through structs for read-only ATA IDENTIFY (unmask drives behind
//  a USB bridge). No data/write/erase opcodes are ever issued - only 0xEC.
// ---------------------------------------------------------------------------
[StructLayout(LayoutKind.Sequential)]
internal struct SCSI_PASS_THROUGH_DIRECT
{
    public ushort Length;
    public byte ScsiStatus;
    public byte PathId;
    public byte TargetId;
    public byte Lun;
    public byte CdbLength;
    public byte SenseInfoLength;
    public byte DataIn;
    public uint DataTransferLength;
    public uint TimeOutValue;
    public IntPtr DataBuffer;
    public uint SenseInfoOffset;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Cdb;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SPTD_WITH_SENSE
{
    public SCSI_PASS_THROUGH_DIRECT Spt;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Sense;
}

// ---------------------------------------------------------------------------
//  Deterministic, invertible pattern (SplitMix64 finalizer).
// ---------------------------------------------------------------------------
internal static class Pattern
{
    private const ulong GAMMA = 0x9E3779B97F4A7C15UL;
    private const ulong C1 = 0xBF58476D1CE4E5B9UL;
    private const ulong C2 = 0x94D049BB133111EBUL;
    private const ulong C1_INV = 0x96DE1B173F119089UL;
    private const ulong C2_INV = 0x319642B2D24D8EC3UL;

    public static ulong Mix(ulong x)
    {
        x += GAMMA;
        x = (x ^ (x >> 30)) * C1;
        x = (x ^ (x >> 27)) * C2;
        return x ^ (x >> 31);
    }

    private static ulong Undo(ulong y, int k)
    {
        ulong x = y;
        for (int i = 0; i < 5; i++) x = y ^ (x >> k);
        return x;
    }

    public static ulong InvMix(ulong y)
    {
        ulong z = Undo(y, 31);
        z *= C2_INV;
        z = Undo(z, 27);
        z *= C1_INV;
        z = Undo(z, 30);
        return z - GAMMA;
    }

    public static void Fill(byte[] buf, int len, ulong absBase)
    {
        int slots = len / 8;
        var span = buf.AsSpan();
        for (int i = 0; i < slots; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(i * 8, 8), Mix(absBase + (ulong)(i * 8)));
    }

    public static long Verify(byte[] buf, int len, ulong absBase, out bool looksZero, out ulong actualAtFail)
    {
        looksZero = false; actualAtFail = 0;
        int slots = len / 8;
        var span = buf.AsSpan();
        for (int i = 0; i < slots; i++)
        {
            ulong actual = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(i * 8, 8));
            ulong expect = Mix(absBase + (ulong)(i * 8));
            if (actual != expect)
            {
                looksZero = actual == 0UL;
                actualAtFail = actual;
                return i * 8;
            }
        }
        return -1;
    }
}

internal sealed class Prog
{
    public int PhaseIndex;
    public string Phase = "";
    public double PhasePercent;
    public double MBps;
    public string Status = "";
}

internal static class Fmt
{
    public static string Bytes(long b)
    {
        double v = b; string[] u = { "B", "KiB", "MiB", "GiB", "TiB" }; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return string.Format(CultureInfo.InvariantCulture, "{0:0.##} {1}", v, u[i]);
    }
}

internal static class St
{
    public const byte Gray = 0, Writing = 1, Written = 2, Verifying = 3, Verified = 4, Fail = 5;
}

// ---------------------------------------------------------------------------
//  Segmented phase progress bar.
// ---------------------------------------------------------------------------
internal sealed class SegmentBar : Control
{
    private string[] _names = Array.Empty<string>();
    private double[] _pct = Array.Empty<double>();
    private int _active = -1;
    private bool _failed;

    public SegmentBar()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
               | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Color.FromArgb(30, 30, 34);
        Height = 26;
    }

    public void SetPhases(params string[] names)
    {
        _names = names;
        _pct = new double[names.Length];
        _active = names.Length > 0 ? 0 : -1;
        _failed = false;
        Invalidate();
    }

    public void Update(int index, double percent)
    {
        if (index < 0 || index >= _pct.Length) return;
        for (int i = 0; i < index; i++) _pct[i] = 100;
        _pct[index] = Math.Max(_pct[index], Math.Max(0, Math.Min(100, percent)));
        _active = index;
        Invalidate();
    }

    public void CompleteAll()
    {
        for (int i = 0; i < _pct.Length; i++) _pct[i] = 100;
        _active = -1;
        Invalidate();
    }

    public void MarkStopped(bool failed) { _failed = failed; _active = -1; Invalidate(); }

    public void Reset()
    {
        for (int i = 0; i < _pct.Length; i++) _pct[i] = 0;
        _active = _pct.Length > 0 ? 0 : -1;
        _failed = false;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        int w = Width, h = Height;
        using (var bg = new SolidBrush(Color.FromArgb(30, 30, 34))) g.FillRectangle(bg, 0, 0, w, h);
        if (_names.Length == 0) return;

        int n = _names.Length, gap = 3;
        int segW = (w - gap * (n - 1)) / n;

        for (int i = 0; i < n; i++)
        {
            int x = i * (segW + gap);
            int sw = (i == n - 1) ? w - x : segW;
            using (var trough = new SolidBrush(Color.FromArgb(52, 52, 58)))
                g.FillRectangle(trough, x, 0, sw, h);

            int fill = (int)Math.Round(sw * _pct[i] / 100.0);
            if (fill > 0)
            {
                Color c = _failed && i == LastTouched() ? Color.FromArgb(200, 70, 70)
                        : _pct[i] >= 100 ? Color.FromArgb(70, 175, 90)
                        : Color.FromArgb(70, 130, 200);
                using var br = new LinearGradientBrush(new Rectangle(x, 0, Math.Max(1, fill), h),
                    ControlPaint.Light(c), c, LinearGradientMode.Vertical);
                g.FillRectangle(br, x, 0, fill, h);
            }
            if (i == _active)
                using (var pen = new Pen(Color.FromArgb(150, 200, 255), 1))
                    g.DrawRectangle(pen, x, 0, sw - 1, h - 1);

            string label = $"{_names[i]} {(int)_pct[i]}%";
            var sz = g.MeasureString(label, Font);
            using var tb = new SolidBrush(Color.WhiteSmoke);
            g.DrawString(label, Font, tb, x + (sw - sz.Width) / 2, (h - sz.Height) / 2);
        }
    }

    private int LastTouched()
    {
        for (int i = _pct.Length - 1; i >= 0; i--) if (_pct[i] > 0) return i;
        return 0;
    }
}

// ---------------------------------------------------------------------------
//  Live line graph (throughput curves).
// ---------------------------------------------------------------------------
internal sealed class LineGraph : Control
{
    public readonly object Gate = new();
    private string _title = "";
    private string[] _names = Array.Empty<string>();
    private Color[] _colors = Array.Empty<Color>();
    public List<double>[] Data = Array.Empty<List<double>>();

    public LineGraph()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
               | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Color.FromArgb(24, 24, 28);
    }

    public void Begin(string title, params (string name, Color color)[] defs)
    {
        lock (Gate)
        {
            _title = title;
            _names = defs.Select(d => d.name).ToArray();
            _colors = defs.Select(d => d.color).ToArray();
            Data = defs.Select(_ => new List<double>()).ToArray();
        }
        Invalidate();
    }

    public void ClearGraph()
    {
        lock (Gate) { _title = ""; _names = Array.Empty<string>(); _colors = Array.Empty<Color>(); Data = Array.Empty<List<double>>(); }
        Invalidate();
    }

    public bool HasData { get { lock (Gate) { return Data.Any(d => d.Count > 0); } } }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        int w = Width, h = Height;
        using (var bg = new SolidBrush(BackColor)) g.FillRectangle(bg, 0, 0, w, h);

        int padL = 44, padR = 8, padT = 24, padB = 18;
        var plot = new Rectangle(padL, padT, Math.Max(1, w - padL - padR), Math.Max(1, h - padT - padB));

        double max = 1; int maxCount = 0;
        List<double>[] snap;
        string[] names; Color[] colors; string title;
        lock (Gate)
        {
            snap = Data.Select(d => new List<double>(d)).ToArray();
            names = (string[])_names.Clone();
            colors = (Color[])_colors.Clone();
            title = _title;
        }
        foreach (var s in snap) { foreach (var v in s) if (v > max) max = v; if (s.Count > maxCount) maxCount = s.Count; }
        max = NiceMax(max);

        using (var grid = new Pen(Color.FromArgb(50, 50, 56)))
        using (var axis = new Pen(Color.FromArgb(90, 90, 98)))
        using (var txt = new SolidBrush(Color.FromArgb(150, 150, 158)))
        using (var f = new Font(FontFamily.GenericSansSerif, 7.5f))
        {
            for (int i = 0; i <= 4; i++)
            {
                int y = plot.Bottom - (int)(plot.Height * i / 4.0);
                g.DrawLine(grid, plot.Left, y, plot.Right, y);
                string lbl = (max * i / 4.0).ToString("0", CultureInfo.InvariantCulture);
                g.DrawString(lbl, f, txt, 4, y - 7);
            }
            g.DrawLine(axis, plot.Left, plot.Top, plot.Left, plot.Bottom);
            g.DrawLine(axis, plot.Left, plot.Bottom, plot.Right, plot.Bottom);
            if (!string.IsNullOrEmpty(title))
                g.DrawString(title, f, new SolidBrush(Color.Gainsboro), plot.Left, 5);
        }

        int denom = Math.Max(1, maxCount - 1);
        for (int si = 0; si < snap.Length; si++)
        {
            var pts = snap[si];
            if (pts.Count == 0) continue;
            using var pen = new Pen(colors[si], 1.6f);
            PointF? prev = null;
            for (int i = 0; i < pts.Count; i++)
            {
                float x = plot.Left + (float)plot.Width * i / denom;
                float y = plot.Bottom - (float)(plot.Height * (pts[i] / max));
                var cur = new PointF(x, y);
                if (prev is PointF p) g.DrawLine(pen, p, cur);
                prev = cur;
            }
        }

        // legend in the top band, above the plot (right-aligned, never over the curves)
        using (var lf = new Font(FontFamily.GenericSansSerif, 7.5f))
        using (var lt = new SolidBrush(Color.Gainsboro))
        {
            int lx = plot.Right;
            for (int si = snap.Length - 1; si >= 0; si--)
            {
                string nm = names.Length > si ? names[si] : "";
                float tw = g.MeasureString(nm, lf).Width;
                lx -= (int)tw;
                g.DrawString(nm, lf, lt, lx, 5);
                lx -= 4 + 10;
                using var swb = new SolidBrush(colors[si]);
                g.FillRectangle(swb, lx, 7, 10, 8);
                lx -= 12;
            }
        }
    }

    private static double NiceMax(double m)
    {
        if (m <= 1) return 1;
        double mag = Math.Pow(10, Math.Floor(Math.Log10(m)));
        double n = m / mag;
        double step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
        return step * mag;
    }
}

// ===========================================================================
//  Filesystem fraud engine.
// ===========================================================================
internal sealed class Plan
{
    public required string Root;
    public long ClaimedBytes; public long FreeBytes; public int Sector;
    public long ChunkSize; public long BlockSize; public long TestBytes; public int TotalBlocks;
    public string Label = ""; public string Format = ""; public string Type = "";
}

internal sealed class TestResult
{
    public bool Completed; public bool Cancelled; public string? Error;
    public long WrittenBytes; public long VerifiedGoodBytes; public long FirstFailOffset = -1;
    public bool FailLooksZero; public double WriteMBps; public double ReadMBps; public Plan? Plan;
}

internal sealed class FsTester
{
    private const string FilePrefix = "d8flashtest_";

    public static Plan BuildPlan(DriveInfo di, long capBytes)
    {
        string root = di.RootDirectory.FullName;
        int sector = Native.FsSectorSize(root);
        long block = 8L * 1024 * 1024, chunk = 1024L * 1024 * 1024, margin = 8L * 1024 * 1024;
        long usable = di.AvailableFreeSpace - margin; if (usable < 0) usable = 0;
        if (capBytes > 0) usable = Math.Min(usable, capBytes);
        usable -= usable % sector;
        int totalBlocks = usable == 0 ? 0 : (int)((usable + block - 1) / block);
        string fmt; try { fmt = di.DriveFormat; } catch { fmt = "?"; }
        return new Plan
        {
            Root = root, ClaimedBytes = di.TotalSize, FreeBytes = di.AvailableFreeSpace, Sector = sector,
            ChunkSize = chunk, BlockSize = block, TestBytes = usable, TotalBlocks = totalBlocks,
            Label = string.IsNullOrWhiteSpace(di.VolumeLabel) ? "(no label)" : di.VolumeLabel,
            Format = fmt, Type = di.DriveType.ToString()
        };
    }

    public TestResult Run(Plan plan, byte[] states, bool keepFiles, IProgress<Prog> prog, CancellationToken ct)
    {
        var result = new TestResult { Plan = plan };
        int block = (int)plan.BlockSize, sector = plan.Sector;
        IntPtr rawBuf = Marshal.AllocHGlobal(block + sector);
        long al = (rawBuf.ToInt64() + (sector - 1)) & ~((long)(sector - 1));
        IntPtr readBuf = new IntPtr(al);
        byte[] writeBuf = new byte[block], verifyBuf = new byte[block];
        try
        {
            Cleanup(plan.Root);
            long absOffset = 0; var swW = Stopwatch.StartNew(); int fileIdx = 0; long remaining = plan.TestBytes;
            while (remaining > 0)
            {
                ct.ThrowIfCancellationRequested();
                long fileSize = Math.Min(plan.ChunkSize, remaining);
                string path = Path.Combine(plan.Root, $"{FilePrefix}{fileIdx:D5}.bin");
                try
                {
                    using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, FileOptions.WriteThrough);
                    long pos = 0;
                    while (pos < fileSize)
                    {
                        ct.ThrowIfCancellationRequested();
                        int toWrite = (int)Math.Min(block, fileSize - pos);
                        int bi = (int)(absOffset / block); if (bi < states.Length) states[bi] = St.Writing;
                        Pattern.Fill(writeBuf, toWrite, (ulong)absOffset);
                        fs.Write(writeBuf, 0, toWrite);
                        if (bi < states.Length) states[bi] = St.Written;
                        pos += toWrite; absOffset += toWrite;
                        double mbps = swW.Elapsed.TotalSeconds > 0 ? absOffset / 1048576.0 / swW.Elapsed.TotalSeconds : 0;
                        prog.Report(new Prog { PhaseIndex = 0, Phase = "Writing", PhasePercent = plan.TestBytes > 0 ? absOffset * 100.0 / plan.TestBytes : 100, MBps = mbps, Status = $"{Fmt.Bytes(absOffset)} / {Fmt.Bytes(plan.TestBytes)}" });
                    }
                    fs.Flush(true);
                }
                catch (IOException)
                {
                    swW.Stop(); result.WrittenBytes = absOffset;
                    result.WriteMBps = swW.Elapsed.TotalSeconds > 0 ? absOffset / 1048576.0 / swW.Elapsed.TotalSeconds : 0;
                    goto verify;
                }
                remaining -= fileSize; fileIdx++;
            }
            swW.Stop(); result.WrittenBytes = absOffset;
            result.WriteMBps = swW.Elapsed.TotalSeconds > 0 ? absOffset / 1048576.0 / swW.Elapsed.TotalSeconds : 0;

        verify:
            prog.Report(new Prog { PhaseIndex = 0, Phase = "Writing", PhasePercent = 100, MBps = result.WriteMBps, Status = "write phase done" });
            long verifyTotal = result.WrittenBytes, vOffset = 0; var swR = Stopwatch.StartNew(); fileIdx = 0; long vRemaining = verifyTotal;
            while (vRemaining > 0)
            {
                ct.ThrowIfCancellationRequested();
                long fileSize = Math.Min(plan.ChunkSize, vRemaining);
                string path = Path.Combine(plan.Root, $"{FilePrefix}{fileIdx:D5}.bin");
                using SafeFileHandle h = Native.CreateFileW(path, Native.GENERIC_READ, Native.FILE_SHARE_READ, IntPtr.Zero, Native.OPEN_EXISTING, Native.FILE_FLAG_NO_BUFFERING | Native.FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
                if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                long pos = 0;
                while (pos < fileSize)
                {
                    ct.ThrowIfCancellationRequested();
                    int toRead = (int)Math.Min(block, fileSize - pos);
                    int bi = (int)(vOffset / block); if (bi < states.Length && states[bi] != St.Fail) states[bi] = St.Verifying;
                    if (!Native.ReadFile(h, readBuf, (uint)toRead, out uint got, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (got == 0) break;
                    Marshal.Copy(readBuf, verifyBuf, 0, (int)got);
                    long bad = Pattern.Verify(verifyBuf, (int)got, (ulong)vOffset, out bool zero, out _);
                    if (bad < 0) { if (bi < states.Length) states[bi] = St.Verified; result.VerifiedGoodBytes = vOffset + got; }
                    else { if (bi < states.Length) states[bi] = St.Fail; if (result.FirstFailOffset < 0) { result.FirstFailOffset = vOffset + bad; result.FailLooksZero = zero; } }
                    pos += got; vOffset += got;
                    double mbps = swR.Elapsed.TotalSeconds > 0 ? vOffset / 1048576.0 / swR.Elapsed.TotalSeconds : 0;
                    prog.Report(new Prog { PhaseIndex = 1, Phase = "Verifying", PhasePercent = verifyTotal > 0 ? vOffset * 100.0 / verifyTotal : 100, MBps = mbps, Status = $"{Fmt.Bytes(vOffset)} / {Fmt.Bytes(verifyTotal)}" + (result.FirstFailOffset >= 0 ? $"  ERROR @ {Fmt.Bytes(result.FirstFailOffset)}" : "") });
                }
                vRemaining -= fileSize; fileIdx++;
            }
            swR.Stop(); result.ReadMBps = swR.Elapsed.TotalSeconds > 0 ? vOffset / 1048576.0 / swR.Elapsed.TotalSeconds : 0;
            result.Completed = true;
            prog.Report(new Prog { PhaseIndex = 1, Phase = "Verifying", PhasePercent = 100, MBps = result.ReadMBps, Status = "verify phase done" });
        }
        catch (OperationCanceledException) { result.Cancelled = true; }
        catch (Exception ex) { result.Error = ex.Message; }
        finally { Marshal.FreeHGlobal(rawBuf); if (!keepFiles) Cleanup(plan.Root); }
        return result;
    }

    public static void Cleanup(string root)
    {
        try { foreach (var f in Directory.EnumerateFiles(root, FilePrefix + "*.bin")) { try { File.Delete(f); } catch { } } }
        catch { }
    }
}

// ===========================================================================
//  Raw fraud engine.
// ===========================================================================
internal enum RawVerdict { Genuine, Void, Wrap, WriteRefused, Corruption, Error }

internal sealed class RawResult
{
    public bool Cancelled; public string? Error; public RawVerdict Verdict = RawVerdict.Error;
    public long ClaimedBytes; public long RealBytes = -1; public long FirstFailOffset = -1; public long LastGoodEnd;
    public double WriteMBps; public double ReadMBps; public string Model = ""; public int Sector; public int Probes;
    public int PinpointSteps; public string Detail = "";
}

internal static class RawIo
{
    public static SafeFileHandle OpenDisk(string physPath)
        => Native.CreateFileW(physPath, Native.GENERIC_READ | Native.GENERIC_WRITE,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_NO_BUFFERING | Native.FILE_FLAG_WRITE_THROUGH, IntPtr.Zero);

    public static SafeFileHandle OpenDiskRead(string physPath)
        => Native.CreateFileW(physPath, Native.GENERIC_READ,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING,
            0, IntPtr.Zero);

    public static List<SafeFileHandle> LockVolumes(IReadOnlyList<string> letters)
    {
        var locks = new List<SafeFileHandle>();
        foreach (var letter in letters)
        {
            string vp = $"\\\\.\\{letter.TrimEnd('\\', ':')}:";
            var vh = Native.CreateFileW(vp, Native.GENERIC_READ | Native.GENERIC_WRITE,
                Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero);
            if (vh.IsInvalid) { vh.Dispose(); continue; }
            Native.DeviceIoControl(vh, Native.FSCTL_LOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
            Native.DeviceIoControl(vh, Native.FSCTL_DISMOUNT_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
            locks.Add(vh);
        }
        return locks;
    }

    public static void ReleaseVolumes(List<SafeFileHandle> locks)
    {
        foreach (var vh in locks)
        {
            try { Native.DeviceIoControl(vh, Native.FSCTL_UNLOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero); } catch { }
            vh.Dispose();
        }
    }

    public static void WriteAt(SafeFileHandle h, IntPtr buf, long off, int len)
    {
        if (!Native.SetFilePointerEx(h, off, out _, Native.FILE_BEGIN)) throw new Win32Exception(Marshal.GetLastWin32Error(), "seek(write)");
        if (!Native.WriteFile(h, buf, (uint)len, out uint w, IntPtr.Zero) || w != len) throw new Win32Exception(Marshal.GetLastWin32Error(), $"write @ {off}");
    }

    public static void ReadAt(SafeFileHandle h, IntPtr buf, long off, int len)
    {
        if (!Native.SetFilePointerEx(h, off, out _, Native.FILE_BEGIN)) throw new Win32Exception(Marshal.GetLastWin32Error(), "seek(read)");
        if (!Native.ReadFile(h, buf, (uint)len, out uint g, IntPtr.Zero) || g != len) throw new Win32Exception(Marshal.GetLastWin32Error(), $"read @ {off}");
    }

    public static double Mbps(Stopwatch sw, long bytes) => sw.Elapsed.TotalSeconds > 0 ? bytes / 1048576.0 / sw.Elapsed.TotalSeconds : 0;
}

internal sealed class RawTester
{
    private readonly int _blk = 1 << 20;

    public RawResult Run(string physPath, int diskNumber, IReadOnlyList<string> volsToLock, byte[] states, IProgress<Prog> prog, CancellationToken ct)
    {
        var r = new RawResult();
        List<SafeFileHandle> locks = new();
        SafeFileHandle? hDisk = null;
        IntPtr rawBuf = IntPtr.Zero;
        try
        {
            hDisk = RawIo.OpenDisk(physPath);
            if (hDisk.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Open {physPath} failed (need admin?)");
            long size = Native.DiskLength(hDisk);
            int sector = Native.DiskSectorSize(hDisk);
            r.Model = Native.DeviceModel(hDisk, out _);
            r.ClaimedBytes = size; r.Sector = sector;
            if (size <= 0) throw new IOException("Could not read disk length.");
            if (_blk % sector != 0) throw new IOException($"Block/sector mismatch (sector {sector}).");

            locks = RawIo.LockVolumes(volsToLock);
            rawBuf = Marshal.AllocHGlobal(_blk + sector);
            long al = (rawBuf.ToInt64() + (sector - 1)) & ~((long)(sector - 1));
            IntPtr buf = new IntPtr(al);
            byte[] managed = new byte[_blk];

            long lastOff = size - _blk; lastOff -= lastOff % sector; if (lastOff < 0) lastOff = 0;
            double[] fr = { 0, .005, .01, .02, .03, .05, .07, .10, .15, .20, .25, .33, .40, .50, .60, .66, .75, .85, .90, .95, .98, .99, .995 };
            var offsets = new SortedSet<long>();
            foreach (var f in fr) { long o = (long)(size * f); o -= o % sector; if (o < 0) o = 0; if (o > lastOff) o = lastOff; offsets.Add(o); }
            offsets.Add(lastOff);
            var probeList = offsets.Where(o => o >= 0 && o <= lastOff).ToList();
            r.Probes = probeList.Count;

            void Mark(long off, byte s)
            {
                if (states.Length == 0) return;
                int cell = (int)(off * (long)(states.Length - 1) / Math.Max(1L, size));
                if (cell >= 0 && cell < states.Length) states[cell] = s;
            }

            var swW = Stopwatch.StartNew(); int done = 0;
            foreach (var off in probeList)
            {
                ct.ThrowIfCancellationRequested();
                Mark(off, St.Writing);
                Pattern.Fill(managed, _blk, (ulong)off);
                Marshal.Copy(managed, 0, buf, _blk);
                try { RawIo.WriteAt(hDisk, buf, off, _blk); }
                catch (Win32Exception)
                {
                    if (off == 0) throw;
                    swW.Stop();
                    r.Verdict = RawVerdict.WriteRefused; r.FirstFailOffset = off; r.RealBytes = off;
                    r.WriteMBps = RawIo.Mbps(swW, (long)done * _blk);
                    r.Detail = "The device refused writes before the end of its claimed size.";
                    return r;
                }
                Mark(off, St.Written); done++;
                prog.Report(new Prog { PhaseIndex = 0, Phase = "Writing probes", PhasePercent = done * 100.0 / r.Probes, MBps = RawIo.Mbps(swW, (long)done * _blk), Status = $"probe {done}/{r.Probes} @ {Fmt.Bytes(off)}" });
            }
            swW.Stop(); r.WriteMBps = RawIo.Mbps(swW, (long)done * _blk);
            prog.Report(new Prog { PhaseIndex = 0, Phase = "Writing probes", PhasePercent = 100, MBps = r.WriteMBps, Status = "all probes written" });

            var swR = Stopwatch.StartNew(); done = 0;
            long firstFail = -1, lastGoodEnd = 0, wrapReal = -1; RawVerdict failKind = RawVerdict.Genuine;
            foreach (var off in probeList)
            {
                ct.ThrowIfCancellationRequested();
                Mark(off, St.Verifying);
                RawIo.ReadAt(hDisk, buf, off, _blk);
                Marshal.Copy(buf, managed, 0, _blk);
                long bad = Pattern.Verify(managed, _blk, (ulong)off, out bool zero, out ulong actual);
                if (bad < 0) { Mark(off, St.Verified); lastGoodEnd = Math.Max(lastGoodEnd, off + _blk); }
                else
                {
                    Mark(off, St.Fail);
                    if (firstFail < 0)
                    {
                        firstFail = off + bad;
                        if (zero) failKind = RawVerdict.Void;
                        else
                        {
                            ulong here = (ulong)(off + bad);
                            ulong srcO = Pattern.InvMix(actual);
                            bool valid = (srcO % 8 == 0) && srcO < (ulong)size && Pattern.Mix(srcO) == actual && srcO != here;
                            if (valid && srcO < here) { failKind = RawVerdict.Wrap; wrapReal = (long)(here - srcO); }
                            else failKind = RawVerdict.Corruption;
                        }
                    }
                }
                done++;
                prog.Report(new Prog { PhaseIndex = 1, Phase = "Verifying probes", PhasePercent = done * 100.0 / r.Probes, MBps = RawIo.Mbps(swR, (long)done * _blk), Status = $"probe {done}/{r.Probes} @ {Fmt.Bytes(off)}" + (firstFail >= 0 ? $"  FAIL @ {Fmt.Bytes(firstFail)}" : "") });
            }
            swR.Stop(); r.ReadMBps = RawIo.Mbps(swR, (long)done * _blk);
            r.FirstFailOffset = firstFail; r.LastGoodEnd = lastGoodEnd;
            prog.Report(new Prog { PhaseIndex = 1, Phase = "Verifying probes", PhasePercent = 100, MBps = r.ReadMBps, Status = "all probes verified" });

            if (firstFail < 0)
            {
                r.Verdict = RawVerdict.Genuine; r.RealBytes = size;
                r.Detail = "All sampled points across the full claimed size verified.";
                prog.Report(new Prog { PhaseIndex = 2, Phase = "Pinpointing size", PhasePercent = 100, MBps = 0, Status = "not needed - genuine" });
                return r;
            }
            if (failKind == RawVerdict.Wrap && wrapReal > 0)
            {
                r.Verdict = RawVerdict.Wrap; r.RealBytes = wrapReal;
                r.Detail = "Writes wrap over earlier data; exact stride recovered by reversing the pattern.";
                prog.Report(new Prog { PhaseIndex = 2, Phase = "Pinpointing size", PhasePercent = 100, MBps = 0, Status = "exact size from wrap stride" });
                return r;
            }

            long lo = lastGoodEnd, hi = firstFail - (firstFail % sector); if (hi < lo) hi = lo;
            long span = Math.Max(1, hi - lo);
            int estSteps = Math.Max(1, (int)Math.Ceiling(Math.Log2(Math.Max(2.0, (double)span / sector))));
            long steps = 0;
            prog.Report(new Prog { PhaseIndex = 2, Phase = "Pinpointing size", PhasePercent = 0, MBps = 0, Status = $"searching [{Fmt.Bytes(lo)} , {Fmt.Bytes(hi)}]" });
            while (hi - lo > sector)
            {
                ct.ThrowIfCancellationRequested();
                long mid = lo + ((hi - lo) / 2); mid -= mid % sector; if (mid <= lo) break;
                Pattern.Fill(managed, sector, (ulong)mid);
                Marshal.Copy(managed, 0, buf, sector);
                RawIo.WriteAt(hDisk, buf, mid, sector);
                RawIo.ReadAt(hDisk, buf, mid, sector);
                Marshal.Copy(buf, managed, 0, sector);
                long bad = Pattern.Verify(managed, sector, (ulong)mid, out _, out _);
                if (bad < 0) lo = mid + sector; else hi = mid;
                Mark(mid, bad < 0 ? St.Verified : St.Fail);
                steps++;
                prog.Report(new Prog { PhaseIndex = 2, Phase = "Pinpointing size", PhasePercent = Math.Min(99, steps * 100.0 / estSteps), MBps = 0, Status = $"step {steps}: [{Fmt.Bytes(lo)} , {Fmt.Bytes(hi)}]" });
            }
            r.PinpointSteps = (int)steps;
            r.Verdict = failKind == RawVerdict.Corruption ? RawVerdict.Corruption : RawVerdict.Void;
            r.RealBytes = hi;
            r.Detail = failKind == RawVerdict.Corruption
                ? $"Reads past the real chip return corrupted data. Boundary pinned in {steps} steps."
                : $"Reads past the real chip return zeros. Boundary pinned to sector precision in {steps} steps.";
            prog.Report(new Prog { PhaseIndex = 2, Phase = "Pinpointing size", PhasePercent = 100, MBps = 0, Status = $"boundary fixed at {Fmt.Bytes(hi)} in {steps} steps" });
            return r;
        }
        catch (OperationCanceledException) { r.Cancelled = true; return r; }
        catch (Exception ex) { r.Error = ex.Message; r.Verdict = RawVerdict.Error; return r; }
        finally
        {
            if (rawBuf != IntPtr.Zero) Marshal.FreeHGlobal(rawBuf);
            RawIo.ReleaseVolumes(locks);
            hDisk?.Dispose();
        }
    }
}

// ===========================================================================
//  Drive tools: benchmark, TRIM optimize, cap-to-real-size, secure wipe.
// ===========================================================================
internal sealed class BenchResult
{
    public bool Cancelled; public string? Error;
    public double WriteAvg, ReadAvg, WritePeak, ReadPeak;
    public long Bytes;
}

internal sealed class OpResult { public bool Ok; public bool Cancelled; public string? Error; public string Log = ""; }

internal static class Tools
{
    private const string BenchFile = "d8bench.tmp";

    // Non-destructive throughput test. Appends per-chunk MB/s to the sinks (if given).
    public static BenchResult Benchmark(string root, int phaseWrite, int phaseRead,
        List<double>? writeSink, List<double>? readSink, object gate,
        IProgress<Prog> prog, CancellationToken ct)
    {
        var res = new BenchResult();
        int sector = Native.FsSectorSize(root);
        int chunk = 8 * 1024 * 1024;
        long free;
        try { free = new DriveInfo(root).AvailableFreeSpace; } catch { free = 0; }
        long target = Math.Min(512L * 1024 * 1024, Math.Max(32L * 1024 * 1024, free / 2));
        target -= target % chunk; if (target < chunk) target = chunk;
        int samples = (int)(target / chunk);
        string path = Path.Combine(root, BenchFile);

        IntPtr rawBuf = Marshal.AllocHGlobal(chunk + sector);
        long al = (rawBuf.ToInt64() + (sector - 1)) & ~((long)(sector - 1));
        IntPtr aligned = new IntPtr(al);
        byte[] wbuf = new byte[chunk], rbuf = new byte[chunk];
        try
        {
            double sumW = 0, sumR = 0;
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, FileOptions.WriteThrough))
            {
                for (int i = 0; i < samples; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    Pattern.Fill(wbuf, chunk, (ulong)((long)i * chunk));
                    var sw = Stopwatch.StartNew();
                    fs.Write(wbuf, 0, chunk);
                    sw.Stop();
                    double mb = chunk / 1048576.0 / Math.Max(1e-6, sw.Elapsed.TotalSeconds);
                    sumW += mb; res.WritePeak = Math.Max(res.WritePeak, mb);
                    if (writeSink != null) lock (gate) writeSink.Add(mb);
                    prog.Report(new Prog { PhaseIndex = phaseWrite, Phase = "Write BW", PhasePercent = (i + 1) * 100.0 / samples, MBps = mb, Status = $"{i + 1}/{samples} chunks" });
                }
                fs.Flush(true);
            }
            res.WriteAvg = sumW / samples;

            using (SafeFileHandle h = Native.CreateFileW(path, Native.GENERIC_READ, Native.FILE_SHARE_READ, IntPtr.Zero, Native.OPEN_EXISTING, Native.FILE_FLAG_NO_BUFFERING | Native.FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero))
            {
                if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                for (int i = 0; i < samples; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var sw = Stopwatch.StartNew();
                    if (!Native.ReadFile(h, aligned, (uint)chunk, out uint got, IntPtr.Zero) || got == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
                    sw.Stop();
                    Marshal.Copy(aligned, rbuf, 0, (int)got);
                    double mb = got / 1048576.0 / Math.Max(1e-6, sw.Elapsed.TotalSeconds);
                    sumR += mb; res.ReadPeak = Math.Max(res.ReadPeak, mb);
                    if (readSink != null) lock (gate) readSink.Add(mb);
                    prog.Report(new Prog { PhaseIndex = phaseRead, Phase = "Read BW", PhasePercent = (i + 1) * 100.0 / samples, MBps = mb, Status = $"{i + 1}/{samples} chunks" });
                }
            }
            res.ReadAvg = sumR / samples;
            res.Bytes = (long)samples * chunk;
        }
        catch (OperationCanceledException) { res.Cancelled = true; }
        catch (Exception ex) { res.Error = ex.Message; }
        finally
        {
            Marshal.FreeHGlobal(rawBuf);
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
        return res;
    }

    // Real Windows TRIM engine. Parses live "NN% complete" from verbose output.
    public static OpResult Trim(string letter, int phase, IProgress<Prog> prog, CancellationToken ct)
    {
        var res = new OpResult();
        var log = new StringBuilder();
        try
        {
            string l = letter.TrimEnd('\\', ':');
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Optimize-Volume -DriveLetter {l} -ReTrim -Verbose 4>&1\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi) ?? throw new IOException("Could not start powershell.");
            var pctRe = new Regex(@"(\d{1,3})\s*%");
            var swElapsed = Stopwatch.StartNew();
            prog.Report(new Prog { PhaseIndex = phase, Phase = "TRIM", PhasePercent = 1, MBps = 0, Status = "starting Optimize-Volume..." });

            while (!p.StandardOutput.EndOfStream)
            {
                if (ct.IsCancellationRequested) { try { p.Kill(true); } catch { } res.Cancelled = true; break; }
                string? line = p.StandardOutput.ReadLine();
                if (line == null) break;
                log.AppendLine(line);
                var m = pctRe.Match(line);
                if (m.Success && int.TryParse(m.Groups[1].Value, out int pct))
                    prog.Report(new Prog { PhaseIndex = phase, Phase = "TRIM", PhasePercent = Math.Min(100, pct), MBps = 0, Status = $"retrim {pct}%" });
                else
                    prog.Report(new Prog { PhaseIndex = phase, Phase = "TRIM", PhasePercent = 0, MBps = 0, Status = $"optimizing... ({swElapsed.Elapsed.Seconds}s)" });
            }
            string err = p.StandardError.ReadToEnd();
            if (!string.IsNullOrWhiteSpace(err)) log.AppendLine(err.Trim());
            p.WaitForExit();
            res.Ok = !res.Cancelled && p.ExitCode == 0;
            if (!res.Ok && !res.Cancelled)
            {
                string all = log.ToString();
                if (all.IndexOf("not supported", StringComparison.OrdinalIgnoreCase) >= 0)
                    res.Error = "This drive's hardware doesn't support TRIM (normal for USB flash sticks).";
                else
                {
                    string? line = all.Split('\n')
                        .Select(x => x.Trim())
                        .LastOrDefault(x => x.Length > 0 &&
                            (x.IndexOf("Optimize-Volume", StringComparison.OrdinalIgnoreCase) >= 0
                             || x.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0));
                    res.Error = string.IsNullOrEmpty(line) ? $"Optimize-Volume exit code {p.ExitCode}." : line;
                }
            }
            if (res.Ok) prog.Report(new Prog { PhaseIndex = phase, Phase = "TRIM", PhasePercent = 100, MBps = 0, Status = "retrim complete" });
        }
        catch (Exception ex) { res.Error = ex.Message; }
        res.Log = log.ToString();
        return res;
    }

    // Repartition a disk down to its real usable size (with a 1 MiB safety margin).
    public static OpResult CapToReal(int disk, long realBytes)
    {
        var res = new OpResult();
        long sizeMB = realBytes / (1024 * 1024);
        if (sizeMB > 1) sizeMB -= 1;
        if (sizeMB < 1) sizeMB = 1;
        string script =
            "$ErrorActionPreference='Stop';" +
            $"Clear-Disk -Number {disk} -RemoveData -Confirm:$false;" +
            $"$p=New-Partition -DiskNumber {disk} -Size {sizeMB}MB -AssignDriveLetter;" +
            "Format-Volume -Partition $p -FileSystem exFAT -NewFileSystemLabel 'D8-REAL' -Confirm:$false";
        RunPs(script, out bool ok, out string? error, out string log);
        res.Ok = ok;
        res.Error = error;
        res.Log = (ok ? $"Capped partition to {sizeMB} MB (exFAT, label D8-REAL).\r\n" : "") + log;
        return res;
    }

    private static string SafeLabel(string label)
    {
        string s = new string((label ?? "").Where(c => c != '\'' && c != '"' && c != '`').ToArray()).Trim();
        if (s.Length == 0) s = "D8-DRIVE";
        if (s.Length > 32) s = s.Substring(0, 32);
        return s;
    }

    // Format an existing lettered volume (works on a raw/unformatted volume that still has a letter).
    public static OpResult FormatVolume(string letter, string fs, string label)
    {
        var res = new OpResult();
        string l = letter.TrimEnd('\\', ':');
        string lbl = SafeLabel(label);
        string script =
            "$ErrorActionPreference='Stop';" +
            $"Format-Volume -DriveLetter {l} -FileSystem {fs} -NewFileSystemLabel '{lbl}' -Force -Confirm:$false";
        RunPs(script, out bool ok, out string? error, out string log);
        res.Ok = ok; res.Error = error;
        res.Log = (ok ? $"Formatted {l}: as {fs} (label '{lbl}').\r\n" : "") + log;
        return res;
    }

    // Format a physical disk that has no partition yet (e.g. right after diskpart 'clean').
    public static OpResult FormatRawDisk(int disk, string fs, string label)
    {
        var res = new OpResult();
        string lbl = SafeLabel(label);
        string script =
            "$ErrorActionPreference='Stop';" +
            $"$d=Get-Disk -Number {disk};" +
            $"if($d.IsOffline){{Set-Disk -Number {disk} -IsOffline $false}};" +
            $"if($d.IsReadOnly){{Set-Disk -Number {disk} -IsReadOnly $false}};" +
            $"if((Get-Disk -Number {disk}).PartitionStyle -eq 'RAW'){{Initialize-Disk -Number {disk} -PartitionStyle MBR}};" +
            $"$p=New-Partition -DiskNumber {disk} -UseMaximumSize -AssignDriveLetter;" +
            $"Format-Volume -Partition $p -FileSystem {fs} -NewFileSystemLabel '{lbl}' -Force -Confirm:$false";
        RunPs(script, out bool ok, out string? error, out string log);
        res.Ok = ok; res.Error = error;
        res.Log = (ok ? $"Partitioned + formatted PhysicalDrive{disk} as {fs} (label '{lbl}').\r\n" : "") + log;
        return res;
    }

    private static void RunPs(string script, out bool ok, out string? error, out string log)
    {
        ok = false; error = null;
        var sb = new StringBuilder();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi) ?? throw new IOException("Could not start powershell.");
            sb.Append(p.StandardOutput.ReadToEnd());
            string err = p.StandardError.ReadToEnd();
            p.WaitForExit();
            if (!string.IsNullOrWhiteSpace(err)) sb.AppendLine(err.Trim());
            ok = p.ExitCode == 0;
            if (!ok) error = $"PowerShell exit code {p.ExitCode}.";
        }
        catch (Exception ex) { error = ex.Message; }
        log = sb.ToString();
    }

    // Raw zero-fill across the whole physical disk.
    public static OpResult Wipe(string physPath, IReadOnlyList<string> vols, int phase, IProgress<Prog> prog, CancellationToken ct)
    {
        var res = new OpResult();
        List<SafeFileHandle> locks = new();
        SafeFileHandle? hDisk = null;
        IntPtr rawBuf = IntPtr.Zero;
        try
        {
            hDisk = RawIo.OpenDisk(physPath);
            if (hDisk.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Open {physPath} failed (need admin?)");
            long size = Native.DiskLength(hDisk);
            int sector = Native.DiskSectorSize(hDisk);
            if (size <= 0) throw new IOException("Could not read disk length.");
            int block = 8 * 1024 * 1024;
            locks = RawIo.LockVolumes(vols);
            rawBuf = Marshal.AllocHGlobal(block + sector);
            long al = (rawBuf.ToInt64() + (sector - 1)) & ~((long)(sector - 1));
            IntPtr buf = new IntPtr(al);
            byte[] zeros = new byte[block]; // already zero
            Marshal.Copy(zeros, 0, buf, block);

            long off = 0; var sw = Stopwatch.StartNew();
            while (off < size)
            {
                ct.ThrowIfCancellationRequested();
                int len = (int)Math.Min(block, size - off);
                len -= len % sector; if (len == 0) break;
                RawIo.WriteAt(hDisk, buf, off, len);
                off += len;
                prog.Report(new Prog { PhaseIndex = phase, Phase = "Zero-fill", PhasePercent = off * 100.0 / size, MBps = RawIo.Mbps(sw, off), Status = $"{Fmt.Bytes(off)} / {Fmt.Bytes(size)}" });
            }
            res.Ok = true;
            res.Log = $"Zero-filled {Fmt.Bytes(off)} at {RawIo.Mbps(sw, off):0.0} MB/s.";
        }
        catch (OperationCanceledException) { res.Cancelled = true; }
        catch (Exception ex) { res.Error = ex.Message; }
        finally
        {
            if (rawBuf != IntPtr.Zero) Marshal.FreeHGlobal(rawBuf);
            RawIo.ReleaseVolumes(locks);
            hDisk?.Dispose();
        }
        return res;
    }
}

// ---------------------------------------------------------------------------
//  USB / disk metadata (manufacturer, model, VID/PID, serial) via WMI.
// ---------------------------------------------------------------------------
internal sealed class DriveMeta
{
    public string Model = "";
    public string Manufacturer = "";
    public string Serial = "";
    public string Interface = "";
    public string Size = "";
    public string Pnp = "";
    public string Vid = "";
    public string Pid = "";
    public string Vendor = "";
    public string Mismatch = "";
    public string FriendlyName = "";   // MSFT_PhysicalDisk (sometimes the real drive)
    public string MediaType = "";       // SSD / HDD / Unspecified
    public string BusType = "";         // USB / SATA / NVMe / ...
    public bool IsBridge;               // model looks like a USB-to-SATA/NVMe adapter
    public string AtaModel = "";        // real drive model via ATA IDENTIFY through the bridge
    public string AtaSerial = "";
    public string AtaFirmware = "";
    public bool Unmasked;               // ATA IDENTIFY succeeded behind a bridge
}

internal static class UsbMeta
{
    // Runs from a temp .ps1 (via -File) so there is no inline-escaping to get wrong.
    private const string MetaScript = @"
param([int]$Index)
$ErrorActionPreference='SilentlyContinue'
$d = Get-CimInstance Win32_DiskDrive -Filter ""Index=$Index""
if (-not $d) { '{}'; exit }
$out = [ordered]@{
  Model = [string]$d.Model
  Manufacturer = [string]$d.Manufacturer
  Serial = ([string]$d.SerialNumber).Trim()
  Interface = [string]$d.InterfaceType
  Size = [string]$d.Size
  Pnp = [string]$d.PNPDeviceID
  Vid = ''
  Pid = ''
  FriendlyName = ''
  MediaType = ''
  BusType = ''
}
$leaf = ($d.PNPDeviceID -split '\\')[-1] -replace '&0$',''
if ($leaf) {
  $usb = Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -match 'VID_' -and $_.DeviceID -match [regex]::Escape($leaf) } | Select-Object -First 1
  if ($usb -and ($usb.DeviceID -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})')) {
    $out.Vid = $matches[1]
    $out.Pid = $matches[2]
  }
}
$pd = Get-CimInstance -Namespace root\Microsoft\Windows\Storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq $Index } | Select-Object -First 1
if ($pd) {
  $out.FriendlyName = [string]$pd.FriendlyName
  $mt = @{0='Unspecified';3='HDD';4='SSD';5='SCM'}[[int]$pd.MediaType]; if (-not $mt) { $mt = '' }
  $out.MediaType = $mt
  $bt = @{7='USB';8='RAID';9='iSCSI';11='SATA';17='NVMe';3='ATA';10='SAS'}[[int]$pd.BusType]; if (-not $bt) { $bt = '' }
  $out.BusType = $bt
}
($out | ConvertTo-Json -Compress)
";

    private static readonly Dictionary<string, string> Vendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["0781"] = "SanDisk", ["04e8"] = "Samsung", ["0951"] = "Kingston", ["154b"] = "PNY",
        ["8564"] = "Transcend", ["125f"] = "ADATA", ["05dc"] = "Lexar", ["1b1c"] = "Corsair",
        ["0930"] = "Toshiba", ["18a5"] = "Verbatim",
        ["090c"] = "Silicon Motion (controller maker)", ["058f"] = "Alcor Micro (controller maker)",
        ["1f75"] = "Innostor (controller maker)", ["13fe"] = "Phison/Kingston (generic)",
        ["048d"] = "ITE (controller maker)", ["0c76"] = "JMTek (generic)", ["1516"] = "CBM (controller maker)"
    };
    private static readonly string[] Generics = { "090c", "058f", "1f75", "13fe", "048d", "0c76", "1516" };
    private static readonly string[] Brands = { "sandisk", "samsung", "kingston", "lexar", "pny", "corsair", "transcend", "adata", "toshiba", "sony", "verbatim", "integral" };

    public static DriveMeta? Query(int index)
    {
        if (index < 0) return null;
        string ps = Path.Combine(Path.GetTempPath(), $"d8meta_{Guid.NewGuid():N}.ps1");
        try
        {
            File.WriteAllText(ps, MetaScript);
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{ps}\" -Index {index}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            string json = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(6000)) { try { p.Kill(true); } catch { } return null; }
            json = json.Trim();
            if (json.Length == 0 || json[0] != '{') return null;
            var meta = Parse(json);
            if (meta != null && meta.IsBridge)
            {
                var ata = AtaIdentify(index);
                if (ata is (string mdl, string ser, string fw2) && !string.IsNullOrWhiteSpace(mdl))
                {
                    meta.AtaModel = mdl;
                    meta.AtaSerial = ser;
                    meta.AtaFirmware = fw2;
                    meta.Unmasked = true;
                }
            }
            return meta;
        }
        catch { return null; }
        finally { try { if (File.Exists(ps)) File.Delete(ps); } catch { } }
    }

    // Read-only ATA IDENTIFY DEVICE (0xEC) through a SCSI/SAT bridge. Returns the
    // real drive's (model, serial, firmware), or null if the bridge won't forward it
    // (cheap bridges) or we lack admin. Never writes or erases anything.
    private static (string model, string serial, string fw)? AtaIdentify(int diskIndex)
    {
        string path = $"\\\\.\\PhysicalDrive{diskIndex}";
        using var h = Native.CreateFileW(path, Native.GENERIC_READ | Native.GENERIC_WRITE,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero, Native.OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return null;

        IntPtr dataBuf = Marshal.AllocHGlobal(512);
        IntPtr sptBuf = IntPtr.Zero;
        try
        {
            for (int i = 0; i < 512; i++) Marshal.WriteByte(dataBuf, i, 0);
            var sptwb = new SPTD_WITH_SENSE
            {
                Spt = new SCSI_PASS_THROUGH_DIRECT
                {
                    Length = (ushort)Marshal.SizeOf<SCSI_PASS_THROUGH_DIRECT>(),
                    CdbLength = 12,
                    DataIn = 1,                 // SCSI_IOCTL_DATA_IN
                    DataTransferLength = 512,
                    TimeOutValue = 5,
                    DataBuffer = dataBuf,
                    SenseInfoLength = 32,
                    SenseInfoOffset = (uint)Marshal.OffsetOf<SPTD_WITH_SENSE>(nameof(SPTD_WITH_SENSE.Sense)),
                    Cdb = new byte[16]
                },
                Sense = new byte[32]
            };
            // ATA PASS-THROUGH(12): PIO data-in, 1 sector, IDENTIFY DEVICE
            sptwb.Spt.Cdb[0] = 0xA1;  // ATA PASS-THROUGH(12)
            sptwb.Spt.Cdb[1] = 0x08;  // PROTOCOL = PIO Data-In (4 << 1)
            sptwb.Spt.Cdb[2] = 0x0E;  // T_DIR=1, BYTE_BLOCK=1, T_LENGTH=2
            sptwb.Spt.Cdb[4] = 0x01;  // sector count = 1
            sptwb.Spt.Cdb[9] = 0xEC;  // COMMAND = IDENTIFY DEVICE

            int size = Marshal.SizeOf<SPTD_WITH_SENSE>();
            sptBuf = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(sptwb, sptBuf, false);
            bool ok = Native.DeviceIoControl(h, Native.IOCTL_SCSI_PASS_THROUGH_DIRECT,
                sptBuf, (uint)size, sptBuf, (uint)size, out _, IntPtr.Zero);
            if (!ok) return null;

            byte[] id = new byte[512];
            Marshal.Copy(dataBuf, id, 0, 512);
            string model = AtaString(id, 54, 40);    // words 27-46
            string serial = AtaString(id, 20, 20);   // words 10-19
            string fw = AtaString(id, 46, 8);         // words 23-26
            if (string.IsNullOrWhiteSpace(model)) return null;
            return (model, serial, fw);
        }
        catch { return null; }
        finally
        {
            if (sptBuf != IntPtr.Zero) Marshal.FreeHGlobal(sptBuf);
            Marshal.FreeHGlobal(dataBuf);
        }
    }

    // ATA IDENTIFY strings are byte-swapped within each 16-bit word.
    private static string AtaString(byte[] id, int offset, int len)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < len && offset + i + 1 < id.Length; i += 2)
        {
            sb.Append((char)id[offset + i + 1]);
            sb.Append((char)id[offset + i]);
        }
        return sb.ToString().Replace('\0', ' ').Trim();
    }

    private static DriveMeta? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.ValueKind == JsonValueKind.Array) { if (r.GetArrayLength() == 0) return null; r = r[0]; }
            string G(string k) => r.TryGetProperty(k, out var v) && v.ValueKind != JsonValueKind.Null
                ? (v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString()) : "";
            var m = new DriveMeta
            {
                Model = G("Model").Trim(),
                Manufacturer = G("Manufacturer").Trim(),
                Serial = G("Serial").Trim(),
                Interface = G("Interface").Trim(),
                Size = G("Size").Trim(),
                Pnp = G("Pnp").Trim(),
                Vid = G("Vid").Trim(),
                Pid = G("Pid").Trim(),
                FriendlyName = G("FriendlyName").Trim(),
                MediaType = G("MediaType").Trim(),
                BusType = G("BusType").Trim()
            };
            if (m.Vid.Length == 4 && Vendors.TryGetValue(m.Vid, out var vn)) m.Vendor = vn;
            else if (m.Vid.Length == 4) m.Vendor = "unknown vendor";
            if (m.Vid.Length == 4)
            {
                string ml = m.Model.ToLowerInvariant();
                string? brand = Brands.FirstOrDefault(b => ml.Contains(b));
                bool generic = Generics.Contains(m.Vid.ToLowerInvariant());
                if (brand != null && generic)
                    m.Mismatch = $"Model text says '{brand}' but USB vendor ID {m.Vid} is a controller maker, not that brand - verify authenticity.";
            }
            // A drive behind a USB-to-SATA/NVMe bridge often reports the *adapter*, not the
            // drive inside. Tell-tale: USB bus + a "SCSI Disk Device" style model.
            string mlow = m.Model.ToLowerInvariant();
            bool usb = m.BusType.Equals("USB", StringComparison.OrdinalIgnoreCase)
                    || m.Interface.Equals("USB", StringComparison.OrdinalIgnoreCase);
            if (usb && (mlow.Contains("scsi disk device") || mlow.Contains("usb device")))
                m.IsBridge = true;
            return m;
        }
        catch { return null; }
    }
}

// ---------------------------------------------------------------------------
//  Block-map control.
// ---------------------------------------------------------------------------
internal sealed class BlockMap : Control
{
    public byte[]? States;

    public BlockMap()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
               | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Color.FromArgb(30, 30, 34);
    }

    private static int Pri(byte s) => s switch { St.Fail => 100, St.Verified => 40, St.Written => 25, St.Verifying => 20, St.Writing => 15, _ => 0 };
    private static Color Col(byte s) => s switch
    {
        St.Fail => Color.FromArgb(220, 60, 60),
        St.Verified => Color.FromArgb(70, 190, 90),
        St.Written => Color.FromArgb(70, 110, 190),
        St.Verifying => Color.FromArgb(220, 190, 60),
        St.Writing => Color.FromArgb(210, 140, 50),
        _ => Color.FromArgb(70, 70, 76)
    };

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics; var st = States; int w = Width, h = Height;
        if (st == null || st.Length == 0 || w <= 0)
        {
            using var b0 = new SolidBrush(Color.FromArgb(70, 70, 76));
            g.FillRectangle(b0, 0, 0, w, h);
            if (w > 40 && h > 20)
            {
                using var tf = new Font(FontFamily.GenericSansSerif, 8f);
                using var tb = new SolidBrush(Color.FromArgb(120, 120, 128));
                const string msg = "block map — fills during a fraud test";
                var sz = g.MeasureString(msg, tf);
                g.DrawString(msg, tf, tb, (w - sz.Width) / 2, (h - sz.Height) / 2);
            }
            return;
        }
        for (int x = 0; x < w; x++)
        {
            long start = (long)x * st.Length / w, end = (long)(x + 1) * st.Length / w;
            if (end <= start) end = start + 1;
            byte worst = 0;
            for (long i = start; i < end && i < st.Length; i++) if (Pri(st[i]) > Pri(worst)) worst = st[i];
            using var b = new SolidBrush(Col(worst));
            g.FillRectangle(b, x, 0, 1, h);
        }
    }
}

// ---------------------------------------------------------------------------
//  Confirmation dialogs.
// ---------------------------------------------------------------------------
internal sealed class ConfirmFsForm : Form
{
    public ConfirmFsForm(Plan plan, Icon? appIcon)
    {
        string letter = plan.Root.TrimEnd('\\', '/');
        Text = "Confirm test"; if (appIcon != null) Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog; StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false; ClientSize = new Size(460, 210);
        var msg = new Label { Dock = DockStyle.Top, Height = 120, Padding = new Padding(12), Text =
            $"Target: {letter}  [{plan.Label}]  ({plan.Type}, {plan.Format})\r\nClaimed: {Fmt.Bytes(plan.ClaimedBytes)}\r\nWill write ~{Fmt.Bytes(plan.TestBytes)} into free space.\r\n\r\nThis fills the drive and can corrupt existing data on a fake.\r\nType the drive letter to proceed:" };
        var tb = new TextBox { Dock = DockStyle.Fill };
        var ok = new Button { Text = "PROCEED", DialogResult = DialogResult.OK, Enabled = false, Width = 110 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 110 };
        tb.TextChanged += (_, _) => ok.Enabled = string.Equals(tb.Text.Trim().TrimEnd('\\', '/'), letter, StringComparison.OrdinalIgnoreCase);
        var row = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 44, Padding = new Padding(8) };
        row.Controls.Add(ok); row.Controls.Add(cancel);
        var host = new Panel { Dock = DockStyle.Bottom, Height = 30, Padding = new Padding(12, 0, 12, 0) }; host.Controls.Add(tb);
        Controls.Add(host); Controls.Add(row); Controls.Add(msg); AcceptButton = ok; CancelButton = cancel;
    }
}

internal sealed class ConfirmRawForm : Form
{
    public ConfirmRawForm(int diskNumber, long claimed, string model, IReadOnlyList<string> letters, Icon? appIcon, string okText, string headline)
    {
        string token = $"PhysicalDrive{diskNumber}";
        Text = "Confirm destructive operation"; if (appIcon != null) Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog; StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false; ClientSize = new Size(500, 300);
        var msg = new Label { Dock = DockStyle.Top, Height = 186, Padding = new Padding(12), ForeColor = Color.OrangeRed, Text =
            $"\\\\.\\{token}\r\nModel: {model}\r\nClaimed: {Fmt.Bytes(claimed)}\r\nVolumes to be dismounted: {(letters.Count == 0 ? "(none)" : string.Join(", ", letters))}\r\n\r\n" +
            headline + "\r\nThis destroys the partition table and ALL DATA on this disk -\r\neven if the drive turns out genuine.\r\n\r\n" +
            $"To arm, type:  {token}" };
        var tb = new TextBox { Dock = DockStyle.Fill };
        var chk = new CheckBox { Dock = DockStyle.Bottom, Height = 24, Text = "I understand this erases the entire disk.", Padding = new Padding(12, 0, 0, 0) };
        var ok = new Button { Text = okText, DialogResult = DialogResult.OK, Enabled = false, Width = 140 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 110 };
        void Upd() => ok.Enabled = chk.Checked && string.Equals(tb.Text.Trim(), token, StringComparison.OrdinalIgnoreCase);
        tb.TextChanged += (_, _) => Upd(); chk.CheckedChanged += (_, _) => Upd();
        var row = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 44, Padding = new Padding(8) };
        row.Controls.Add(ok); row.Controls.Add(cancel);
        var host = new Panel { Dock = DockStyle.Bottom, Height = 30, Padding = new Padding(12, 0, 12, 0) }; host.Controls.Add(tb);
        Controls.Add(host); Controls.Add(row); Controls.Add(chk); Controls.Add(msg); AcceptButton = ok; CancelButton = cancel;
    }
}

internal sealed class InputForm : Form
{
    public string Value = "";
    public InputForm(string prompt, string def, Icon? appIcon)
    {
        Text = "Input"; if (appIcon != null) Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog; StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false; ClientSize = new Size(380, 130);
        var msg = new Label { Dock = DockStyle.Top, Height = 50, Padding = new Padding(12), Text = prompt };
        var tb = new TextBox { Dock = DockStyle.Fill, Text = def };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = 90 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90 };
        ok.Click += (_, _) => Value = tb.Text.Trim();
        var row = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 44, Padding = new Padding(8) };
        row.Controls.Add(ok); row.Controls.Add(cancel);
        var host = new Panel { Dock = DockStyle.Bottom, Height = 30, Padding = new Padding(12, 0, 12, 0) }; host.Controls.Add(tb);
        Controls.Add(host); Controls.Add(row); Controls.Add(msg); AcceptButton = ok; CancelButton = cancel;
    }
}

internal sealed class FormatForm : Form
{
    public string FileSystem = "exFAT";
    public string Label = "D8-DRIVE";

    public FormatForm(string target, string defLabel, Icon? appIcon)
    {
        Text = "Format drive"; if (appIcon != null) Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog; StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false; ClientSize = new Size(400, 200);

        var msg = new Label { Dock = DockStyle.Top, Height = 56, Padding = new Padding(12),
            Text = $"Format: {target}\r\nThis erases everything on it." };

        var rowFs = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, Padding = new Padding(12, 2, 0, 0), WrapContents = false };
        rowFs.Controls.Add(new Label { Text = "File system:", AutoSize = true, Padding = new Padding(0, 6, 8, 0) });
        var cboFs = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        cboFs.Items.AddRange(new object[] { "exFAT", "NTFS", "FAT32" });
        cboFs.SelectedIndex = 0;
        rowFs.Controls.Add(cboFs);

        var rowLbl = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, Padding = new Padding(12, 2, 0, 0), WrapContents = false };
        rowLbl.Controls.Add(new Label { Text = "Label:", AutoSize = true, Padding = new Padding(0, 6, 8, 0) });
        var tbLabel = new TextBox { Width = 200, Text = defLabel };
        rowLbl.Controls.Add(tbLabel);

        var ok = new Button { Text = "Format", DialogResult = DialogResult.OK, Width = 100 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 100 };
        ok.Click += (_, _) => { FileSystem = cboFs.SelectedItem?.ToString() ?? "exFAT"; Label = tbLabel.Text.Trim(); };
        var brow = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 46, Padding = new Padding(8) };
        brow.Controls.Add(ok); brow.Controls.Add(cancel);

        Controls.Add(rowLbl); Controls.Add(rowFs); Controls.Add(msg); Controls.Add(brow);
        AcceptButton = ok; CancelButton = cancel;
    }
}

// ---------------------------------------------------------------------------
//  Main window.
// ---------------------------------------------------------------------------
internal sealed class MainForm : Form
{
    private readonly ComboBox _cboDrive = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300 };
    private readonly Button _btnRefresh = new() { Text = "Refresh", Width = 80 };
    private readonly Button _btnFormat = new() { Text = "Format", Width = 70 };
    private readonly Label _lblInfo = new() { AutoSize = false, Height = 44, Dock = DockStyle.Top, Padding = new Padding(4) };

    private readonly RadioButton _rbFs = new() { Text = "Filesystem (safe, no admin)", Checked = true, AutoSize = true };
    private readonly RadioButton _rbRaw = new() { Text = "RAW (full size, DESTROYS, admin)", AutoSize = true, ForeColor = Color.OrangeRed };

    private readonly RadioButton _rbFull = new() { Text = "Full", Checked = true, AutoSize = true };
    private readonly RadioButton _rbQuick = new() { Text = "Quick cap (GiB):", AutoSize = true };
    private readonly NumericUpDown _numCap = new() { Minimum = 1, Maximum = 100000, Value = 8, Width = 70, Enabled = false };
    private readonly CheckBox _chkKeep = new() { Text = "Keep files", AutoSize = true };

    private readonly Button _btnStart = new() { Text = "Start Test", Width = 100 };
    private readonly Button _btnCancel = new() { Text = "Cancel", Width = 80, Enabled = false };
    private readonly Button _btnSave = new() { Text = "Save Report", Width = 100, Enabled = false };
    private readonly ComboBox _cboFormat = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 118 };

    // drive tools panel (the red box)
    private readonly Button _btnBench = new() { Text = "Benchmark", Dock = DockStyle.Fill, Height = 30 };
    private readonly Button _btnTrim = new() { Text = "Optimize (TRIM)", Dock = DockStyle.Fill, Height = 30 };
    private readonly Button _btnCap = new() { Text = "Cap to real size", Dock = DockStyle.Fill, Height = 30 };
    private readonly Button _btnWipe = new() { Text = "Secure wipe", Dock = DockStyle.Fill, Height = 30, ForeColor = Color.OrangeRed };

    private readonly SegmentBar _seg = new() { Dock = DockStyle.Top, Height = 26 };
    private readonly Label _lblStatus = new() { Dock = DockStyle.Top, Height = 20, Padding = new Padding(4, 2, 4, 2) };
    private readonly BlockMap _map = new() { Dock = DockStyle.Left, Width = 380 };
    private readonly LineGraph _graph = new() { Dock = DockStyle.Fill };
    private readonly RichTextBox _txt = new()
    {
        Multiline = true,
        ReadOnly = true,
        Dock = DockStyle.Fill,
        ScrollBars = RichTextBoxScrollBars.Vertical,   // auto-hides until content overflows
        WordWrap = true,
        Font = new Font(FontFamily.GenericMonospace, 9f),
        BackColor = Color.FromArgb(24, 24, 28),
        ForeColor = Color.Gainsboro,
        BorderStyle = BorderStyle.None
    };

    private readonly System.Windows.Forms.Timer _repaint = new() { Interval = 120 };
    private CancellationTokenSource? _cts;
    private byte[]? _states;
    private string _sysRoot = "";
    private int _sysDisk = -1;
    private Icon? _appIcon;
    private long _lastRealBytes;
    private TestResult? _lastFs;
    private RawResult? _lastRaw;
    private DriveMeta? _lastMeta;
    private string _exDrive = "";
    private DateTime _exWhen = DateTime.Now;

    public MainForm()
    {
        Text = "D8 Flash Tester v2.7  -  Digital8Dreamz" + (Program.IsElevated() ? "  (admin)" : "");
        MinimumSize = new Size(820, 700);
        Size = new Size(940, 780);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(38, 38, 44);
        ForeColor = Color.Gainsboro;
        LoadAppIcon();

        try { _sysRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? ""; } catch { }
        if (Program.IsElevated() && _sysRoot.Length >= 1) _sysDisk = Native.VolumeToDiskNumber(_sysRoot.Substring(0, 1));

        BuildLayout();

        _btnRefresh.Click += (_, _) => LoadDrives();
        _btnFormat.Click += async (_, _) => await FormatAsync();
        _cboDrive.SelectedIndexChanged += (_, _) => UpdateInfo();
        _rbQuick.CheckedChanged += (_, _) => _numCap.Enabled = _rbQuick.Checked && _rbFs.Checked;
        _rbFs.CheckedChanged += (_, _) => ModeChanged();
        _rbRaw.CheckedChanged += (_, _) => ModeChanged();
        _btnStart.Click += async (_, _) => await StartAsync();
        _btnCancel.Click += (_, _) => _cts?.Cancel();
        _btnSave.Click += (_, _) => SaveReport();
        _btnBench.Click += async (_, _) => await BenchAsync();
        _btnTrim.Click += async (_, _) => await TrimAsync();
        _btnCap.Click += async (_, _) => await CapAsync();
        _btnWipe.Click += async (_, _) => await WipeAsync();
        _repaint.Tick += (_, _) => { _map.States = _states; _map.Invalidate(); _graph.Invalidate(); };
        _repaint.Start();

        _seg.SetPhases("Write", "Verify");
        _cboFormat.Items.AddRange(new object[] { "Text (.txt)", "JSON (.json)", "HTML (.html)", "All three" });
        _cboFormat.SelectedIndex = 0;
        LoadDrives();
        Log("Ready.\r\n" +
            "Fraud test: Filesystem (safe) or RAW (full size, erases).\r\n" +
            "Drive tools (top-right): Benchmark, Optimize (TRIM),\r\n" +
            "Cap-to-real-size (fix a fake), and Secure wipe.\r\n");
    }

    private void LoadAppIcon()
    {
        try
        {
            string? exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe)) { _appIcon = Icon.ExtractAssociatedIcon(exe); if (_appIcon != null) { Icon = _appIcon; return; } }
        }
        catch { }
        try { string s = Path.Combine(AppContext.BaseDirectory, "app.ico"); if (File.Exists(s)) { _appIcon = new Icon(s); Icon = _appIcon; } }
        catch { }
    }

    private void BuildLayout()
    {
        var top = new Panel { Dock = DockStyle.Top, Height = 176, Padding = new Padding(8) };

        // right-side tools panel (the red box)
        var tools = new Panel { Dock = DockStyle.Right, Width = 300, Padding = new Padding(8, 0, 0, 0) };
        var toolsInner = new Panel { Dock = DockStyle.Fill, BorderStyle = BorderStyle.FixedSingle, Padding = new Padding(8) };
        var toolsTitle = new Label { Dock = DockStyle.Top, Height = 20, Text = "Drive tools", ForeColor = Color.Gainsboro };
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        grid.Controls.Add(_btnBench, 0, 0);
        grid.Controls.Add(_btnTrim, 1, 0);
        grid.Controls.Add(_btnCap, 0, 1);
        grid.Controls.Add(_btnWipe, 1, 1);
        toolsInner.Controls.Add(grid);
        toolsInner.Controls.Add(toolsTitle);
        tools.Controls.Add(toolsInner);

        // left-side controls
        var left = new Panel { Dock = DockStyle.Fill };
        var rowDrive = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, WrapContents = false };
        rowDrive.Controls.Add(new Label { Text = "Drive:", AutoSize = true, Padding = new Padding(0, 6, 6, 0) });
        rowDrive.Controls.Add(_cboDrive); rowDrive.Controls.Add(_btnRefresh); rowDrive.Controls.Add(_btnFormat);
        var rowMode = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 28, WrapContents = false };
        rowMode.Controls.Add(_rbFs); rowMode.Controls.Add(_rbRaw);
        var rowOpt = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 28, WrapContents = false };
        rowOpt.Controls.Add(_rbFull); rowOpt.Controls.Add(_rbQuick); rowOpt.Controls.Add(_numCap); rowOpt.Controls.Add(_chkKeep);
        var rowBtns = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, WrapContents = false };
        rowBtns.Controls.Add(_btnStart); rowBtns.Controls.Add(_btnCancel); rowBtns.Controls.Add(_btnSave); rowBtns.Controls.Add(_cboFormat);
        left.Controls.Add(_lblInfo); left.Controls.Add(rowBtns); left.Controls.Add(rowOpt); left.Controls.Add(rowMode); left.Controls.Add(rowDrive);

        top.Controls.Add(left);
        top.Controls.Add(tools);

        // middle: seg + status + (blockmap | graph) + legend
        var mid = new Panel { Dock = DockStyle.Top, Height = 210, Padding = new Padding(8, 0, 8, 4) };
        var legend = new Label { Dock = DockStyle.Bottom, Height = 18, Text = "map: gray=untested  blue=written  green=verified  red=ERROR    |    graph: throughput MB/s" };
        var fill = new Panel { Dock = DockStyle.Fill };
        fill.Controls.Add(_graph);
        fill.Controls.Add(_map);
        mid.Controls.Add(fill);
        mid.Controls.Add(_lblStatus);
        mid.Controls.Add(_seg);
        mid.Controls.Add(legend);

        var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };
        host.Controls.Add(_txt);

        Controls.Add(host);
        Controls.Add(mid);
        Controls.Add(top);
    }

    private void ModeChanged()
    {
        bool fs = _rbFs.Checked;
        _rbFull.Enabled = _rbQuick.Enabled = fs;
        _numCap.Enabled = fs && _rbQuick.Checked;
        _chkKeep.Enabled = fs;
        _seg.SetPhases(fs ? new[] { "Write", "Verify" } : new[] { "Write", "Verify", "Pinpoint" });
        UpdateInfo();
    }

    private sealed class DriveItem
    {
        public DriveInfo? Info;          // null for a raw physical disk with no partition
        public int PhysicalDisk = -1;    // set only for raw-no-partition entries
        public bool NeedsFormat;         // lettered but not mounted (RAW filesystem)
        public bool RawNoPartition;      // physical disk with no usable partition
        public long Size;
        public required string Display;
        public override string ToString() => Display;
    }

    private void LoadDrives()
    {
        _cboDrive.Items.Clear();
        var disksWithVolumes = new HashSet<int>();

        foreach (var di in DriveInfo.GetDrives())
        {
            string root = di.RootDirectory.FullName;
            string letter = root.Length >= 1 ? root.Substring(0, 1) : "";
            // remember which physical disks already own a lettered volume (ready or raw)
            if (letter.Length == 1)
            {
                int dn = Native.VolumeToDiskNumber(letter);
                if (dn >= 0) disksWithVolumes.Add(dn);
            }

            if (di.IsReady)
            {
                bool sys = string.Equals(root, _sysRoot, StringComparison.OrdinalIgnoreCase);
                string label; try { label = string.IsNullOrWhiteSpace(di.VolumeLabel) ? "(no label)" : di.VolumeLabel; } catch { label = "(?)"; }
                string disp = $"{root.TrimEnd('\\')}  {label}  [{di.DriveType}]  {Fmt.Bytes(di.TotalSize)}" + (sys ? "  *** SYSTEM ***" : "");
                _cboDrive.Items.Add(new DriveItem { Info = di, Display = disp });
            }
            else if (di.DriveType is DriveType.Removable or DriveType.Fixed)
            {
                // lettered but not mounted -> raw filesystem, needs formatting
                _cboDrive.Items.Add(new DriveItem { Info = di, NeedsFormat = true,
                    Display = $"{root.TrimEnd('\\')}  *** NEEDS FORMAT (raw) ***" });
            }
        }

        // raw USB disks with NO partition at all (e.g. right after diskpart 'clean') - needs admin to see
        if (Program.IsElevated())
        {
            for (int n = 0; n < 16; n++)
            {
                if (n == _sysDisk || disksWithVolumes.Contains(n)) continue;
                string phys = $"\\\\.\\PhysicalDrive{n}";
                using var h = RawIo.OpenDiskRead(phys);
                if (h.IsInvalid) continue;
                long size = Native.DiskLength(h);
                if (size <= 0) continue;
                string model = Native.DeviceModel(h, out bool isUsb);
                if (!isUsb) continue; // only offer to format removable USB disks with no partition
                _cboDrive.Items.Add(new DriveItem
                {
                    PhysicalDisk = n, RawNoPartition = true, Size = size,
                    Display = $"PhysicalDrive{n}  {model}  {Fmt.Bytes(size)}  *** RAW - no partition ***"
                });
            }
        }

        if (_cboDrive.Items.Count > 0) _cboDrive.SelectedIndex = 0;
        UpdateInfo();
    }

    private DriveItem? SelectedItem() => _cboDrive.SelectedItem as DriveItem;
    private DriveInfo? SelectedDrive()
    {
        var it = SelectedItem();
        return (it != null && it.Info != null && it.Info.IsReady) ? it.Info : null;
    }

    private void UpdateInfo()
    {
        var it = SelectedItem();
        if (it == null) { _lblInfo.Text = ""; return; }

        if (it.RawNoPartition)
        {
            _lblInfo.ForeColor = Color.Orange;
            _lblInfo.Text = $"Raw disk: PhysicalDrive{it.PhysicalDisk}   Size: {Fmt.Bytes(it.Size)}\r\nNo partition yet - click Format to make it usable, then test.";
            return;
        }
        if (it.NeedsFormat || it.Info == null || !it.Info.IsReady)
        {
            _lblInfo.ForeColor = Color.Orange;
            string r = it.Info?.RootDirectory.FullName.TrimEnd('\\') ?? "(drive)";
            _lblInfo.Text = $"{r} is unformatted (raw filesystem).\r\nClick Format to make it usable, then run a test.";
            return;
        }

        var di = it.Info;
        bool sys = string.Equals(di.RootDirectory.FullName, _sysRoot, StringComparison.OrdinalIgnoreCase);
        int sector = Native.FsSectorSize(di.RootDirectory.FullName);
        string mode = _rbRaw.Checked ? "RAW: erases the whole physical disk this letter lives on." : "Filesystem: tests free space only.";
        _lblInfo.ForeColor = sys ? Color.OrangeRed : (_rbRaw.Checked ? Color.Orange : Color.Gainsboro);
        _lblInfo.Text = $"Claimed: {Fmt.Bytes(di.TotalSize)}   Free: {Fmt.Bytes(di.AvailableFreeSpace)}   Sector: {sector} B\r\n" +
                        (sys ? "SYSTEM drive - fraud test blocked (tools still allowed where safe)." : mode);
    }

    // returns true and shows a message if the selected drive has no usable (mounted) filesystem
    private bool RequireReady()
    {
        var it = SelectedItem();
        if (it != null && it.Info != null && it.Info.IsReady) return false;
        MessageBox.Show("This drive isn't formatted yet. Click Format first, then run this.", "Needs formatting",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
        return true;
    }

    // ---- fraud test flows ---------------------------------------------------

    private async Task StartAsync()
    {
        if (RequireReady()) return;
        var di = SelectedDrive();
        if (di == null) { MessageBox.Show("Pick a drive first."); return; }
        if (string.Equals(di.RootDirectory.FullName, _sysRoot, StringComparison.OrdinalIgnoreCase))
        { MessageBox.Show("Refusing to test the system drive.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Stop); return; }
        if (_rbRaw.Checked) await StartRawAsync(di); else await StartFsAsync(di);
    }

    private async Task StartFsAsync(DriveInfo di)
    {
        long cap = _rbQuick.Checked ? (long)_numCap.Value * 1024 * 1024 * 1024 : 0;
        Plan plan = FsTester.BuildPlan(di, cap);
        if (plan.TestBytes <= 0) { MessageBox.Show("No free space to test. Format or free space first."); return; }
        using (var c = new ConfirmFsForm(plan, _appIcon)) if (c.ShowDialog(this) != DialogResult.OK) return;

        _states = new byte[Math.Max(1, plan.TotalBlocks)]; _map.States = _states; _map.Visible = true;
        _graph.ClearGraph();
        _seg.SetPhases("Write", "Verify");
        _cts = new CancellationTokenSource(); SetRunning(true); _txt.Clear();
        Log($"=== Filesystem test @ {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
        Log($"Drive {plan.Root} [{plan.Label}] {plan.Type}/{plan.Format} sector {plan.Sector}B");
        Log($"Claimed {Fmt.Bytes(plan.ClaimedBytes)}, testing {Fmt.Bytes(plan.TestBytes)} of free space.\r\n");
        _exDrive = plan.Root.TrimEnd('\\'); _exWhen = DateTime.Now; _lastRaw = null; _lastFs = null;
        await LoadMetaAsync(Native.VolumeToDiskNumber(plan.Root.Substring(0, 1)));
        var prog = new Progress<Prog>(p => { _seg.Update(p.PhaseIndex, p.PhasePercent); _lblStatus.Text = $"{p.Phase}: {p.Status}  ({p.MBps:0.0} MB/s)"; });
        var res = await Task.Run(() => new FsTester().Run(plan, _states!, _chkKeep.Checked, prog, _cts.Token));
        _map.States = _states; _map.Invalidate();
        FinishBar(res.Cancelled, res.Error != null);
        RenderFs(res);
        EndRun();
    }

    private async Task StartRawAsync(DriveInfo di)
    {
        if (EnsureAdminOrRelaunch()) return;
        string letter = di.RootDirectory.FullName.Substring(0, 1);
        int disk = Native.VolumeToDiskNumber(letter);
        if (disk < 0) { MessageBox.Show("Could not map that drive letter to a physical disk."); return; }
        if (disk == _sysDisk) { MessageBox.Show($"PhysicalDrive{disk} hosts Windows. Refusing.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Stop); return; }
        var vols = VolumesOnDisk(disk);
        using (var c = new ConfirmRawForm(disk, di.TotalSize, "(queried at run time)", vols, _appIcon, "ERASE + TEST", "RAW MODE WRITES SECTORS DIRECTLY."))
            if (c.ShowDialog(this) != DialogResult.OK) return;

        _states = new byte[1000]; _map.States = _states; _map.Visible = true; _graph.ClearGraph();
        _seg.SetPhases("Write", "Verify", "Pinpoint");
        _cts = new CancellationTokenSource(); SetRunning(true); _txt.Clear();
        Log($"=== RAW test @ {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
        Log($"PhysicalDrive{disk} (from {letter}:) dismounting: {(vols.Count == 0 ? "(none)" : string.Join(",", vols))}\r\n");
        _exDrive = $"PhysicalDrive{disk} ({letter}:)"; _exWhen = DateTime.Now; _lastFs = null; _lastRaw = null;
        await LoadMetaAsync(disk);
        string phys = $"\\\\.\\PhysicalDrive{disk}";
        var prog = new Progress<Prog>(p => { _seg.Update(p.PhaseIndex, p.PhasePercent); _lblStatus.Text = $"{p.Phase}: {p.Status}" + (p.MBps > 0 ? $"  ({p.MBps:0.0} MB/s)" : ""); });
        var res = await Task.Run(() => new RawTester().Run(phys, disk, vols, _states!, prog, _cts.Token));
        _map.States = _states; _map.Invalidate();
        FinishBar(res.Cancelled, res.Error != null);
        RenderRaw(res);
        EndRun();
    }

    // ---- drive tool flows ---------------------------------------------------

    private async Task BenchAsync()
    {
        if (RequireReady()) return;
        var di = SelectedDrive();
        if (di == null) { MessageBox.Show("Pick a drive first."); return; }
        _graph.Begin("Benchmark", ("Write", Color.FromArgb(210, 140, 50)), ("Read", Color.FromArgb(70, 190, 90)));
        _map.Visible = false;
        _seg.SetPhases("Write BW", "Read BW");
        _cts = new CancellationTokenSource(); SetRunning(true);
        Log($"=== Benchmark {di.RootDirectory.FullName} @ {DateTime.Now:HH:mm:ss} ===");
        _exDrive = di.RootDirectory.FullName.TrimEnd('\\'); _exWhen = DateTime.Now;
        await LoadMetaAsync(Native.VolumeToDiskNumber(di.RootDirectory.FullName.Substring(0, 1)));
        var prog = new Progress<Prog>(p => { _seg.Update(p.PhaseIndex, p.PhasePercent); _lblStatus.Text = $"{p.Phase}: {p.Status}  ({p.MBps:0.0} MB/s)"; });
        string root = di.RootDirectory.FullName;
        var res = await Task.Run(() => Tools.Benchmark(root, 0, 1, _graph.Data.Length > 0 ? _graph.Data[0] : null, _graph.Data.Length > 1 ? _graph.Data[1] : null, _graph.Gate, prog, _cts.Token));
        FinishBar(res.Cancelled, res.Error != null);
        Log("");
        if (res.Error != null) Log("ERROR: " + res.Error);
        else if (res.Cancelled) Log("Cancelled.");
        else
        {
            Log($"Write : avg {res.WriteAvg:0.0} MB/s  peak {res.WritePeak:0.0} MB/s");
            Log($"Read  : avg {res.ReadAvg:0.0} MB/s  peak {res.ReadPeak:0.0} MB/s");
            Log($"(tested {Fmt.Bytes(res.Bytes)}, non-destructive)");
        }
        EndRun();
    }

    private async Task TrimAsync()
    {
        if (RequireReady()) return;
        var di = SelectedDrive();
        if (di == null) { MessageBox.Show("Pick a drive first."); return; }
        if (di.DriveType == DriveType.Removable)
        {
            var ans = MessageBox.Show(
                "This looks like a USB flash drive or SD card.\r\n\r\n" +
                "These almost never support TRIM - it will most likely do nothing, or report \"not supported.\" " +
                "TRIM is meant for internal SSDs.\r\n\r\nTry anyway?",
                "TRIM may not be supported", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (ans != DialogResult.Yes) return;
        }
        if (EnsureAdminOrRelaunch()) return;
        string letter = di.RootDirectory.FullName.Substring(0, 1);
        string root = di.RootDirectory.FullName;

        _graph.Begin("Write MB/s: before vs after TRIM", ("Before", Color.FromArgb(120, 120, 130)), ("After", Color.FromArgb(70, 190, 90)));
        _map.Visible = false;
        _seg.SetPhases("Bench before", "TRIM", "Bench after");
        _cts = new CancellationTokenSource(); SetRunning(true);
        Log($"=== Optimize (TRIM) {root} @ {DateTime.Now:HH:mm:ss} ===");
        var prog = new Progress<Prog>(p => { _seg.Update(p.PhaseIndex, p.PhasePercent); _lblStatus.Text = $"{p.Phase}: {p.Status}" + (p.MBps > 0 ? $"  ({p.MBps:0.0} MB/s)" : ""); });

        BenchResult? before = null, after = null;
        OpResult? trim = null;
        await Task.Run(() =>
        {
            before = Tools.Benchmark(root, 0, 0, _graph.Data[0], null, _graph.Gate, prog, _cts!.Token);
            if (before.Cancelled || before.Error != null) return;
            trim = Tools.Trim(letter, 1, prog, _cts.Token);
            if (trim.Cancelled || !trim.Ok) return;
            after = Tools.Benchmark(root, 2, 2, _graph.Data[1], null, _graph.Gate, prog, _cts.Token);
        });

        bool cancelled = (before?.Cancelled ?? false) || (trim?.Cancelled ?? false) || (after?.Cancelled ?? false);
        bool hardError = before?.Error != null || after?.Error != null;
        bool trimFailed = trim != null && !trim.Ok && !(trim.Cancelled);

        if (cancelled) { _seg.MarkStopped(false); _lblStatus.Text = "Cancelled."; }
        else if (hardError) { _seg.MarkStopped(true); _lblStatus.Text = "Stopped on error."; }
        else if (trimFailed) { _seg.MarkStopped(false); _lblStatus.Text = "TRIM not supported / skipped."; }
        else { _seg.CompleteAll(); _lblStatus.Text = "Done."; }

        Log("");
        if (before != null && before.Error == null && !before.Cancelled)
            Log($"Before : write {before.WriteAvg:0.0} MB/s   read {before.ReadAvg:0.0} MB/s");

        if (cancelled) Log("Cancelled.");
        else if (before?.Error != null) Log("ERROR (benchmark before): " + before.Error);
        else if (trim != null && trim.Ok)
        {
            if (after != null && after.Error == null)
                Log($"After  : write {after.WriteAvg:0.0} MB/s   read {after.ReadAvg:0.0} MB/s");
            else if (after?.Error != null)
                Log("ERROR (benchmark after): " + after.Error);
            Log("TRIM: complete. (Flash-safe optimize - retrim only, never a defrag.)");
        }
        else if (trim != null)
        {
            Log("TRIM did not run: " + (trim.Error ?? "failed."));
            string extra = trim.Log?.Trim() ?? "";
            if (extra.Length > 0) Log(extra);
            Log("USB flash sticks usually can't be TRIMmed - that's expected, not a fault of the drive.");
        }
        EndRun();
    }

    private async Task CapAsync()
    {
        if (RequireReady()) return;
        var di = SelectedDrive();
        if (di == null) { MessageBox.Show("Pick a drive first."); return; }
        if (EnsureAdminOrRelaunch()) return;
        string letter = di.RootDirectory.FullName.Substring(0, 1);
        int disk = Native.VolumeToDiskNumber(letter);
        if (disk < 0) { MessageBox.Show("Could not map that drive letter to a physical disk."); return; }
        if (disk == _sysDisk) { MessageBox.Show($"PhysicalDrive{disk} hosts Windows. Refusing.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Stop); return; }

        long realBytes = _lastRealBytes;
        if (realBytes <= 0)
        {
            using var inp = new InputForm("No measured real size yet (run a RAW test first).\r\nEnter the real size in MB to cap to:", "124", _appIcon);
            if (inp.ShowDialog(this) != DialogResult.OK) return;
            if (!long.TryParse(inp.Value, out long mb) || mb <= 0) { MessageBox.Show("Invalid size."); return; }
            realBytes = mb * 1024 * 1024;
        }

        var vols = VolumesOnDisk(disk);
        using (var c = new ConfirmRawForm(disk, di.TotalSize, $"cap to ~{Fmt.Bytes(realBytes)}", vols, _appIcon, "REPARTITION", "REPARTITION TO REAL SIZE."))
            if (c.ShowDialog(this) != DialogResult.OK) return;

        _seg.SetPhases("Repartition"); _seg.Update(0, 5); _graph.ClearGraph(); _map.Visible = false;
        _cts = new CancellationTokenSource(); SetRunning(true);
        Log($"=== Cap PhysicalDrive{disk} to ~{Fmt.Bytes(realBytes)} @ {DateTime.Now:HH:mm:ss} ===");
        long rb = realBytes;
        var res = await Task.Run(() => Tools.CapToReal(disk, rb));
        _seg.Update(0, 100);
        FinishBar(false, !res.Ok);
        Log("");
        if (res.Ok) { Log(res.Log.Trim()); Log("Done. Verify by copying a file and reading it back."); }
        else Log("ERROR: " + (res.Error ?? "cap failed") + "\r\n" + res.Log.Trim());
        EndRun();
    }

    private async Task WipeAsync()
    {
        if (RequireReady()) return;
        var di = SelectedDrive();
        if (di == null) { MessageBox.Show("Pick a drive first."); return; }
        if (EnsureAdminOrRelaunch()) return;
        string letter = di.RootDirectory.FullName.Substring(0, 1);
        int disk = Native.VolumeToDiskNumber(letter);
        if (disk < 0) { MessageBox.Show("Could not map that drive letter to a physical disk."); return; }
        if (disk == _sysDisk) { MessageBox.Show($"PhysicalDrive{disk} hosts Windows. Refusing.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Stop); return; }

        var vols = VolumesOnDisk(disk);
        using (var c = new ConfirmRawForm(disk, di.TotalSize, "(queried at run time)", vols, _appIcon, "ZERO-FILL", "SECURE WIPE: ZERO-FILL THE ENTIRE DISK."))
            if (c.ShowDialog(this) != DialogResult.OK) return;

        _states = new byte[1]; _graph.ClearGraph(); _map.Visible = false;
        _seg.SetPhases("Zero-fill");
        _cts = new CancellationTokenSource(); SetRunning(true);
        Log($"=== Secure wipe PhysicalDrive{disk} @ {DateTime.Now:HH:mm:ss} ===");
        string phys = $"\\\\.\\PhysicalDrive{disk}";
        var prog = new Progress<Prog>(p => { _seg.Update(p.PhaseIndex, p.PhasePercent); _lblStatus.Text = $"{p.Phase}: {p.Status}  ({p.MBps:0.0} MB/s)"; });
        var res = await Task.Run(() => Tools.Wipe(phys, vols, 0, prog, _cts.Token));
        FinishBar(res.Cancelled, !res.Ok && !res.Cancelled);
        Log("");
        if (res.Ok) { Log(res.Log); Log("Disk is zeroed - reformat before use."); }
        else if (res.Cancelled) Log("Cancelled (partial wipe).");
        else Log("ERROR: " + res.Error);
        EndRun();
    }

    private async Task FormatAsync()
    {
        var it = SelectedItem();
        if (it == null) { MessageBox.Show("Pick a drive first."); return; }
        if (EnsureAdminOrRelaunch()) return;

        int disk; string target; string defLabel;
        if (it.RawNoPartition)
        {
            disk = it.PhysicalDisk;
            if (disk == _sysDisk) { MessageBox.Show($"PhysicalDrive{disk} hosts Windows. Refusing.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Stop); return; }
            target = $"PhysicalDrive{disk} (raw, {Fmt.Bytes(it.Size)})";
            defLabel = "D8-DRIVE";
        }
        else
        {
            if (it.Info == null) { MessageBox.Show("Pick a drive first."); return; }
            string root = it.Info.RootDirectory.FullName;
            if (string.Equals(root, _sysRoot, StringComparison.OrdinalIgnoreCase))
            { MessageBox.Show("Refusing to format the system drive.", "Blocked", MessageBoxButtons.OK, MessageBoxIcon.Stop); return; }
            target = root.TrimEnd('\\');
            try { defLabel = string.IsNullOrWhiteSpace(it.Info.VolumeLabel) ? "D8-DRIVE" : it.Info.VolumeLabel; } catch { defLabel = "D8-DRIVE"; }
        }

        string fs, label;
        using (var f = new FormatForm(target, defLabel, _appIcon))
        {
            if (f.ShowDialog(this) != DialogResult.OK) return;
            fs = f.FileSystem; label = f.Label;
        }
        if (MessageBox.Show($"Format {target} as {fs}?\r\nThis erases everything on it.", "Confirm format",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        _seg.SetPhases("Format"); _seg.Update(0, 5); _graph.ClearGraph(); _map.Visible = false;
        _cts = new CancellationTokenSource(); SetRunning(true);
        Log($"=== Format {target} as {fs} (label '{label}') @ {DateTime.Now:HH:mm:ss} ===");
        bool raw = it.RawNoPartition; int dk = it.RawNoPartition ? it.PhysicalDisk : -1;
        string lt = it.Info?.RootDirectory.FullName.Substring(0, 1) ?? "";
        var res = await Task.Run(() => raw ? Tools.FormatRawDisk(dk, fs, label) : Tools.FormatVolume(lt, fs, label));
        _seg.Update(0, 100);
        if (res.Ok)
        {
            _seg.CompleteAll(); _lblStatus.Text = "Formatted.";
            Log(""); Log("Format OK - drive is ready to test."); if (!string.IsNullOrWhiteSpace(res.Log)) Log(res.Log.Trim());
        }
        else
        {
            _seg.MarkStopped(true); _lblStatus.Text = "Format failed.";
            Log(""); Log("ERROR: " + (res.Error ?? "format failed"));
            if (!string.IsNullOrWhiteSpace(res.Log)) Log(res.Log.Trim());
            Log("If formatting keeps failing on this stick, its flash is likely worn out - retire it.");
        }
        EndRun();
        LoadDrives();
    }

    // ---- helpers ------------------------------------------------------------

    private async Task LoadMetaAsync(int disk)
    {
        _lastMeta = null;
        if (disk < 0) return;
        var m = await Task.Run(() => UsbMeta.Query(disk));
        _lastMeta = m;
        if (m != null) LogMeta(m);
    }

    private void LogMeta(DriveMeta m)
    {
        string model = string.IsNullOrWhiteSpace(m.Model) ? "(unknown)" : m.Model;
        string busTag = !string.IsNullOrWhiteSpace(m.BusType) ? m.BusType : m.Interface;
        Log($"Device        : {model}" + (string.IsNullOrWhiteSpace(busTag) ? "" : $"  [{busTag}]"));
        if (m.IsBridge)
            Log("                (USB bridge/adapter - the enclosure, not necessarily the drive inside)");
        if (m.Unmasked)
        {
            Log($"REAL DRIVE    : {m.AtaModel}  (unmasked via ATA IDENTIFY)");
            if (!string.IsNullOrWhiteSpace(m.AtaSerial)) Log($"Drive serial  : {m.AtaSerial}");
            if (!string.IsNullOrWhiteSpace(m.AtaFirmware)) Log($"Firmware      : {m.AtaFirmware}");
        }
        if (!string.IsNullOrWhiteSpace(m.FriendlyName) &&
            !m.FriendlyName.Equals(m.Model, StringComparison.OrdinalIgnoreCase))
            Log($"Reported drive: {m.FriendlyName}");
        if (!string.IsNullOrWhiteSpace(m.MediaType)) Log($"Media type    : {m.MediaType}");
        if (!string.IsNullOrWhiteSpace(m.Vid))
            Log($"USB ID        : VID {m.Vid}  PID {m.Pid}" + (string.IsNullOrWhiteSpace(m.Vendor) ? "" : $"  ({m.Vendor})"));
        if (!string.IsNullOrWhiteSpace(m.Serial)) Log($"Serial        : {m.Serial}");
        if (!string.IsNullOrWhiteSpace(m.Mismatch)) Log($"NOTE          : {m.Mismatch}");
        Log("");
    }

    private List<string> VolumesOnDisk(int disk)
    {
        var vols = new List<string>();
        foreach (var d in DriveInfo.GetDrives())
        {
            if (!d.IsReady) continue;
            string l = d.RootDirectory.FullName.Substring(0, 1);
            if (Native.VolumeToDiskNumber(l) == disk) vols.Add(l);
        }
        return vols;
    }

    // returns true if the caller should stop (relaunching, or user declined)
    private bool EnsureAdminOrRelaunch()
    {
        if (Program.IsElevated()) return false;
        if (MessageBox.Show("This needs administrator rights. Relaunch elevated now?", "Elevation required",
            MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return true;
        try { Process.Start(new ProcessStartInfo { FileName = Environment.ProcessPath, UseShellExecute = true, Verb = "runas" }); Application.Exit(); }
        catch (Exception ex) { MessageBox.Show("Could not elevate: " + ex.Message); }
        return true;
    }

    private void EndRun()
    {
        SetRunning(false);
        _cts?.Dispose();
        _cts = null;
        if (_txt.TextLength > 0) _btnSave.Enabled = true;   // report is saveable after any run (test or tool)
    }

    private void FinishBar(bool cancelled, bool errored)
    {
        if (cancelled || errored) { _seg.MarkStopped(errored); _lblStatus.Text = cancelled ? "Cancelled." : "Stopped on error."; }
        else { _seg.CompleteAll(); _lblStatus.Text = "Done."; }
    }

    private void RenderFs(TestResult r)
    {
        _lastFs = r; _lastRaw = null;
        Log("");
        if (r.Error != null) { Log("ERROR: " + r.Error); _btnSave.Enabled = true; return; }
        if (r.Cancelled) Log("Cancelled. Partial results:");
        var p = r.Plan!;
        Log("----------------------------------------");
        Log($"Written        : {Fmt.Bytes(r.WrittenBytes)}");
        Log($"Verified good  : {Fmt.Bytes(r.VerifiedGoodBytes)}");
        Log($"Write speed    : {r.WriteMBps:0.0} MB/s");
        Log($"Read speed     : {r.ReadMBps:0.0} MB/s");
        if (r.WrittenBytes < p.TestBytes && r.FirstFailOffset < 0)
            Log($"NOTE: drive refused writes after {Fmt.Bytes(r.WrittenBytes)} (claimed free {Fmt.Bytes(p.FreeBytes)}).");
        Log("----------------------------------------");
        if (r.FirstFailOffset < 0 && r.Completed)
        {
            Log($"RESULT: no errors across {Fmt.Bytes(r.VerifiedGoodBytes)} tested.");
            Log(_rbQuick.Checked ? $"VERDICT: PASSED within the {Fmt.Bytes(p.TestBytes)} cap (a larger fake is not ruled out)."
                                 : "VERDICT: GENUINE within tested free space (format + full for absolute certainty).");
        }
        else if (r.FirstFailOffset >= 0)
        {
            _lastRealBytes = r.FirstFailOffset;
            Log($"First error    : {Fmt.Bytes(r.FirstFailOffset)}  ({(r.FailLooksZero ? "zeros / void" : "mismatch / wrap")})");
            Log($"Estimated real : ~{Fmt.Bytes(r.FirstFailOffset)}");
            Log($"VERDICT: FAKE / FAILING.  Claimed {Fmt.Bytes(p.ClaimedBytes)}, real ~{Fmt.Bytes(r.FirstFailOffset)}.");
            Log("Tip: 'Cap to real size' will fix this drive to its true capacity.");
        }
        Log("----------------------------------------");
        _btnSave.Enabled = true;
    }

    private void RenderRaw(RawResult r)
    {
        _lastRaw = r; _lastFs = null;
        Log("");
        if (r.Error != null) { Log("ERROR: " + r.Error); _btnSave.Enabled = true; return; }
        if (r.Cancelled) Log("Cancelled. Partial results:");
        Log("----------------------------------------");
        Log($"Device         : {r.Model}");
        Log($"Sector         : {r.Sector} B     Probes: {r.Probes}");
        Log($"Claimed        : {Fmt.Bytes(r.ClaimedBytes)}");
        Log($"Write speed    : {r.WriteMBps:0.0} MB/s");
        Log($"Read speed     : {r.ReadMBps:0.0} MB/s");
        if (r.FirstFailOffset >= 0) Log($"First error    : {Fmt.Bytes(r.FirstFailOffset)}   last good end: {Fmt.Bytes(r.LastGoodEnd)}");
        Log("----------------------------------------");
        switch (r.Verdict)
        {
            case RawVerdict.Genuine:
                Log($"VERDICT: GENUINE. Full claimed {Fmt.Bytes(r.ClaimedBytes)} verified at all sample points."); break;
            case RawVerdict.Void:
                Log("VERDICT: FAKE (capacity void / zeros past the real chip).");
                Log($"   Claimed : {Fmt.Bytes(r.ClaimedBytes)}");
                Log($"   Real    : ~{Fmt.Bytes(r.RealBytes)} usable"); break;
            case RawVerdict.Wrap:
                Log("VERDICT: FAKE (writes wrap over earlier data).");
                Log($"   Claimed : {Fmt.Bytes(r.ClaimedBytes)}");
                Log($"   Real    : ~{Fmt.Bytes(r.RealBytes)} (exact wrap stride)"); break;
            case RawVerdict.Corruption:
                Log("VERDICT: FAKE / FAILING (corrupted reads past the real chip).");
                Log($"   Real    : ~{Fmt.Bytes(r.RealBytes)}"); break;
            case RawVerdict.WriteRefused:
                Log("VERDICT: FAKE / FAILING - refused writes before its claimed end.");
                Log($"   Refused at: {Fmt.Bytes(r.FirstFailOffset)}"); break;
            default:
                Log("VERDICT: inconclusive."); break;
        }
        if (r.RealBytes > 0) _lastRealBytes = r.RealBytes;
        if (!string.IsNullOrEmpty(r.Detail)) Log(r.Detail);
        if (r.ClaimedBytes > 0 && r.RealBytes > 0 && r.RealBytes < r.ClaimedBytes)
            Log($"Overstated by  : {(double)r.ClaimedBytes / r.RealBytes:0.#}x");
        if (r.Verdict is RawVerdict.Void or RawVerdict.Wrap or RawVerdict.Corruption)
            Log("Tip: 'Cap to real size' will repartition this to its true capacity.");
        Log("NOTE: the disk's partition table was erased - reformat before use.");
        Log("----------------------------------------");
        _btnSave.Enabled = true;
    }

    private void SaveReport()
    {
        int sel = _cboFormat.SelectedIndex; // 0=txt 1=json 2=html 3=all
        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

        if (sel == 3)
        {
            using var sfd = new SaveFileDialog { Filter = "All formats (base name)|*.*", FileName = $"D8FlashTest_{stamp}" };
            if (sfd.ShowDialog(this) != DialogResult.OK) return;
            string dir = Path.GetDirectoryName(sfd.FileName) ?? ".";
            string bas = Path.Combine(dir, Path.GetFileNameWithoutExtension(sfd.FileName));
            try
            {
                File.WriteAllText(bas + ".txt", _txt.Text);
                File.WriteAllText(bas + ".json", BuildJson());
                File.WriteAllText(bas + ".html", BuildHtml());
                MessageBox.Show("Saved .txt, .json and .html.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show("Save failed: " + ex.Message); }
            return;
        }

        string ext; string filter; Func<string> gen;
        if (sel == 1) { ext = "json"; filter = "JSON (*.json)|*.json"; gen = BuildJson; }
        else if (sel == 2) { ext = "html"; filter = "HTML (*.html)|*.html"; gen = BuildHtml; }
        else { ext = "txt"; filter = "Text (*.txt)|*.txt"; gen = () => _txt.Text; }
        using var sfd2 = new SaveFileDialog { Filter = filter, FileName = $"D8FlashTest_{stamp}.{ext}" };
        if (sfd2.ShowDialog(this) != DialogResult.OK) return;
        try { File.WriteAllText(sfd2.FileName, gen()); }
        catch (Exception ex) { MessageBox.Show("Save failed: " + ex.Message); }
    }

    private static string? SnapPng64(Control c)
    {
        if (c.Width <= 0 || c.Height <= 0) return null;
        try
        {
            using var bmp = new Bitmap(c.Width, c.Height);
            c.DrawToBitmap(bmp, new Rectangle(0, 0, c.Width, c.Height));
            using var ms = new MemoryStream();
            bmp.Save(ms, ImageFormat.Png);
            return Convert.ToBase64String(ms.ToArray());
        }
        catch { return null; }
    }

    private string BuildJson()
    {
        var d = new Dictionary<string, object?>
        {
            ["tool"] = "D8 Flash Tester",
            ["version"] = "2.7",
            ["timestamp"] = _exWhen.ToString("o"),
            ["drive"] = _exDrive,
        };
        if (_lastFs is TestResult fs && fs.Plan is Plan p)
        {
            bool fake = fs.FirstFailOffset >= 0;
            d["mode"] = "filesystem";
            d["claimedBytes"] = p.ClaimedBytes;
            d["freeBytes"] = p.FreeBytes;
            d["sectorBytes"] = p.Sector;
            d["testedBytes"] = fs.WrittenBytes;
            d["verifiedGoodBytes"] = fs.VerifiedGoodBytes;
            d["firstFailOffset"] = fs.FirstFailOffset;
            d["writeMBps"] = Math.Round(fs.WriteMBps, 2);
            d["readMBps"] = Math.Round(fs.ReadMBps, 2);
            d["verdict"] = fake ? "fake_or_failing" : (fs.Completed ? "genuine_within_tested" : "incomplete");
            if (fake)
            {
                d["realBytesEstimate"] = fs.FirstFailOffset;
                if (fs.FirstFailOffset > 0) d["overstatementRatio"] = Math.Round((double)p.ClaimedBytes / fs.FirstFailOffset, 1);
                d["failLooksZero"] = fs.FailLooksZero;
            }
        }
        else if (_lastRaw is RawResult rr)
        {
            d["mode"] = "raw";
            d["model"] = rr.Model;
            d["sectorBytes"] = rr.Sector;
            d["probes"] = rr.Probes;
            d["pinpointSteps"] = rr.PinpointSteps;
            d["claimedBytes"] = rr.ClaimedBytes;
            d["realBytes"] = rr.RealBytes;
            d["firstFailOffset"] = rr.FirstFailOffset;
            d["writeMBps"] = Math.Round(rr.WriteMBps, 2);
            d["readMBps"] = Math.Round(rr.ReadMBps, 2);
            d["verdict"] = rr.Verdict.ToString().ToLowerInvariant();
            d["detail"] = rr.Detail;
            if (rr.ClaimedBytes > 0 && rr.RealBytes > 0 && rr.RealBytes < rr.ClaimedBytes)
                d["overstatementRatio"] = Math.Round((double)rr.ClaimedBytes / rr.RealBytes, 1);
        }
        else
        {
            d["mode"] = "log";
        }
        if (_lastMeta is DriveMeta meta)
        {
            d["metadata"] = new Dictionary<string, object?>
            {
                ["model"] = meta.Model,
                ["isUsbBridge"] = meta.IsBridge,
                ["unmaskedRealDrive"] = meta.Unmasked ? meta.AtaModel : "",
                ["unmaskedSerial"] = meta.Unmasked ? meta.AtaSerial : "",
                ["unmaskedFirmware"] = meta.Unmasked ? meta.AtaFirmware : "",
                ["reportedDrive"] = meta.FriendlyName,
                ["mediaType"] = meta.MediaType,
                ["busType"] = meta.BusType,
                ["manufacturer"] = meta.Manufacturer,
                ["interface"] = meta.Interface,
                ["serial"] = meta.Serial,
                ["vid"] = meta.Vid,
                ["pid"] = meta.Pid,
                ["usbVendor"] = meta.Vendor,
                ["pnpDeviceId"] = meta.Pnp,
                ["note"] = meta.Mismatch
            };
        }
        d["report"] = _txt.Text;
        return JsonSerializer.Serialize(d, new JsonSerializerOptions { WriteIndented = true });
    }

    private string BuildHtml()
    {
        string verdict = "—", vColor = "#8a8a92", subtitle = _exDrive;
        long claimed = 0, real = -1; double? ratio = null;
        var rows = new List<(string, string)>();

        if (_lastFs is TestResult fs && fs.Plan is Plan p)
        {
            bool fake = fs.FirstFailOffset >= 0;
            verdict = fake ? "FAKE / FAILING" : (fs.Completed ? "GENUINE (within tested)" : "INCOMPLETE");
            vColor = fake ? "#dc3c3c" : "#46af5a";
            claimed = p.ClaimedBytes; real = fake ? fs.FirstFailOffset : p.ClaimedBytes;
            if (fake && fs.FirstFailOffset > 0) ratio = (double)p.ClaimedBytes / fs.FirstFailOffset;
            rows.Add(("Mode", "Filesystem (free-space)"));
            rows.Add(("Claimed", Fmt.Bytes(p.ClaimedBytes)));
            rows.Add(("Tested", Fmt.Bytes(fs.WrittenBytes)));
            rows.Add(("Verified good", Fmt.Bytes(fs.VerifiedGoodBytes)));
            if (fake) rows.Add(("First error at", Fmt.Bytes(fs.FirstFailOffset)));
            rows.Add(("Write speed", $"{fs.WriteMBps:0.0} MB/s"));
            rows.Add(("Read speed", $"{fs.ReadMBps:0.0} MB/s"));
        }
        else if (_lastRaw is RawResult rr)
        {
            bool fake = rr.Verdict is RawVerdict.Void or RawVerdict.Wrap or RawVerdict.Corruption or RawVerdict.WriteRefused;
            verdict = rr.Verdict == RawVerdict.Genuine ? "GENUINE" : fake ? "FAKE / FAILING" : rr.Verdict.ToString();
            vColor = rr.Verdict == RawVerdict.Genuine ? "#46af5a" : fake ? "#dc3c3c" : "#d0a03c";
            claimed = rr.ClaimedBytes; real = rr.RealBytes;
            if (rr.ClaimedBytes > 0 && rr.RealBytes > 0 && rr.RealBytes < rr.ClaimedBytes) ratio = (double)rr.ClaimedBytes / rr.RealBytes;
            rows.Add(("Mode", "RAW (full physical)"));
            rows.Add(("Device", rr.Model));
            rows.Add(("Claimed", Fmt.Bytes(rr.ClaimedBytes)));
            if (rr.RealBytes >= 0) rows.Add(("Real usable", Fmt.Bytes(rr.RealBytes)));
            if (rr.FirstFailOffset >= 0) rows.Add(("First error at", Fmt.Bytes(rr.FirstFailOffset)));
            rows.Add(("Write speed", $"{rr.WriteMBps:0.0} MB/s"));
            rows.Add(("Read speed", $"{rr.ReadMBps:0.0} MB/s"));
            if (!string.IsNullOrEmpty(rr.Detail)) rows.Add(("Detail", rr.Detail));
        }
        else
        {
            verdict = "LOG"; vColor = "#8a8a92";
            rows.Add(("Mode", "Tool / log output"));
        }
        if (ratio is double rr2) rows.Add(("Overstated by", $"{rr2:0.#}x"));
        if (_lastMeta is DriveMeta meta)
        {
            if (!string.IsNullOrWhiteSpace(meta.Model))
                rows.Add(("Device", meta.Model + (meta.IsBridge ? "  (USB bridge/adapter - not necessarily the drive inside)" : "")));
            if (meta.Unmasked)
                rows.Add(("Real drive", meta.AtaModel + "  (unmasked via ATA IDENTIFY)" + (string.IsNullOrWhiteSpace(meta.AtaSerial) ? "" : $"  ·  SN {meta.AtaSerial}")));
            if (!string.IsNullOrWhiteSpace(meta.FriendlyName) && !meta.FriendlyName.Equals(meta.Model, StringComparison.OrdinalIgnoreCase))
                rows.Add(("Reported drive", meta.FriendlyName));
            if (!string.IsNullOrWhiteSpace(meta.MediaType)) rows.Add(("Media type", meta.MediaType + (string.IsNullOrWhiteSpace(meta.BusType) ? "" : $" / {meta.BusType}")));
            if (!string.IsNullOrWhiteSpace(meta.Vid)) rows.Add(("USB ID", $"VID {meta.Vid}  PID {meta.Pid}" + (string.IsNullOrWhiteSpace(meta.Vendor) ? "" : $"  ({meta.Vendor})")));
            if (!string.IsNullOrWhiteSpace(meta.Serial)) rows.Add(("Serial", meta.Serial));
            if (!string.IsNullOrWhiteSpace(meta.Mismatch)) rows.Add(("⚠ Note", meta.Mismatch));
        }

        string? mapImg = (_lastFs != null || _lastRaw != null) ? SnapPng64(_map) : null;
        string? graphImg = _graph.HasData ? SnapPng64(_graph) : null;

        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>D8 Flash Tester report</title><style>");
        sb.Append("body{background:#26262c;color:#e6e6e6;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px;}");
        sb.Append(".card{max-width:820px;margin:0 auto;background:#1e1e22;border:1px solid #3a3a42;border-radius:10px;overflow:hidden;}");
        sb.Append(".hd{padding:16px 20px;border-bottom:1px solid #3a3a42;}");
        sb.Append(".hd h1{margin:0;font-size:18px;} .hd .sub{color:#9a9aa2;font-size:13px;margin-top:4px;}");
        sb.Append(".verdict{padding:14px 20px;font-size:22px;font-weight:700;color:#fff;}");
        sb.Append("table{width:100%;border-collapse:collapse;} td{padding:8px 20px;border-top:1px solid #303038;font-size:14px;}");
        sb.Append("td.k{color:#9a9aa2;width:180px;} .imgs{padding:12px 20px;} .imgs img{max-width:100%;border:1px solid #3a3a42;border-radius:6px;margin:8px 0;display:block;}");
        sb.Append(".lbl{color:#9a9aa2;font-size:12px;margin:10px 0 2px;} pre{white-space:pre-wrap;word-wrap:break-word;background:#18181c;color:#d0d0d0;padding:16px 20px;margin:0;border-top:1px solid #3a3a42;font-family:Consolas,monospace;font-size:12px;}");
        sb.Append("</style></head><body><div class=\"card\">");
        sb.Append($"<div class=\"hd\"><h1>D8 Flash Tester — Digital8Dreamz</h1><div class=\"sub\">{WebUtility.HtmlEncode(subtitle)} &middot; {WebUtility.HtmlEncode(_exWhen.ToString("yyyy-MM-dd HH:mm:ss"))}</div></div>");
        sb.Append($"<div class=\"verdict\" style=\"background:{vColor}\">{WebUtility.HtmlEncode(verdict)}</div>");
        sb.Append("<table>");
        foreach (var (k, v) in rows)
            sb.Append($"<tr><td class=\"k\">{WebUtility.HtmlEncode(k)}</td><td>{WebUtility.HtmlEncode(v)}</td></tr>");
        sb.Append("</table>");
        if (mapImg != null || graphImg != null)
        {
            sb.Append("<div class=\"imgs\">");
            if (mapImg != null) { sb.Append("<div class=\"lbl\">Block map (gray=untested, blue=written, green=verified, red=ERROR)</div>"); sb.Append($"<img src=\"data:image/png;base64,{mapImg}\">"); }
            if (graphImg != null) { sb.Append("<div class=\"lbl\">Throughput (MB/s)</div>"); sb.Append($"<img src=\"data:image/png;base64,{graphImg}\">"); }
            sb.Append("</div>");
        }
        sb.Append($"<pre>{WebUtility.HtmlEncode(_txt.Text)}</pre>");
        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    private void SetRunning(bool r)
    {
        _btnStart.Enabled = !r; _btnCancel.Enabled = r; _btnRefresh.Enabled = !r; _cboDrive.Enabled = !r;
        _rbFs.Enabled = _rbRaw.Enabled = !r;
        _rbFull.Enabled = _rbQuick.Enabled = !r && _rbFs.Checked;
        _numCap.Enabled = !r && _rbFs.Checked && _rbQuick.Checked;
        _chkKeep.Enabled = !r && _rbFs.Checked;
        _btnBench.Enabled = _btnTrim.Enabled = _btnCap.Enabled = _btnWipe.Enabled = !r;
        _btnFormat.Enabled = !r;
        if (r) { _btnSave.Enabled = false; _seg.Reset(); _lastFs = null; _lastRaw = null; _lastMeta = null; }
    }

    private void Log(string s) { if (!_txt.IsDisposed) _txt.AppendText(s + "\r\n"); }
    protected override void OnFormClosing(FormClosingEventArgs e) { _cts?.Cancel(); base.OnFormClosing(e); }
}
