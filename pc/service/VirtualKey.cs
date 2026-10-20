using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AuthKey;

/// <summary>
/// Presents the AuthKey-ESP32 to Windows as a standard USB FIDO security key.
///
/// A USB/IP server on 127.0.0.1:3240 emulates a USB HID device with the FIDO
/// usage page; usbip-win2 (a signed driver) attaches it, so Windows / Chrome
/// see a normal "Security key". CTAPHID packets are reassembled here and each
/// CTAP2 request is forwarded to the device over its USB serial console
/// (`ctap &lt;hex&gt;`), where the user approves it as usual.
/// </summary>
public sealed class VirtualKey
{
    const int UsbIpPort = 3240;
    const string BusId = "1-1";
    readonly CancellationTokenSource _stop = new();
    string? _attachedPort;

    public static string DisableFlag => Path.Combine(Config.Dir, "no-virtual-key");

    public void Start()
    {
        if (File.Exists(DisableFlag)) { Log.Write("Virtual key disabled (flag file)"); return; }
        _ = Task.Run(() => ServeAsync(_stop.Token));
        _ = Task.Run(() => AttachLoopAsync(_stop.Token));
    }

    public void Stop()
    {
        _stop.Cancel();
        Detach();
    }

    // --- usbip-win2 attach / detach -----------------------------------------

    public static string? FindUsbIp()
    {
        foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\USBip",
                                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\usbip-win2" })
        {
            var p = Path.Combine(dir, "usbip.exe");
            if (File.Exists(p)) return p;
        }
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
        {
            try { var p = Path.Combine(dir.Trim(), "usbip.exe"); if (File.Exists(p)) return p; } catch { }
        }
        return null;
    }

    static (int code, string output) Run(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
        };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        return (p.ExitCode, output);
    }

    /// <summary>Attach while the ESP32 is plugged in; detach when it goes away.</summary>
    async Task AttachLoopAsync(CancellationToken ct)
    {
        var usbip = FindUsbIp();
        if (usbip == null) { Log.Write("Virtual key: usbip-win2 not installed (usbip.exe not found)"); return; }
        await Task.Delay(1500, ct);   // let the server start
        while (!ct.IsCancellationRequested)
        {
            bool present = UsbTransport.FindPorts().Count > 0;
            if (present && _attachedPort == null)
            {
                var (code, output) = Run(usbip, $"attach -r 127.0.0.1 -b {BusId}");
                var m = System.Text.RegularExpressions.Regex.Match(output, @"port\s+(\d+)");
                if (code == 0)
                {
                    _attachedPort = m.Success ? m.Groups[1].Value : "?";
                    Log.Write($"Virtual key attached (usbip port {_attachedPort})");
                }
                else
                {
                    Log.Write($"Virtual key: attach failed ({code}): {output.Trim()}");
                    await Task.Delay(10000, ct).ContinueWith(_ => { });
                }
            }
            else if (!present && _attachedPort != null)
            {
                Detach();
            }
            await Task.Delay(2000, ct).ContinueWith(_ => { });
        }
    }

    void Detach()
    {
        var usbip = FindUsbIp();
        if (usbip == null || _attachedPort == null) return;
        var args = _attachedPort == "?" ? "detach --all" : $"detach -p {_attachedPort}";
        var (code, output) = Run(usbip, args);
        Log.Write($"Virtual key detached ({code}) {output.Trim()}");
        _attachedPort = null;
    }

    // --- USB/IP server ------------------------------------------------------------

    async Task ServeAsync(CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Loopback, UsbIpPort);
        try { listener.Start(); }
        catch (Exception e) { Log.Write($"Virtual key: cannot listen on {UsbIpPort}: {e.Message}"); return; }
        Log.Write($"Virtual key: USB/IP server on 127.0.0.1:{UsbIpPort}");
        using var reg = ct.Register(listener.Stop);
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct); }
            catch { break; }
            client.NoDelay = true;
            _ = Task.Run(() => new UsbIpConnection(client).RunAsync(ct));
        }
    }
}

/// <summary>One USB/IP client connection (list / import, then URB traffic).</summary>
sealed class UsbIpConnection
{
    const ushort Version = 0x0111;
    readonly TcpClient _client;
    readonly NetworkStream _stream;
    readonly SemaphoreSlim _writeLock = new(1, 1);
    // Windows keeps several interrupt-IN URBs pending. Each report must go to
    // the oldest one, and its RET_SUBMIT must hit the wire before the next
    // report's, or hidclass reassembles CTAPHID packets out of order. So the
    // pairing and the write happen together under this lock.
    readonly object _inLock = new();
    readonly Queue<uint> _pendingIn = new();        // interrupt-IN URB seqnums waiting for data
    readonly Queue<byte[]> _outgoing = new();       // HID reports waiting for an IN URB
    readonly CtapHid _hid;

    public UsbIpConnection(TcpClient client)
    {
        _client = client;
        _stream = client.GetStream();
        _hid = new CtapHid(SendReport);
    }

    async Task<byte[]> ReadExactAsync(int n, CancellationToken ct)
    {
        var buf = new byte[n];
        await _stream.ReadExactlyAsync(buf, ct);
        return buf;
    }

    async Task WriteAsync(byte[] data)
    {
        await _writeLock.WaitAsync();
        try { await _stream.WriteAsync(data); await _stream.FlushAsync(); }
        finally { _writeLock.Release(); }
    }

    void WriteSync(byte[] data)
    {
        _writeLock.Wait();
        try { _stream.Write(data); _stream.Flush(); }
        finally { _writeLock.Release(); }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using (_client)
        {
            try
            {
                // Operation phase: OP_REQ_DEVLIST or OP_REQ_IMPORT.
                var head = await ReadExactAsync(8, ct);
                ushort code = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(2));
                if (code == 0x8005)
                {
                    await WriteAsync(DevList());
                    return;
                }
                if (code != 0x8003) return;
                var busid = Encoding.ASCII.GetString(await ReadExactAsync(32, ct)).TrimEnd('\0');
                if (busid != "1-1")
                {
                    await WriteAsync(OpHeader(0x0003, 1));
                    return;
                }
                await WriteAsync([.. OpHeader(0x0003, 0), .. UsbDevice()]);
                Log.Write("Virtual key: imported by usbip client");
                CtapHid.RefreshInfo();
                await UrbLoopAsync(ct);
            }
            catch (Exception e) when (e is IOException or EndOfStreamException or OperationCanceledException or SocketException)
            {
            }
            catch (Exception e)
            {
                Log.Write($"Virtual key: connection error: {e.Message}");
            }
            finally
            {
                _hid.Dispose();
            }
        }
    }

    static byte[] OpHeader(ushort code, uint status)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(b, Version);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), code);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), status);
        return b;
    }

    static byte[] UsbDevice()
    {
        var b = new byte[312];
        Encoding.ASCII.GetBytes("/sys/devices/authkey/usb1/1-1").CopyTo(b, 0);
        Encoding.ASCII.GetBytes("1-1").CopyTo(b, 256);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(288), 1);    // busnum
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(292), 1);    // devnum
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(296), 2);    // speed: full
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(300), Descriptors.VendorId);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(302), Descriptors.ProductId);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(304), 0x0100);
        b[306] = 0; b[307] = 0; b[308] = 0;     // class per interface
        b[309] = 1;                              // bConfigurationValue
        b[310] = 1;                              // bNumConfigurations
        b[311] = 1;                              // bNumInterfaces
        return b;
    }

    static byte[] DevList()
    {
        var b = new List<byte>(OpHeader(0x0005, 0));
        var n = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(n, 1);
        b.AddRange(n);
        b.AddRange(UsbDevice());
        b.AddRange(new byte[] { 3, 0, 0, 0 });   // interface: HID
        return b.ToArray();
    }

    // --- URB phase ------------------------------------------------------------------

    async Task UrbLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var h = await ReadExactAsync(48, ct);
            uint command = BinaryPrimitives.ReadUInt32BigEndian(h);
            uint seqnum = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(4));
            uint direction = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(12));
            uint ep = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(16));
            if (command == 2)   // CMD_UNLINK
            {
                uint victim = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(20));
                bool removed;
                lock (_inLock)
                {
                    var keep = _pendingIn.Where(s => s != victim).ToList();
                    removed = keep.Count != _pendingIn.Count;
                    _pendingIn.Clear();
                    foreach (var s in keep) _pendingIn.Enqueue(s);
                }
                CtapHid.Verbose($"unlink seq {victim} ({(removed ? "pending IN dropped" : "already completed")})");
                await WriteAsync(RetUnlink(seqnum, removed ? -104 /* -ECONNRESET */ : 0));
                continue;
            }
            if (command != 1) return;   // only CMD_SUBMIT is expected

            int length = BinaryPrimitives.ReadInt32BigEndian(h.AsSpan(24));
            var setup = h.AsSpan(40, 8).ToArray();
            byte[] outData = direction == 0 && length > 0 ? await ReadExactAsync(length, ct) : Array.Empty<byte>();

            if (ep == 0 && setup[0] == 0x21 && setup[1] == 0x09)
            {
                // HID SET_REPORT: an output report sent over the control pipe.
                await WriteAsync(RetSubmit(seqnum, 0, Array.Empty<byte>(), outData.Length));
                CtapHid.Trace($"SET_REPORT {outData.Length} B");
                var pkt = new byte[64];
                Array.Copy(outData, 0, pkt, 0, Math.Min(outData.Length, 64));
                _hid.OnPacket(pkt);
            }
            else if (ep == 0)
            {
                var (status, data) = Descriptors.Control(setup);
                if (status != 0) CtapHid.Trace($"control stall {Convert.ToHexString(setup)}");
                if (data.Length > length) data = data[..length];
                await WriteAsync(RetSubmit(seqnum, status, direction == 1 ? data : Array.Empty<byte>(),
                                           direction == 1 ? data.Length : length));
            }
            else if (direction == 0)   // interrupt OUT: one CTAPHID packet
            {
                await WriteAsync(RetSubmit(seqnum, 0, Array.Empty<byte>(), outData.Length));
                if (outData.Length >= 64) _hid.OnPacket(outData[..64]);
                else CtapHid.Trace($"short OUT packet {outData.Length} B ignored");
            }
            else                       // interrupt IN: wait for a report
            {
                lock (_inLock)
                {
                    if (_outgoing.Count > 0)
                    {
                        var report = _outgoing.Dequeue();
                        WriteSync(RetSubmit(seqnum, 0, report, report.Length));
                    }
                    else _pendingIn.Enqueue(seqnum);
                }
            }
        }
    }

    void SendReport(byte[] report)
    {
        lock (_inLock)
        {
            if (_pendingIn.Count > 0)
            {
                try { WriteSync(RetSubmit(_pendingIn.Dequeue(), 0, report, report.Length)); }
                catch (Exception) { /* connection gone; the URB loop ends on its own */ }
            }
            else
            {
                _outgoing.Enqueue(report);
                if (report[4] != 0xBB) CtapHid.Verbose($"no IN URB pending: report queued ({_outgoing.Count} waiting)");
            }
        }
    }

    static byte[] RetSubmit(uint seqnum, int status, byte[] data, int actual)
    {
        var b = new byte[48 + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(b, 3);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), seqnum);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(20), status);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(24), actual);
        data.CopyTo(b, 48);
        return b;
    }

    static byte[] RetUnlink(uint seqnum, int status)
    {
        var b = new byte[48];
        BinaryPrimitives.WriteUInt32BigEndian(b, 4);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), seqnum);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(20), status);
        return b;
    }
}

/// <summary>USB descriptors for a full-speed FIDO HID device.</summary>
static class Descriptors
{
    public const ushort VendorId = 0x1209;    // pid.codes (open-source hardware)
    public const ushort ProductId = 0xA4B1;

    static readonly byte[] Report =
    {
        0x06, 0xD0, 0xF1,       // Usage Page (FIDO Alliance)
        0x09, 0x01,             // Usage (CTAPHID)
        0xA1, 0x01,             // Collection (Application)
        0x09, 0x20,             //   Usage (Data In)
        0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x81, 0x02,             //   Input (Data, Var, Abs)
        0x09, 0x21,             //   Usage (Data Out)
        0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x91, 0x02,             //   Output (Data, Var, Abs)
        0xC0,                   // End Collection
    };

    static readonly byte[] Device =
    {
        18, 1, 0x00, 0x02, 0, 0, 0, 64,
        VendorId & 0xFF, VendorId >> 8, ProductId & 0xFF, ProductId >> 8,
        0x00, 0x01, 1, 2, 3, 1,
    };

    static byte[] Config()
    {
        byte[] hid = { 9, 0x21, 0x11, 0x01, 0, 1, 0x22, (byte)Report.Length, (byte)(Report.Length >> 8) };
        var b = new List<byte>
        {
            9, 2, 0, 0, 1, 1, 0, 0x80, 50,              // configuration (length patched below)
            9, 4, 0, 0, 2, 3, 0, 0, 0,                  // interface: HID, 2 endpoints
        };
        b.AddRange(hid);
        b.AddRange(new byte[] { 7, 5, 0x81, 3, 64, 0, 5 });   // EP1 IN, interrupt, 64 B, 5 ms
        b.AddRange(new byte[] { 7, 5, 0x01, 3, 64, 0, 5 });   // EP1 OUT
        b[2] = (byte)b.Count;
        b[3] = (byte)(b.Count >> 8);
        return b.ToArray();
    }

    static byte[] Str(string s)
    {
        var u = Encoding.Unicode.GetBytes(s);
        return [(byte)(u.Length + 2), 3, .. u];
    }

    /// <returns>(status, data) for a control transfer. Status -32 = stall.</returns>
    public static (int, byte[]) Control(byte[] setup)
    {
        byte type = setup[0], req = setup[1];
        ushort value = (ushort)(setup[2] | setup[3] << 8);
        byte descType = (byte)(value >> 8), descIndex = (byte)value;
        if (req == 6 && (type & 0x80) != 0)   // GET_DESCRIPTOR
        {
            switch (descType)
            {
                case 1: return (0, Device);
                case 2: return (0, Config());
                case 3:
                    return (0, descIndex switch
                    {
                        0 => new byte[] { 4, 3, 0x09, 0x04 },
                        1 => Str("AuthKey"),
                        2 => Str("AuthKey-ESP32 Security Key"),
                        3 => Str("AK0001"),
                        _ => Str(""),
                    });
                case 0x21: return (0, Config()[18..27]);
                case 0x22: return (0, Report);
                default: return (-32, Array.Empty<byte>());
            }
        }
        if (req == 0 && (type & 0x80) != 0) return (0, new byte[] { 0, 0 });          // GET_STATUS
        if (req == 8 && (type & 0x80) != 0) return (0, new byte[] { 1 });             // GET_CONFIGURATION
        if (req == 9 || req == 11 || req == 1 || req == 3) return (0, Array.Empty<byte>()); // SET_CONFIGURATION / INTERFACE / features
        if (type == 0x21 && (req == 0x0A || req == 0x0B)) return (0, Array.Empty<byte>()); // HID SET_IDLE / SET_PROTOCOL
        return (-32, Array.Empty<byte>());
    }
}

/// <summary>CTAPHID framing (FIDO CTAP 2.0 §8.1); CBOR requests go to the device.</summary>
sealed class CtapHid : IDisposable
{
    const byte CmdPing = 0x81, CmdMsg = 0x83, CmdLock = 0x84, CmdInit = 0x86, CmdWink = 0x88,
               CmdCbor = 0x90, CmdCancel = 0x91, CmdKeepalive = 0xBB, CmdError = 0xBF;
    const byte ErrInvalidCmd = 0x01, ErrInvalidLen = 0x03, ErrInvalidSeq = 0x04, ErrBusy = 0x06, ErrInvalidChannel = 0x0B;
    const uint Broadcast = 0xFFFFFFFF;

    readonly Action<byte[]> _send;
    readonly object _lock = new();
    readonly object _sendLock = new();
    uint _nextCid = 0x10000001;
    // Reassembly
    uint _rxCid;
    byte _rxCmd;
    byte[]? _rxBuf;
    int _rxLen, _rxSeq;
    // Running request
    uint _busyCid;
    CancellationTokenSource? _cancel;

    public CtapHid(Action<byte[]> send) => _send = send;

    // --- getInfo cache (shared by all connections) ---
    const byte CtapGetInfo = 0x04;
    const long InfoRefreshMs = 3000;
    static volatile byte[]? s_info;
    static long s_infoAt;
    static int s_infoRefreshing;

    /// <summary>Fetches getInfo from the device in the background (one at a time).</summary>
    public static void RefreshInfo()
    {
        if (Interlocked.Exchange(ref s_infoRefreshing, 1) == 1) return;
        _ = Task.Run(async () =>
        {
            try
            {
                var r = await DeviceLink.CtapAsync(new[] { CtapGetInfo }, CancellationToken.None);
                if (r.Length > 1 && r[0] == 0) { s_info = r; s_infoAt = Environment.TickCount64; }
            }
            catch (Exception e) { Trace($"getInfo refresh failed: {e.Message}"); }
            finally { Interlocked.Exchange(ref s_infoRefreshing, 0); }
        });
    }

    static readonly Stopwatch Clock = Stopwatch.StartNew();

    /// <summary>HID problems (errors, stalls): always logged.</summary>
    public static void Trace(string msg) => Log.Write($"VK +{Clock.ElapsedMilliseconds}ms {msg}");

    /// <summary>Per-packet trace, only while C:\ProgramData\AuthKey\vk-trace exists.</summary>
    public static void Verbose(string msg)
    {
        if (File.Exists(Path.Combine(Config.Dir, "vk-trace"))) Trace(msg);
    }

    public void Dispose() => _cancel?.Cancel();

    public void OnPacket(byte[] p)
    {
        uint cid = BinaryPrimitives.ReadUInt32BigEndian(p);
        if ((p[4] & 0x80) != 0)
        {
            byte cmd = p[4];
            int len = p[5] << 8 | p[6];
            Verbose($"<- cid {cid:X8} cmd {cmd:X2} len {len}");
            if (cmd == CmdCancel)
            {
                lock (_lock) if (_busyCid == cid) _cancel?.Cancel();
                return;
            }
            if (cmd == CmdInit)
            {
                lock (_lock) { _rxBuf = null; }
                HandleInit(cid, p.AsSpan(7, Math.Min(len, 57)).ToArray());
                return;
            }
            if (cid == 0 || cid == Broadcast) { Error(cid, ErrInvalidChannel); return; }
            if (cmd == CmdCbor && len == 1 && p[7] == CtapGetInfo && s_info is { } info)
            {
                // Windows opens several channels at once and asks each for
                // getInfo; a real key answers in microseconds, so a BUSY here
                // makes Windows give up ("can't read your security key").
                lock (_lock) _rxBuf = null;
                Send(cid, CmdCbor, info);
                if (Environment.TickCount64 - s_infoAt > InfoRefreshMs) RefreshInfo();
                return;
            }
            lock (_lock)
            {
                if (_busyCid != 0 && _busyCid != cid) { Error(cid, ErrBusy); return; }
                if (len > 7609) { Error(cid, ErrInvalidLen); return; }
                _rxCid = cid; _rxCmd = cmd; _rxLen = len; _rxSeq = 0;
                _rxBuf = new byte[len];
                int n = Math.Min(len, 57);
                Array.Copy(p, 7, _rxBuf, 0, n);
                _rxSeq = n;   // bytes received so far (reused as offset)
                if (n == len) Dispatch();
            }
        }
        else
        {
            lock (_lock)
            {
                if (_rxBuf == null || cid != _rxCid) return;
                int expectedSeq = (_rxSeq - 57) / 59;
                if (p[4] != expectedSeq) { _rxBuf = null; Error(cid, ErrInvalidSeq); return; }
                int n = Math.Min(_rxLen - _rxSeq, 59);
                Array.Copy(p, 5, _rxBuf, _rxSeq, n);
                _rxSeq += n;
                if (_rxSeq == _rxLen) Dispatch();
            }
        }
    }

    void HandleInit(uint cid, byte[] nonce)
    {
        if (nonce.Length != 8) { Error(cid, ErrInvalidLen); return; }
        uint newCid = cid == Broadcast ? Interlocked.Increment(ref _nextCid) : cid;
        var r = new byte[17];
        nonce.CopyTo(r, 0);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(8), newCid);
        r[12] = 2;          // CTAPHID protocol version
        r[13] = 2; r[14] = 0; r[15] = 0;   // device version
        r[16] = 0x04 | 0x08 | 0x01;        // CBOR | NMSG (no U2F) | WINK
        Send(cid, CmdInit, r);
    }

    // Called with _lock held once a full message has arrived.
    void Dispatch()
    {
        var cid = _rxCid;
        var cmd = _rxCmd;
        var data = _rxBuf!;
        _rxBuf = null;
        switch (cmd)
        {
            case CmdPing: Send(cid, CmdPing, data); break;
            case CmdWink: Send(cid, CmdWink, Array.Empty<byte>()); break;
            case CmdLock: Send(cid, CmdLock, Array.Empty<byte>()); break;
            case CmdCbor:
                _busyCid = cid;
                _cancel = new CancellationTokenSource();
                var token = _cancel.Token;
                _ = Task.Run(() => RunCborAsync(cid, data, token));
                break;
            case CmdMsg:   // U2F/CTAP1 is not supported: APDU status SW_INS_NOT_SUPPORTED
                Send(cid, CmdMsg, new byte[] { 0x6D, 0x00 });
                break;
            default:
                Error(cid, ErrInvalidCmd);
                break;
        }
    }

    async Task RunCborAsync(uint cid, byte[] request, CancellationToken cancel)
    {
        byte[] response;
        bool done = false;
        // Keepalives come from a timer thread; checking `done` under the send
        // lock guarantees none is sent after (or in the middle of) the reply.
        byte status = request[0] is 0x01 or 0x02 or 0x07 or 0x0B ? (byte)2 /* UP needed */ : (byte)1 /* processing */;
        using var keepalive = new Timer(_ =>
        {
            lock (_sendLock) if (!done) SendLocked(cid, CmdKeepalive, new[] { status });
        }, null, 100, 100);
        try
        {
            response = await DeviceLink.CtapAsync(request, cancel);
        }
        catch (Exception e)
        {
            Log.Write($"Virtual key: {e.Message}");
            response = new byte[] { 0x7F };   // CTAP1_ERR_OTHER
        }
        Log.Write($"Virtual key: CTAP 0x{request[0]:X2} ({request.Length} B) -> status 0x{response[0]:X2} ({response.Length} B)");
        if (request[0] == CtapGetInfo && response.Length > 1 && response[0] == 0)
        {
            s_info = response;
            s_infoAt = Environment.TickCount64;
        }
        lock (_lock) { _busyCid = 0; _cancel = null; }
        lock (_sendLock)
        {
            done = true;
            SendLocked(cid, CmdCbor, response);
        }
    }

    void Error(uint cid, byte code)
    {
        Trace($"-> cid {cid:X8} ERROR {code:X2}");
        Send(cid, CmdError, new[] { code });
    }

    /// <summary>Sends one CTAPHID message; its packets are never interleaved with another's.</summary>
    void Send(uint cid, byte cmd, byte[] data)
    {
        lock (_sendLock) SendLocked(cid, cmd, data);
    }

    void SendLocked(uint cid, byte cmd, byte[] data)
    {
        if (cmd != CmdKeepalive && cmd != CmdError) Verbose($"-> cid {cid:X8} cmd {cmd:X2} len {data.Length}");
        int off = 0;
        byte seq = 0;
        var p = new byte[64];
        BinaryPrimitives.WriteUInt32BigEndian(p, cid);
        p[4] = cmd;
        p[5] = (byte)(data.Length >> 8);
        p[6] = (byte)data.Length;
        int n = Math.Min(data.Length, 57);
        Array.Copy(data, 0, p, 7, n);
        off = n;
        _send(p);
        while (off < data.Length)
        {
            p = new byte[64];
            BinaryPrimitives.WriteUInt32BigEndian(p, cid);
            p[4] = seq++;
            n = Math.Min(data.Length - off, 59);
            Array.Copy(data, off, p, 5, n);
            off += n;
            _send(p);
        }
    }
}

/// <summary>Sends CTAP2 requests to the ESP32 over its USB serial console.</summary>
static class DeviceLink
{
    public static async Task<byte[]> CtapAsync(byte[] request, CancellationToken cancel)
    {
        var ports = UsbTransport.FindPorts();
        if (ports.Count == 0) throw new IOException("AuthKey is not plugged in");
        await UsbTransport.SerialGate.WaitAsync(cancel.IsCancellationRequested ? CancellationToken.None : cancel);
        try
        {
            return await Task.Run(() =>
            {
                using var sp = UsbTransport.OpenWithRetry(ports[0], TimeSpan.FromSeconds(3));
                sp.DiscardInBuffer();
                sp.Write($"ctap {Hex.Of(request)}\n");
                bool cancelSent = false;
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(40);
                var line = new StringBuilder();
                while (DateTime.UtcNow < deadline)
                {
                    if (cancel.IsCancellationRequested && !cancelSent)
                    {
                        sp.Write("ctap cancel\n");   // device answers KEEPALIVE_CANCEL
                        cancelSent = true;
                    }
                    try
                    {
                        int c = sp.ReadChar();
                        if (c != '\n') { line.Append((char)c); continue; }
                        var l = line.ToString().TrimEnd('\r');
                        line.Clear();
                        if (l.StartsWith("CTAP ", StringComparison.Ordinal))
                            return Convert.FromHexString(l[5..].Trim());
                        if (l.StartsWith("ERR", StringComparison.Ordinal)) return new byte[] { 0x7F };
                    }
                    catch (TimeoutException) { }
                }
                return new byte[] { 0x2F };   // CTAP2_ERR_USER_ACTION_TIMEOUT
            });
        }
        finally
        {
            UsbTransport.SerialGate.Release();
        }
    }
}
