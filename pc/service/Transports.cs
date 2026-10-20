using System.IO.Ports;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace AuthKey;

/// <summary>Asks the device to answer an unlock challenge over one transport.</summary>
public interface ITransport
{
    string Name { get; }
    /// <returns>The 32-byte answer, or null if unreachable / denied.</returns>
    Task<byte[]?> AskAsync(byte[] pcId, byte[] challenge, CancellationToken ct);
}

static class Hex
{
    public static string Of(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}

/// <summary>Line protocol shared by USB serial and WiFi: "unlock id chal" -> "UNLOCK mac".</summary>
static class LineProtocol
{
    public static string Request(byte[] pcId, byte[] chal) => $"unlock {Hex.Of(pcId)} {Hex.Of(chal)}\n";

    /// <returns>true = final answer (mac may be null when denied), false = unrelated line.</returns>
    public static bool Parse(string line, out byte[]? mac)
    {
        mac = null;
        line = line.Trim();
        if (line.StartsWith("UNLOCK ", StringComparison.Ordinal))
        {
            try { mac = Convert.FromHexString(line[7..].Trim()); } catch { mac = null; }
            return true;
        }
        return line.StartsWith("ERR", StringComparison.Ordinal);
    }
}

// --- USB serial ---------------------------------------------------------------

public sealed class UsbTransport : ITransport
{
    public string Name => "USB";
    static readonly string[] Bridges = { "VID_10C4&PID_EA60", "VID_1A86&PID_7523", "VID_1A86&PID_55D4" };

    /// <summary>COM ports belonging to known ESP32 USB-UART bridges that are present now.</summary>
    public static List<string> FindPorts()
    {
        var present = new HashSet<string>(SerialPort.GetPortNames(), StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        using var usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
        if (usb == null) return result;
        foreach (var vidPid in Bridges)
        {
            using var dev = usb.OpenSubKey(vidPid);
            if (dev == null) continue;
            foreach (var inst in dev.GetSubKeyNames())
            {
                using var p = dev.OpenSubKey($@"{inst}\Device Parameters");
                if (p?.GetValue("PortName") is string port && present.Contains(port)) result.Add(port);
            }
        }
        return result;
    }

    /// <summary>Serialises access to the COM port (unlock checks and security-key requests).</summary>
    public static readonly SemaphoreSlim SerialGate = new(1, 1);

    /// <summary>Open, retrying briefly while another program (e.g. qr_bridge) holds the port.</summary>
    public static SerialPort OpenWithRetry(string port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try { return Open(port); }
            catch (UnauthorizedAccessException) when (DateTime.UtcNow < deadline) { Thread.Sleep(150); }
        }
    }

    public static SerialPort Open(string port)
    {
        // DTR/RTS stay low so opening the port does not reset the ESP32.
        var sp = new SerialPort(port, 115200)
        {
            DtrEnable = false, RtsEnable = false, Handshake = Handshake.None,
            ReadTimeout = 200, WriteTimeout = 1000, NewLine = "\n", Encoding = Encoding.ASCII,
        };
        sp.Open();
        return sp;
    }

    /// <summary>Send one console line and wait for a terminating reply line.</summary>
    public static async Task<string?> CommandAsync(string port, string line, Func<string, bool> isFinal,
                                                   TimeSpan timeout, CancellationToken ct)
    {
        await SerialGate.WaitAsync(ct);
        try
        {
            return await CommandLockedAsync(port, line, isFinal, timeout, ct);
        }
        finally
        {
            SerialGate.Release();
        }
    }

    static async Task<string?> CommandLockedAsync(string port, string line, Func<string, bool> isFinal,
                                                  TimeSpan timeout, CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            using var sp = OpenWithRetry(port, TimeSpan.FromSeconds(2));
            sp.DiscardInBuffer();
            sp.Write(line);
            var deadline = DateTime.UtcNow + timeout;
            var buf = new StringBuilder();
            while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
            {
                try
                {
                    int c = sp.ReadChar();
                    if (c == '\n')
                    {
                        var l = buf.ToString().TrimEnd('\r');
                        buf.Clear();
                        if (isFinal(l)) return l;
                    }
                    else buf.Append((char)c);
                }
                catch (TimeoutException) { }
            }
            return null;
        }, ct);
    }

    public async Task<byte[]?> AskAsync(byte[] pcId, byte[] challenge, CancellationToken ct)
    {
        foreach (var port in FindPorts())
        {
            try
            {
                var reply = await CommandAsync(port, LineProtocol.Request(pcId, challenge),
                    l => LineProtocol.Parse(l, out _), TimeSpan.FromSeconds(32), ct);
                if (reply != null && LineProtocol.Parse(reply, out var mac)) return mac;
            }
            catch (UnauthorizedAccessException) { Log.Write($"USB: {port} busy (in use by another program)"); }
            catch (Exception e) when (e is not OperationCanceledException) { Log.Write($"USB: {port}: {e.Message}"); }
        }
        return null;
    }
}

// --- WiFi (TCP) -----------------------------------------------------------------

public sealed class WifiTransport : ITransport
{
    public const int Port = 7623;
    readonly Config _cfg;
    public WifiTransport(Config cfg) => _cfg = cfg;
    public string Name => "WiFi";

    public async Task<byte[]?> AskAsync(byte[] pcId, byte[] challenge, CancellationToken ct)
    {
        var hosts = new List<string>();
        if (!string.IsNullOrEmpty(_cfg.LastWifiAddress)) hosts.Add(_cfg.LastWifiAddress);
        hosts.Add(_cfg.WifiHost);
        foreach (var host in hosts.Distinct())
        {
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(3));
                await tcp.ConnectAsync(host, Port, connectCts.Token);
                var addr = (tcp.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address.ToString();
                using var stream = tcp.GetStream();
                var req = Encoding.ASCII.GetBytes(LineProtocol.Request(pcId, challenge));
                await stream.WriteAsync(req, ct);
                using var reader = new StreamReader(stream, Encoding.ASCII);
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCts.CancelAfter(TimeSpan.FromSeconds(32));
                while (await reader.ReadLineAsync(readCts.Token) is { } line)
                {
                    if (!LineProtocol.Parse(line, out var mac)) continue;
                    if (mac != null && addr != null && addr != _cfg.LastWifiAddress)
                    {
                        _cfg.LastWifiAddress = addr;   // remembered for a faster next attempt
                        try { _cfg.Save(); } catch { }
                    }
                    return mac;
                }
            }
            catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                Log.Write($"WiFi: {host}: {e.Message}");
            }
        }
        return null;
    }
}

// --- Bluetooth LE -----------------------------------------------------------------

public sealed class BluetoothTransport : ITransport
{
    static readonly Guid ProvService = Guid.Parse("a3c87500-8ed3-4bdf-8a39-a01bebede295");
    static readonly Guid UnlockChar = Guid.Parse("a3c87503-8ed3-4bdf-8a39-a01bebede295");
    const string DeviceName = "AuthKey-ESP32";
    readonly Config _cfg;
    public BluetoothTransport(Config cfg) => _cfg = cfg;
    public string Name => "Bluetooth";

    public static async Task<ulong?> ScanAsync(TimeSpan timeout, CancellationToken ct)
    {
        var found = new TaskCompletionSource<ulong>(TaskCreationOptions.RunContinuationsAsynchronously);
        var watcher = new BluetoothLEAdvertisementWatcher { ScanningMode = BluetoothLEScanningMode.Active };
        watcher.Received += (_, a) =>
        {
            if (a.Advertisement.LocalName == DeviceName || a.Advertisement.ServiceUuids.Contains(ProvService))
                found.TrySetResult(a.BluetoothAddress);
        };
        watcher.Start();
        try
        {
            using var reg = ct.Register(() => found.TrySetCanceled());
            var done = await Task.WhenAny(found.Task, Task.Delay(timeout, ct));
            return done == found.Task && found.Task.IsCompletedSuccessfully ? found.Task.Result : null;
        }
        catch (OperationCanceledException) { return null; }
        finally { watcher.Stop(); }
    }

    public async Task<byte[]?> AskAsync(byte[] pcId, byte[] challenge, CancellationToken ct)
    {
        try
        {
            var addr = _cfg.BluetoothAddress ?? await ScanAsync(TimeSpan.FromSeconds(8), ct);
            if (addr == null) return null;
            if (_cfg.BluetoothAddress != addr)
            {
                _cfg.BluetoothAddress = addr;
                try { _cfg.Save(); } catch { }
            }

            using var dev = await BluetoothLEDevice.FromBluetoothAddressAsync(addr.Value).AsTask(ct);
            if (dev == null) return null;
            var svcs = await dev.GetGattServicesForUuidAsync(ProvService, BluetoothCacheMode.Uncached).AsTask(ct);
            if (svcs.Status != GattCommunicationStatus.Success || svcs.Services.Count == 0) return null;
            using var svc = svcs.Services[0];
            var chars = await svc.GetCharacteristicsForUuidAsync(UnlockChar, BluetoothCacheMode.Uncached).AsTask(ct);
            if (chars.Status != GattCommunicationStatus.Success || chars.Characteristics.Count == 0) return null;
            var ch = chars.Characteristics[0];

            var reply = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            ch.ValueChanged += (_, e) =>
            {
                using var r = DataReader.FromBuffer(e.CharacteristicValue);
                var b = new byte[r.UnconsumedBufferLength];
                r.ReadBytes(b);
                reply.TrySetResult(b);
            };
            var cccd = await ch.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue.Notify).AsTask(ct);
            if (cccd != GattCommunicationStatus.Success) return null;

            var w = new DataWriter();
            w.WriteBytes(pcId);
            w.WriteBytes(challenge);
            var st = await ch.WriteValueAsync(w.DetachBuffer(), GattWriteOption.WriteWithResponse).AsTask(ct);
            if (st != GattCommunicationStatus.Success) return null;

            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(TimeSpan.FromSeconds(32));
            using var _ = wait.Token.Register(() => reply.TrySetCanceled());
            try
            {
                var data = await reply.Task;
                return data.Length == 33 && data[0] == 0 ? data[1..] : null;
            }
            finally
            {
                // Release the link promptly: the device can only advertise (and
                // do hybrid sign-ins) while nothing is connected to it.
                try
                {
                    await ch.WriteClientCharacteristicConfigurationDescriptorAsync(
                        GattClientCharacteristicConfigurationDescriptorValue.None).AsTask();
                }
                catch { }
                try
                {
                    using var session = await GattSession.FromDeviceIdAsync(dev.BluetoothDeviceId).AsTask();
                    session.MaintainConnection = false;
                }
                catch { }
            }
        }
        catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            Log.Write($"Bluetooth: {e.Message}");
            return null;
        }
    }
}
