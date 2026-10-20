using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace AuthKey;

/// <summary>
/// Event log in C:\ProgramData\AuthKey\logs\service.log. It holds no secrets,
/// so local users may read it (no admin needed to troubleshoot); only SYSTEM
/// and Administrators can write, so it can't be redirected or tampered with.
/// </summary>
static class Log
{
    static readonly object Gate = new();
    static bool _dirReady;
    public static bool ToConsole;
    public static string Dir => Path.Combine(Config.Dir, "logs");

    static void EnsureDir()
    {
        if (_dirReady) return;
        var di = Directory.CreateDirectory(Dir);
        try
        {
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            void Allow(WellKnownSidType sid, FileSystemRights rights) =>
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), rights, inherit,
                                                           PropagationFlags.None, AccessControlType.Allow));
            Allow(WellKnownSidType.LocalSystemSid, FileSystemRights.FullControl);
            Allow(WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl);
            Allow(WellKnownSidType.BuiltinUsersSid, FileSystemRights.ReadAndExecute);
            di.SetAccessControl(sec);
        }
        catch { }   // not elevated (console mode): keep the default ACL
        _dirReady = true;
    }

    public static void Write(string msg)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {msg}";
        if (ToConsole) Console.WriteLine(line);
        try
        {
            lock (Gate)
            {
                EnsureDir();
                var path = Path.Combine(Dir, "service.log");
                if (File.Exists(path) && new FileInfo(path).Length > 512 * 1024)
                    File.Move(path, path + ".old", overwrite: true);
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }
        catch { }
    }
}

/// <summary>Runs one challenge-response over every enabled transport at once.</summary>
public static class Engine
{
    static readonly byte[] Label = Encoding.ASCII.GetBytes("AuthKey unlock v1");
    static readonly SemaphoreSlim OneAtATime = new(1, 1);

    public static byte[] Expected(byte[] key, byte[] pcId, byte[] challenge)
    {
        using var h = new HMACSHA256(key);
        return h.ComputeHash([.. Label, .. pcId, .. challenge]);
    }

    public static List<ITransport> Transports(Config cfg)
    {
        var list = new List<ITransport>();
        if (cfg.UseUsb) list.Add(new UsbTransport());
        if (cfg.UseBluetooth) list.Add(new BluetoothTransport(cfg));
        if (cfg.UseWifi) list.Add(new WifiTransport(cfg));
        return list;
    }

    /// <returns>Name of the transport that proved the device's presence, or null.</returns>
    public static async Task<string?> VerifyAsync(Config cfg, IEnumerable<ITransport> transports, TimeSpan timeout)
    {
        if (!await OneAtATime.WaitAsync(timeout)) return null;
        try
        {
            var pcId = Convert.FromHexString(cfg.PcId);
            var key = cfg.Key;
            var challenge = RandomNumberGenerator.GetBytes(32);
            var expected = Expected(key, pcId, challenge);
            CryptographicOperations.ZeroMemory(key);

            using var cts = new CancellationTokenSource(timeout);
            var pending = transports.Select(async t => (t.Name, Mac: await t.AskAsync(pcId, challenge, cts.Token))).ToList();
            while (pending.Count > 0)
            {
                var done = await Task.WhenAny(pending);
                pending.Remove(done);
                try
                {
                    var (name, mac) = await done;
                    if (mac != null && mac.Length == 32 && CryptographicOperations.FixedTimeEquals(mac, expected))
                    {
                        cts.Cancel();   // stop the other transports
                        return name;
                    }
                    if (mac != null) Log.Write($"{name}: wrong answer (device paired with another key?)");
                }
                catch (OperationCanceledException) { }
            }
            return null;
        }
        finally
        {
            OneAtATime.Release();
        }
    }
}
