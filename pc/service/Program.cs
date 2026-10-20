using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

namespace AuthKey;

public static class Program
{
    const string Usage = """
        AuthKeyUnlock — Windows sign-in with the AuthKey-ESP32

          AuthKeyUnlock pair            pair this PC with the device (admin, device on USB)
          AuthKeyUnlock test            check every transport (admin)
          AuthKeyUnlock status          show pairing and settings (admin)
          AuthKeyUnlock set usb|bluetooth|wifi on|off
          AuthKeyUnlock set wifi-host <name-or-ip>
          AuthKeyUnlock unpair          forget the pairing on this PC (admin)
          AuthKeyUnlock console         run the pipe server in this window (debug)
          AuthKeyUnlock service         (used by the Windows service)
        """;

    public static async Task<int> Main(string[] args)
    {
        var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "";
        try
        {
            switch (cmd)
            {
                case "service":
                    ServiceBase.Run(new UnlockService());
                    return 0;
                case "console":
                    Log.ToConsole = true;
                    var server = new PipeServer();
                    server.Start();
                    var key = new VirtualKey();
                    key.Start();
                    Console.WriteLine("Pipe server + virtual USB key running. Press Enter to stop.");
                    Console.ReadLine();
                    key.Stop();
                    server.Stop();
                    return 0;
                case "pair": RequireAdmin(); return await PairAsync();
                case "test": RequireAdmin(); return await TestAsync();
                case "status": RequireAdmin(); return Status();
                case "set": RequireAdmin(); return Set(args);
                case "unpair":
                    RequireAdmin();
                    if (File.Exists(Config.FilePath)) File.Delete(Config.FilePath);
                    Console.WriteLine("Pairing removed. (Also run `unlock remove <n>` on the device console.)");
                    return 0;
                default:
                    Console.WriteLine(Usage);
                    return cmd == "" || cmd == "help" ? 0 : 1;
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Error: {e.Message}");
            return 2;
        }
    }

    static void RequireAdmin()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("run this from an elevated (Administrator) terminal");
    }

    // --- pair -------------------------------------------------------------------

    static (string domain, string user) DetectAccount()
    {
        // A Microsoft account signs in as MicrosoftAccount\<email>.
        using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\IdentityCRL\UserExtendedProperties");
        var email = k?.GetSubKeyNames().FirstOrDefault(n => n.Contains('@'));
        if (email != null) return ("MicrosoftAccount", email);
        return (Environment.MachineName, Environment.UserName);
    }

    static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var pw = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (pw.Length > 0) pw.Length--; continue; }
            if (!char.IsControl(key.KeyChar)) pw.Append(key.KeyChar);
        }
        Console.WriteLine();
        return pw.ToString();
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUserW(string user, string? domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    /// <summary>
    /// One interactive logon attempt (each failure counts towards Windows'
    /// account-lockout threshold, so never retry automatically).
    /// </summary>
    static bool CheckPassword(string domain, string user, string password)
    {
        if (LogonUserW(user, domain, password, 2 /* interactive */, 0, out var token))
        {
            CloseHandle(token);
            return true;
        }
        int err = Marshal.GetLastWin32Error();
        Console.WriteLine(err switch
        {
            1326 => "Windows says: wrong user name or password (error 1326). If the password is right, password sign-in " +
                    "may be disabled: turn off 'Only allow Windows Hello sign-in for Microsoft accounts' " +
                    "(Settings > Accounts > Sign-in options), then try again.",
            1327 => "Windows says: account restriction (error 1327), e.g. password sign-in disabled for this account.",
            1909 => "Windows says: the account is locked out (error 1909). Wait for the lockout to expire.",
            1311 => "Windows says: no logon server available (error 1311). Connect to the internet and try again.",
            _ => $"Windows says: logon failed (error {err}).",
        });
        return false;
    }

    static async Task<int> PairAsync()
    {
        var (domain, user) = DetectAccount();
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? "";
        Console.WriteLine($"Windows account: {domain}\\{user}");
        Console.WriteLine(domain == "MicrosoftAccount"
            ? "This is a Microsoft account: enter its PASSWORD (the one for account.microsoft.com), not your Windows Hello PIN."
            : "Enter this account's Windows password (not the Windows Hello PIN).");
        var password = ReadPassword("Password: ");
        if (!CheckPassword(domain, user, password))
        {
            Console.WriteLine("Windows rejected that password. Nothing was changed.");
            return 1;
        }
        Console.WriteLine("Password verified.");

        var ports = UsbTransport.FindPorts();
        if (ports.Count == 0)
        {
            Console.WriteLine("Plug the AuthKey-ESP32 in over USB (and close anything using its COM port, e.g. qr_bridge).");
            return 1;
        }
        var pcId = RandomNumberGenerator.GetBytes(8);
        var key = RandomNumberGenerator.GetBytes(32);
        var name = Environment.MachineName.Length > 20 ? Environment.MachineName[..20] : Environment.MachineName;
        Console.WriteLine($"Sending pairing request to the device on {ports[0]} — press OK on the device to confirm...");
        var reply = await UsbTransport.CommandAsync(ports[0], $"unlock pair {Hex.Of(pcId)} {Hex.Of(key)} {name}\n",
            l => l.StartsWith("OK paired") || l.StartsWith("ERR"), TimeSpan.FromSeconds(40), CancellationToken.None);
        if (reply == null || !reply.StartsWith("OK paired"))
        {
            Console.WriteLine($"Pairing failed: {reply ?? "no answer (timed out)"}");
            return 1;
        }

        var cfg = Config.Load() ?? new Config();
        cfg.PcId = Hex.Of(pcId);
        cfg.SetKey(key);
        cfg.Domain = domain;
        cfg.User = user;
        cfg.Sid = sid;
        cfg.SetPassword(password);
        cfg.Save();
        CryptographicOperations.ZeroMemory(key);
        Console.WriteLine("Paired. Run `AuthKeyUnlock test` to check USB, Bluetooth and WiFi.");
        return 0;
    }

    // --- test / status / set -------------------------------------------------------

    static async Task<int> TestAsync()
    {
        var cfg = Config.Load() ?? throw new InvalidOperationException("not paired yet (run `AuthKeyUnlock pair`)");
        Log.ToConsole = true;
        int ok = 0;
        foreach (var t in Engine.Transports(cfg))
        {
            var sw = Stopwatch.StartNew();
            var via = await Engine.VerifyAsync(cfg, new[] { t }, TimeSpan.FromSeconds(35));
            Console.WriteLine($"  {t.Name,-10} {(via != null ? "OK" : "not reachable")}  ({sw.ElapsedMilliseconds} ms)");
            if (via != null) ok++;
        }
        Console.WriteLine(ok > 0 ? "The lock screen can use any transport marked OK." : "No transport worked.");
        return ok > 0 ? 0 : 1;
    }

    static int Status()
    {
        var cfg = Config.Load();
        if (cfg == null) { Console.WriteLine("Not paired."); return 1; }
        Console.WriteLine($"Account:    {cfg.Domain}\\{cfg.User}");
        Console.WriteLine($"PC id:      {cfg.PcId}");
        Console.WriteLine($"USB:        {(cfg.UseUsb ? "on" : "off")}");
        Console.WriteLine($"Bluetooth:  {(cfg.UseBluetooth ? "on" : "off")} {cfg.BluetoothAddress?.ToString("X12")}");
        Console.WriteLine($"WiFi:       {(cfg.UseWifi ? "on" : "off")} {cfg.WifiHost} {cfg.LastWifiAddress}");
        Console.WriteLine($"Lock screen: {(File.Exists(Config.DisableFlag) ? "DISABLED (remove " + Config.DisableFlag + ")" : "enabled")}");
        return 0;
    }

    static int Set(string[] args)
    {
        var cfg = Config.Load() ?? throw new InvalidOperationException("not paired yet");
        if (args.Length < 3) { Console.WriteLine(Usage); return 1; }
        var on = args[2].Equals("on", StringComparison.OrdinalIgnoreCase);
        switch (args[1].ToLowerInvariant())
        {
            case "usb": cfg.UseUsb = on; break;
            case "bluetooth": case "ble": cfg.UseBluetooth = on; break;
            case "wifi": cfg.UseWifi = on; break;
            case "wifi-host": cfg.WifiHost = args[2]; cfg.LastWifiAddress = null; break;
            default: Console.WriteLine(Usage); return 1;
        }
        cfg.Save();
        return Status();
    }
}

public sealed class UnlockService : ServiceBase
{
    readonly PipeServer _server = new();
    readonly VirtualKey _key = new();
    public UnlockService() => ServiceName = "AuthKeyUnlock";

    protected override void OnStart(string[] args)
    {
        _server.Start();
        _key.Start();
    }

    protected override void OnStop()
    {
        _key.Stop();
        _server.Stop();
    }
}
