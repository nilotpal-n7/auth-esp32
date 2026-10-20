using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace AuthKey;

/// <summary>
/// Pairing data, stored in C:\ProgramData\AuthKey\unlock.json. The device key
/// and the Windows password are encrypted with DPAPI (machine scope) and the
/// folder is readable only by SYSTEM and Administrators.
/// </summary>
public sealed class Config
{
    public string PcId { get; set; } = "";            // hex, 8 bytes
    public string KeyProtected { get; set; } = "";    // DPAPI(base64)
    public string Domain { get; set; } = "";          // "MicrosoftAccount" or computer/domain name
    public string User { get; set; } = "";
    public string Sid { get; set; } = "";
    public string PasswordProtected { get; set; } = "";
    public bool UseUsb { get; set; } = true;
    public bool UseBluetooth { get; set; } = true;
    public bool UseWifi { get; set; } = true;
    public string WifiHost { get; set; } = "authkey-esp32.local";
    public string? LastWifiAddress { get; set; }
    public ulong? BluetoothAddress { get; set; }

    public static string Dir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AuthKey");
    public static string FilePath => Path.Combine(Dir, "unlock.json");
    public static string DisableFlag => Path.Combine(Dir, "disabled");

    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AuthKey-ESP32 unlock v1");
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static Config? Load()
    {
        try
        {
            return File.Exists(FilePath) ? JsonSerializer.Deserialize<Config>(File.ReadAllText(FilePath)) : null;
        }
        catch
        {
            return null;
        }
    }

    public void Save()
    {
        EnsureSecureDir();
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Json));
    }

    public byte[] Key => Unprotect(KeyProtected);
    public string Password => Encoding.UTF8.GetString(Unprotect(PasswordProtected));
    public void SetKey(byte[] key) => KeyProtected = Protect(key);
    public void SetPassword(string pw) => PasswordProtected = Protect(Encoding.UTF8.GetBytes(pw));

    static string Protect(byte[] data) =>
        Convert.ToBase64String(ProtectedData.Protect(data, Entropy, DataProtectionScope.LocalMachine));

    static byte[] Unprotect(string b64) =>
        ProtectedData.Unprotect(Convert.FromBase64String(b64), Entropy, DataProtectionScope.LocalMachine);

    static void EnsureSecureDir()
    {
        var di = Directory.CreateDirectory(Dir);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        di.SetAccessControl(sec);
    }
}
