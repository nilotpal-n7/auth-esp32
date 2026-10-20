using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace AuthKey;

/// <summary>
/// Named pipe used by the lock-screen credential provider (running as SYSTEM
/// inside LogonUI). Requests are single lines:
///   INFO   -> "INFO &lt;b64 sid&gt; &lt;b64 user&gt;"            (no secrets)
///   UNLOCK -> "OK &lt;b64 domain&gt; &lt;b64 user&gt; &lt;b64 password&gt;" or "NO &lt;reason&gt;"
/// The pipe only accepts SYSTEM and elevated administrators, so the password
/// never reaches ordinary user processes.
/// </summary>
public sealed class PipeServer
{
    public const string Name = "AuthKeyUnlock";
    readonly CancellationTokenSource _stop = new();
    Task? _loop;

    public void Start() => _loop = Task.Run(() => RunAsync(_stop.Token));

    public void Stop()
    {
        _stop.Cancel();
        try { _loop?.Wait(2000); } catch { }
    }

    static NamedPipeServerStream Create()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        // Elevated admins can already decrypt the vault, so this exposes nothing
        // new; it lets elevated credential prompts (CredUI) use the device too.
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(Name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, sec);
    }

    async Task RunAsync(CancellationToken ct)
    {
        Log.Write("Pipe server started");
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = Create();
                await pipe.WaitForConnectionAsync(ct);
                var client = pipe;
                pipe = null;
                _ = Task.Run(() => HandleAsync(client, ct));   // one task per client
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e)
            {
                Log.Write($"Pipe: {e.Message}");
                await Task.Delay(500, ct).ContinueWith(_ => { });
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    static async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, Encoding.ASCII, false, 256, leaveOpen: true);
                var request = (await reader.ReadLineAsync(ct))?.Trim();
                string reply = await HandleRequestAsync(request);
                var bytes = Encoding.ASCII.GetBytes(reply + "\n");
                await pipe.WriteAsync(bytes, ct);
                await pipe.FlushAsync(ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                Log.Write($"Pipe client: {e.Message}");
            }
        }
    }

    public static async Task<string> HandleRequestAsync(string? request)
    {
        if (File.Exists(Config.DisableFlag)) return "NO disabled";
        var cfg = Config.Load();
        if (cfg == null) return "NO not-paired";
        switch (request)
        {
            case "INFO":
                return $"INFO {B64(cfg.Sid)} {B64(cfg.User)}";
            case "UNLOCK":
            {
                var via = await Engine.VerifyAsync(cfg, Engine.Transports(cfg), TimeSpan.FromSeconds(35));
                if (via == null)
                {
                    Log.Write("Unlock: device not reachable or denied");
                    return "NO device";
                }
                Log.Write($"Unlock: device verified via {via}");
                return $"OK {B64(cfg.Domain)} {B64(cfg.User)} {B64(cfg.Password)}";
            }
            default:
                return "NO bad-request";
        }
    }
}
