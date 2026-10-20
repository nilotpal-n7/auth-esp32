# Starts the AuthKey QR helper (tools\qr_bridge.py) in the background at every
# login, and right now. No admin needed: it adds a shortcut to your Startup
# folder pointing at pc\bin\AuthKeyQR.exe (built by pc\build.ps1), which runs
# the helper with no window. It shows as "AuthKey QR helper" in Task Manager;
# ending it there stops the helper.
#
#   powershell -ExecutionPolicy Bypass -File tools\autostart.ps1           # install + start
#   powershell -ExecutionPolicy Bypass -File tools\autostart.ps1 -Remove   # stop + remove
#
# Output goes to %LOCALAPPDATA%\AuthKey\qr_bridge.log.
param([switch]$Remove)
$ErrorActionPreference = "Stop"

$repo     = Split-Path $PSScriptRoot -Parent
$launcher = Join-Path $repo "pc\bin\AuthKeyQR.exe"
$link     = Join-Path ([Environment]::GetFolderPath("Startup")) "AuthKey QR helper.lnk"
$logFile  = Join-Path $env:LOCALAPPDATA "AuthKey\qr_bridge.log"

function Stop-Bridge {
    Get-Process AuthKeyQR -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
        Where-Object { $_.CommandLine -like "*qr_bridge.py*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

if ($Remove) {
    Stop-Bridge
    Remove-Item $link -ErrorAction SilentlyContinue
    Write-Host "QR helper stopped and removed from startup."
    return
}

if (-not (Test-Path $launcher)) { throw "Missing $launcher - run pc\build.ps1 first." }

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($link)
$lnk.TargetPath = $launcher
$lnk.WorkingDirectory = $repo
$lnk.Description = "AuthKey QR helper: passkey and authenticator QR codes to the AuthKey-ESP32"
$lnk.Save()

Stop-Bridge
Start-Process -FilePath $launcher -WorkingDirectory $repo
Write-Host "QR helper starts at login and is running now (Task Manager: 'AuthKey QR helper')."
Write-Host "Log: $logFile"
