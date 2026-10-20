#Requires -RunAsAdministrator
<#
  Installs AuthKey Windows sign-in:
    - copies AuthKeyProvider.dll + AuthKeyUnlock.exe to "C:\Program Files\AuthKey"
    - registers the credential provider (lock screen / sign-in "AuthKey" option)
    - installs and starts the "AuthKey Unlock" Windows service
    - pairs this PC with the device (device on USB, press OK on it)

  Undo with pc\uninstall.ps1. Emergency off-switch (keeps everything installed):
    New-Item "$env:ProgramData\AuthKey\disabled"
#>
param([switch]$SkipPairing)
$ErrorActionPreference = "Stop"

$clsid = "{50B5E277-5F97-43F5-AE3C-3542AD8DF74C}"
$src = Join-Path $PSScriptRoot "bin"
$dst = Join-Path $env:ProgramFiles "AuthKey"
$exe = Join-Path $dst "AuthKeyUnlock.exe"
$dll = Join-Path $dst "AuthKeyProvider.dll"

foreach ($f in "AuthKeyProvider.dll", "AuthKeyUnlock.exe") {
    if (-not (Test-Path (Join-Path $src $f))) { throw "Missing $src\$f - run pc\build.ps1 first" }
}

# Windows Hello-only mode hides password-based sign-in providers.
$pwless = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -ErrorAction SilentlyContinue
if ($pwless.DevicePasswordLessBuildVersion -eq 2) {
    Write-Warning ("'Only allow Windows Hello sign-in for Microsoft accounts' is ON. If the AuthKey option does not " +
                   "appear on the lock screen, turn it off in Settings > Accounts > Sign-in options.")
}

Write-Host "Installing files to $dst"
New-Item -ItemType Directory -Force $dst | Out-Null
$svc = Get-Service AuthKeyUnlock -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Stopped") { Stop-Service AuthKeyUnlock -Force }
Copy-Item (Join-Path $src "AuthKeyUnlock.exe") $exe -Force
# LogonUI may still have an older DLL loaded: move it aside instead of overwriting.
if (Test-Path $dll) {
    $old = "$dll.old-$(Get-Date -Format yyyyMMddHHmmss)"
    try { Move-Item $dll $old -Force } catch { Write-Warning "Could not replace the loaded DLL; reboot and run again." ; throw }
}
Copy-Item (Join-Path $src "AuthKeyProvider.dll") $dll -Force
Get-ChildItem "$dst\AuthKeyProvider.dll.old-*" -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue

Write-Host "Registering the credential provider"
$cp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
New-Item $cp -Force | Out-Null
Set-ItemProperty $cp -Name "(default)" -Value "AuthKey"
$com = "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid"
New-Item "$com\InprocServer32" -Force | Out-Null
Set-ItemProperty $com -Name "(default)" -Value "AuthKey credential provider"
Set-ItemProperty "$com\InprocServer32" -Name "(default)" -Value $dll
Set-ItemProperty "$com\InprocServer32" -Name "ThreadingModel" -Value "Apartment"

Write-Host "Installing the AuthKey Unlock service"
if (-not $svc) {
    New-Service -Name AuthKeyUnlock -DisplayName "AuthKey Unlock" -StartupType Automatic `
        -BinaryPathName "`"$exe`" service" `
        -Description "Verifies the AuthKey-ESP32 (USB / Bluetooth / WiFi) for Windows sign-in." | Out-Null
    sc.exe failure AuthKeyUnlock reset= 60 actions= restart/5000/restart/5000/restart/30000 | Out-Null
}
Start-Service AuthKeyUnlock

if (-not $SkipPairing) {
    Write-Host ""
    Write-Host "Pairing (close tools\qr_bridge.py first so the USB port is free)..."
    & $exe pair
    if ($LASTEXITCODE -ne 0) { Write-Warning "Pairing did not complete. Run: & '$exe' pair" ; exit 1 }
    Write-Host ""
    Write-Host "Testing transports..."
    & $exe test
}

Write-Host ""
Write-Host "Done. Lock with Win+L, press any key: with the AuthKey present you are signed in automatically."
Write-Host "If it isn't the selected option, pick 'Sign-in options' > AuthKey once; Windows remembers it."
