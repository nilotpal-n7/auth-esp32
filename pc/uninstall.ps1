#Requires -RunAsAdministrator
<# Removes AuthKey Windows sign-in. -Purge also deletes the saved pairing (encrypted password). #>
param([switch]$Purge)
$ErrorActionPreference = "Continue"
$clsid = "{50B5E277-5F97-43F5-AE3C-3542AD8DF74C}"
$dst = Join-Path $env:ProgramFiles "AuthKey"

Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -Recurse -ErrorAction SilentlyContinue
Remove-Item "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid" -Recurse -ErrorAction SilentlyContinue
Write-Host "Credential provider unregistered (it disappears from the lock screen now)."

if (Get-Service AuthKeyUnlock -ErrorAction SilentlyContinue) {
    Stop-Service AuthKeyUnlock -Force -ErrorAction SilentlyContinue
    sc.exe delete AuthKeyUnlock | Out-Null
    Write-Host "Service removed."
}

# The DLL may still be loaded by LogonUI until the next sign-in/reboot.
Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $dst) { Write-Host "Some files in $dst are in use; they can be deleted after a reboot." }

if ($Purge) {
    Remove-Item (Join-Path $env:ProgramData "AuthKey") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Pairing data deleted. Also remove this PC on the device: unlock list / unlock remove <n>."
}
