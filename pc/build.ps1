# Builds the AuthKey Windows sign-in components into pc\bin:
#   AuthKeyProvider.dll  (credential provider, C++/MSVC, x64)
#   AuthKeyUnlock.exe    (service + pairing tool, .NET 9)
#   AuthKeyQR.exe        (starts tools\qr_bridge.py hidden; see tools\autostart.ps1)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$bin = Join-Path $root "bin"
New-Item -ItemType Directory -Force $bin | Out-Null

# --- C++ credential provider -------------------------------------------------
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "Visual Studio with the C++ x64 tools is required" }
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$src = Join-Path $root "credprov\AuthKeyProvider.cpp"
$def = Join-Path $root "credprov\AuthKeyProvider.def"
$obj = Join-Path $bin "AuthKeyProvider.obj"
$dll = Join-Path $bin "AuthKeyProvider.dll"
$implib = Join-Path $bin "AuthKeyProvider.lib"   # keeps linker by-products out of the source tree
$env:PATH = "$(Split-Path $vswhere);$env:PATH"   # vcvars64.bat calls vswhere.exe
$cmd = "`"$vcvars`" >nul 2>&1 && cl /nologo /LD /O2 /W4 /EHsc /MT /DUNICODE /D_UNICODE /Fo`"$obj`" `"$src`" /link /DEF:`"$def`" /OUT:`"$dll`" /IMPLIB:`"$implib`""
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "credential provider build failed" }
Remove-Item -ErrorAction SilentlyContinue (Join-Path $bin "AuthKeyProvider.obj"), (Join-Path $bin "AuthKeyProvider.exp"), (Join-Path $bin "AuthKeyProvider.lib")

# --- QR helper launcher (runs tools\qr_bridge.py hidden, named in Task Manager) ---
$qr = Join-Path $root "qrhelper"
$res = Join-Path $bin "AuthKeyQR.res"
$cmd = "`"$vcvars`" >nul 2>&1 && rc /nologo /fo`"$res`" `"$qr\AuthKeyQR.rc`" && " +
       "cl /nologo /O2 /W4 /MT /DUNICODE /D_UNICODE /Fo`"$bin\AuthKeyQR.obj`" `"$qr\AuthKeyQR.c`" `"$res`" " +
       "/link /SUBSYSTEM:WINDOWS /OUT:`"$bin\AuthKeyQR.exe`" user32.lib shell32.lib ole32.lib"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "QR helper launcher build failed" }
Remove-Item -ErrorAction SilentlyContinue (Join-Path $bin "AuthKeyQR.obj"), $res

# --- .NET service ----------------------------------------------------------------
dotnet publish (Join-Path $root "service\AuthKeyUnlock.csproj") -c Release -r win-x64 --self-contained false `
    -p:PublishSingleFile=true -o $bin | Out-Host
if ($LASTEXITCODE -ne 0) { throw "service build failed" }
Write-Host "Built into $bin"
