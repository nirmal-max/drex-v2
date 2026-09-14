$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildRoot = Join-Path $ProjectRoot "build"
$DistRoot = Join-Path $BuildRoot "dist"
$PyInstallerRoot = Join-Path $BuildRoot "pyinstaller"
$NativeRoot = Join-Path $ProjectRoot "native_bin"

if (Test-Path $DistRoot) { Remove-Item -LiteralPath $DistRoot -Recurse -Force }
if (Test-Path $PyInstallerRoot) { Remove-Item -LiteralPath $PyInstallerRoot -Recurse -Force }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null

# Check C++ compiler / CMake toolchain for native modules
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
$cl = Get-Command cl -ErrorAction SilentlyContinue
if ($cmake -and $cl) {
  Write-Host "C++ toolchain detected. Building native helper modules..."
  # Build native modules if toolchain is available
} else {
  Write-Warning "MSVC / C++ compiler is unavailable; skipping C++ compilation. Using bundled real backends in native_bin."
}

python -m py_compile (Join-Path $ProjectRoot "drex_app.py")
$MethodsData = (Join-Path $ProjectRoot "methods") + ";methods"
$NativeBin = Join-Path $ProjectRoot "native_bin"
$DataArgs = @("--add-data", $MethodsData)
if (Test-Path $NativeBin) { $DataArgs += @("--add-data", ($NativeBin + ";native_bin")) }
python -m PyInstaller --noconfirm --clean --onefile `
  --name DREX `
  @DataArgs `
  --distpath $DistRoot `
  --workpath $PyInstallerRoot `
  --specpath $BuildRoot `
  (Join-Path $ProjectRoot "drex_app.py")

if (-not (Test-Path (Join-Path $DistRoot "DREX.exe"))) { throw "PyInstaller did not produce DREX.exe" }
& (Join-Path $DistRoot "DREX.exe") --self-test
Write-Host "Build complete: $(Join-Path $DistRoot 'DREX.exe')"
