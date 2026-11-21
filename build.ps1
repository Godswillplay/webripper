# build.ps1 -- WebRipper Recon 5.0 PyInstaller packaging script (Pure CLI / Console)
# Usage: .\build.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  WebRipper Recon 5.0 -- Headless Engine Build Script" -ForegroundColor Cyan
Write-Host "  ===================================================" -ForegroundColor DarkGray
Write-Host ""

# Determine Python executable
$pythonCmd = @("python")
if (Test-Path ".\.venv\Scripts\python.exe") {
    $pythonCmd = @(".\.venv\Scripts\python.exe")
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = @("py")
}

# Check PyInstaller
Write-Host "[1/4] Verifying PyInstaller environment ($($pythonCmd -join ' '))..." -ForegroundColor Gray
& $pythonCmd -m PyInstaller --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  PyInstaller not found. Installing..." -ForegroundColor Yellow
    & $pythonCmd -m pip install pyinstaller
}

# Clean previous build
Write-Host "[2/4] Cleaning previous build artifacts..." -ForegroundColor Gray
Get-Process -Name "WebRipperRecon", "WebRipper" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
if (Test-Path ".\build\WebRipper") { Remove-Item -Recurse -Force ".\build\WebRipper" }
if (Test-Path ".\build\WebRipperRecon") { Remove-Item -Recurse -Force ".\build\WebRipperRecon" }
if (Test-Path ".\dist\WebRipper.exe") { Remove-Item -Force ".\dist\WebRipper.exe" }
if (Test-Path ".\dist\WebRipperRecon.exe") { Remove-Item -Force ".\dist\WebRipperRecon.exe" }

# Build
Write-Host "[3/4] Compiling standalone WebRipperRecon.exe (Console/Headless)..." -ForegroundColor Gray
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $pythonCmd -m PyInstaller WebRipper.spec --noconfirm
$ErrorActionPreference = $prevEAP

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  BUILD FAILED (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# Report
Write-Host "[4/4] Verifying binary package..." -ForegroundColor Gray
$exe = Get-Item ".\dist\WebRipperRecon.exe" -ErrorAction SilentlyContinue
if ($exe) {
    $sizeMB = [math]::Round($exe.Length / 1MB, 1)
    Write-Host ""
    Write-Host "  Build Successful!" -ForegroundColor Green
    Write-Host "  Output: $($exe.FullName)" -ForegroundColor White
    Write-Host "  Size:   $sizeMB MB" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  WARNING: Executable not found at expected path." -ForegroundColor Yellow
    Write-Host ""
}
