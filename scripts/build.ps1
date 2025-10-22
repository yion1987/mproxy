# Build script for mproxy
# Usage: .\scripts\build.ps1

Param(
    [string]$Name = "mproxy"
)

# Set UTF-8 encoding for console output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "[1/3] Building mproxy.exe..." -ForegroundColor Cyan

# Check if icon exists
if (-not (Test-Path "assets\icon.ico")) {
    Write-Host "Error: Icon file not found at assets\icon.ico" -ForegroundColor Red
    exit 1
}

# Find Python/PyInstaller
$pyinstaller = $null

# Try venv first
if (Test-Path ".venv\Scripts\pyinstaller.exe") {
    $pyinstaller = ".venv\Scripts\pyinstaller.exe"
} elseif (Get-Command pyinstaller -ErrorAction SilentlyContinue) {
    $pyinstaller = "pyinstaller"
} else {
    Write-Host "Error: PyInstaller not found. Install it with: pip install pyinstaller" -ForegroundColor Red
    exit 1
}

Write-Host "[2/3] Running PyInstaller..." -ForegroundColor Cyan

# Build single executable
& $pyinstaller --noconfirm --clean --onefile `
    --noconsole `
    --icon="assets\icon.ico" `
    --name=$Name `
    --add-data="assets\icon.ico;assets" `
    --hidden-import=pystray._win32 `
    --hidden-import=PIL._tkinter_finder `
    main.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[3/3] Build complete!" -ForegroundColor Green
Write-Host "Output: dist\$Name.exe" -ForegroundColor Yellow
