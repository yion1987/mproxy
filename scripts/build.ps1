Param(
    [string]$Name = "mproxy"
)

Write-Host "准备生成程序图标并打包可执行文件..." -ForegroundColor Cyan

# Ensure assets directory
if (-not (Test-Path "assets")) {
    New-Item -ItemType Directory -Path "assets" | Out-Null
}

# Generate a simple .ico using .NET System.Drawing
Add-Type -AssemblyName System.Drawing

# Larger size for clearer icon; background fully transparent
$size = 256
$bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Transparent background
$gfx.Clear([System.Drawing.Color]::FromArgb(0,0,0,0))

# Colors
$primaryColor = [System.Drawing.ColorTranslator]::FromHtml("#2D7FFF")
$accentColor  = [System.Drawing.ColorTranslator]::FromHtml("#FFFFFF")

# Outer ring to suggest network/proxy
$ringThickness = 18
$ringRect = New-Object System.Drawing.Rectangle -ArgumentList 20, 20, ($size - 40), ($size - 40)
$ringPen = New-Object System.Drawing.Pen -ArgumentList $primaryColor, $ringThickness
$ringPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$gfx.DrawEllipse($ringPen, $ringRect)

# Proxy path: line with rounded caps and arrow head
$linePen = New-Object System.Drawing.Pen -ArgumentList $accentColor, 14
$linePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$linePen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round

$cx = [int]($size/2)
$cy = [int]($size/2)
$x1 = [int]($size*0.28)
$x2 = [int]($size*0.72)
$gfx.DrawLine($linePen, (New-Object System.Drawing.Point -ArgumentList $x1, $cy), (New-Object System.Drawing.Point -ArgumentList $x2, $cy))

# Arrow head pointing to the right
$arrowLen = [int]($size*0.06)
$arrowTip = New-Object System.Drawing.Point -ArgumentList $x2, $cy
$arrowP1  = New-Object System.Drawing.Point -ArgumentList ($x2 - $arrowLen), ($cy - $arrowLen)
$arrowP2  = New-Object System.Drawing.Point -ArgumentList ($x2 - $arrowLen), ($cy + $arrowLen)
$whiteBrush = New-Object System.Drawing.SolidBrush($accentColor)
$gfx.FillPolygon($whiteBrush, @($arrowTip, $arrowP1, $arrowP2))

# Nodes to represent endpoints
$nodeBrush = New-Object System.Drawing.SolidBrush($primaryColor)
$nodeR = 16
$nodeRectL = New-Object System.Drawing.Rectangle -ArgumentList ($x1 - $nodeR), ($cy - $nodeR), (2*$nodeR), (2*$nodeR)
$nodeRectR = New-Object System.Drawing.Rectangle -ArgumentList ($x2 - $nodeR), ($cy - $nodeR), (2*$nodeR), (2*$nodeR)
$gfx.FillEllipse($nodeBrush, $nodeRectL)
$gfx.FillEllipse($nodeBrush, $nodeRectR)

# Save to .ico
$hIcon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)
$fs = [System.IO.File]::Open("assets/icon.ico", [System.IO.FileMode]::Create)
$icon.Save($fs)
$fs.Close()
$whiteBrush.Dispose()
$nodeBrush.Dispose()
$ringPen.Dispose()
$linePen.Dispose()
$gfx.Dispose()
$bmp.Dispose()

Write-Host "已生成 assets/icon.ico" -ForegroundColor Green

# Resolve venv tools (PowerShell 5 compatible)
$venvScripts = Resolve-Path ".\.venv\Scripts" -ErrorAction SilentlyContinue
$venvScriptsPath = $null
if ($venvScripts) {
    if ($venvScripts -is [System.Array]) {
        $venvScriptsPath = $venvScripts[0].Path
    } else {
        $venvScriptsPath = $venvScripts.Path
    }
} else {
    Write-Warning "未找到 .venv\Scripts，将尝试使用系统 Python 环境。"
}

if ($venvScriptsPath) {
    $pipCandidate = Join-Path $venvScriptsPath "pip.exe"
} else {
    $pipCandidate = $null
}
if ($pipCandidate -and (Test-Path $pipCandidate)) {
    $pip = $pipCandidate
} else {
    $pip = "pip"
}

# Ensure pyinstaller is installed
Write-Host "检查并安装 pyinstaller..." -ForegroundColor Cyan
try {
    & $pip install pyinstaller | Out-Host
} catch {
    Write-Warning "安装 pyinstaller 失败，请手动安装后重试。"
}

# Resolve pyinstaller executable
if ($venvScriptsPath) {
    $pyinstallerExeCandidate = Join-Path $venvScriptsPath "pyinstaller.exe"
} else {
    $pyinstallerExeCandidate = $null
}
if ($pyinstallerExeCandidate -and (Test-Path $pyinstallerExeCandidate)) {
    $pyinstallerExe = $pyinstallerExeCandidate
} else {
    $pyinstallerExe = "pyinstaller"
}

Write-Host "开始打包..." -ForegroundColor Cyan
# 使用 --noconfirm 避免交互确认，--clean 清理缓存，--onefile 单一可执行文件
# 若存在旧的 .spec 文件，可能覆盖 CLI 选项，先删除以确保 --onefile 生效
if (Test-Path ".\mproxy.spec") {
    Remove-Item ".\mproxy.spec" -Force -ErrorAction SilentlyContinue
}
& $pyinstallerExe --noconsole --windowed --noconfirm --clean --onefile --icon assets\icon.ico --name $Name main.py

# 输出位置（单文件）：dist\$Name.exe
Write-Host "打包完成。可执行文件在 dist/$Name.exe" -ForegroundColor Green