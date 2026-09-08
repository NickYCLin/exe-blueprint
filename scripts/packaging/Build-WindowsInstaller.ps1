[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,
    [string] $StageDirectory,
    [string] $Version,
    [string] $CompilerPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows 安裝程式必須在 Windows 建置。'
}
if (-not $Version) {
    [xml] $props = [IO.File]::ReadAllText((Join-Path $repoRoot 'Directory.Build.props'))
    $Version = [string] $props.Project.PropertyGroup.Version
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw '版本格式必須是 major.minor.patch。'
}

if (-not $CompilerPath) {
    $compilerCommand = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($compilerCommand) {
        $CompilerPath = $compilerCommand.Source
    }
    else {
        $CompilerPath = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
    }
}
if (-not (Test-Path -LiteralPath $CompilerPath -PathType Leaf)) {
    throw '找不到 Inno Setup 6.3 以上的 ISCC.exe；請用 -CompilerPath 指定。'
}
# ISCC.exe 本身的檔案版本不等於 Inno Setup 產品版本；由編譯器檢查腳本需要的功能。

$outputDir = [IO.Path]::GetFullPath($OutputDirectory)
$installerPath = Join-Path $outputDir "ExeBlueprint-v$Version-win-x64-setup.exe"
if (Test-Path -LiteralPath $installerPath) {
    throw "安裝程式已存在，請改用新的輸出目錄：$installerPath"
}
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

if (-not $StageDirectory) {
    $desktopDir = Join-Path $outputDir 'publish-desktop'
    $cliDir = Join-Path $outputDir 'publish-cli'
    $StageDirectory = Join-Path $outputDir 'stage'
    if (Test-Path -LiteralPath $StageDirectory) {
        throw "打包目錄已存在，請改用新的輸出目錄：$StageDirectory"
    }
    & dotnet publish (Join-Path $repoRoot 'src\ExeBlueprint.Desktop') -c Release -r win-x64 `
        --self-contained true "-p:Version=$Version" -p:PublishSingleFile=false `
        -p:DebugSymbols=false -p:DebugType=None -o $desktopDir | Out-Host
    if ($LASTEXITCODE -ne 0) { throw '桌面版 publish 失敗。' }
    & dotnet publish (Join-Path $repoRoot 'src\ExeBlueprint.Cli') -c Release -r win-x64 `
        --self-contained true "-p:Version=$Version" -p:PublishSingleFile=true `
        -p:DebugSymbols=false -p:DebugType=None -o $cliDir | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'CLI publish 失敗。' }
    New-Item -ItemType Directory -Path $StageDirectory | Out-Null
    Copy-Item -Path (Join-Path $desktopDir '*') -Destination $StageDirectory -Recurse
    Copy-Item -LiteralPath (Join-Path $cliDir 'exe-blueprint.exe') `
        -Destination (Join-Path $StageDirectory 'exe-blueprint-cli.exe')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'packaging\README-desktop.txt') `
        -Destination (Join-Path $StageDirectory 'README.txt')
}
$stageDir = (Resolve-Path -LiteralPath $StageDirectory).Path
foreach ($requiredFile in @('ExeBlueprint.exe', 'ExeBlueprint.dll', 'ExeBlueprint.runtimeconfig.json',
    'exe-blueprint-cli.exe', 'coreclr.dll', 'README.txt')) {
    if (-not (Test-Path -LiteralPath (Join-Path $stageDir $requiredFile) -PathType Leaf)) {
        throw "打包目錄缺少 $requiredFile。"
    }
}

# 固定官方 repository 的翻譯版本與雜湊，不使用會隨時間變動的下載內容。
$buildInputs = Join-Path $outputDir 'build-inputs'
New-Item -ItemType Directory -Path $buildInputs -Force | Out-Null
$languagePath = Join-Path $buildInputs 'ChineseTraditional.isl'
$languageUrl = 'https://raw.githubusercontent.com/jrsoftware/issrc/is-6_7_1/Files/Languages/Unofficial/ChineseTraditional.isl'
Invoke-WebRequest -UseBasicParsing -Uri $languageUrl -OutFile $languagePath
$languageHash = (Get-FileHash -LiteralPath $languagePath -Algorithm SHA256).Hash
if ($languageHash -ne 'AB22B0EBF82969D1C9A7208E0E9F60E5119C0C95B9DACC00EB8E5582C7D3C604') {
    throw '繁體中文語系檔的 SHA-256 不符。'
}

& $CompilerPath "/DAppVersion=$Version" "/DStageDir=$stageDir" "/DChineseMessages=$languagePath" `
    "/O$outputDir" (Join-Path $repoRoot 'packaging\windows\ExeBlueprint.iss') | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw 'Inno Setup 編譯失敗。'
}
Write-Output $installerPath
