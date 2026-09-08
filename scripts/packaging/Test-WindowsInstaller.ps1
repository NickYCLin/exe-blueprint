[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $InstallerPath,
    [Parameter(Mandatory = $true)] [string] $PreviousInstallerPath,
    [Parameter(Mandatory = $true)] [string] $StageDirectory,
    [Parameter(Mandatory = $true)] [string] $ExpectedVersion,
    [Parameter(Mandatory = $true)] [string] $EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
# 這項驗收會寫入解除安裝登錄與捷徑，只允許在拋棄式 GitHub runner 執行。
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw '安裝／移除驗收僅能在 GitHub Actions 的 Windows runner 執行。'
}
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ExeBlueprint.Desktop_is1'
if (Test-Path -LiteralPath $registryPath) {
    throw 'runner 已有 ExeBlueprint 安裝紀錄，停止測試以免影響既有安裝。'
}
$evidenceDir = [IO.Path]::GetFullPath($EvidenceDirectory)
$runnerRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $evidenceDir.StartsWith($runnerRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw '驗收目錄必須位於 RUNNER_TEMP 內。'
}
$installDir = Join-Path $evidenceDir 'installed app'
if (Test-Path -LiteralPath $installDir) {
    throw '測試安裝目錄已存在。'
}
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
$programsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
$shortcutPath = Join-Path $programsDir 'ExeBlueprint\ExeBlueprint.lnk'
if (Test-Path -LiteralPath $shortcutPath) {
    throw 'runner 已有 ExeBlueprint 捷徑，停止測試。'
}

function Invoke-Installer([string] $Path, [string] $LogName) {
    $logPath = Join-Path $evidenceDir $LogName
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
        '/NOCLOSEAPPLICATIONS', '/NORESTARTAPPLICATIONS', '/LANG=zh-TW',
        ('/DIR="' + $installDir + '"'), ('/LOG="' + $logPath + '"'))
    $process = Start-Process -FilePath $Path -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "安裝程式結束碼為 $($process.ExitCode)，請查看 $logPath。" }
}

Invoke-Installer (Resolve-Path -LiteralPath $PreviousInstallerPath).Path 'install.log'
if ((Get-ItemProperty -LiteralPath $registryPath).DisplayVersion -ne '0.0.0') {
    throw '初次安裝版本登錄不符。'
}
if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
    throw '初次安裝沒有建立開始功能表捷徑。'
}
$userDataDir = Join-Path $installDir 'user-data'
New-Item -ItemType Directory -Path $userDataDir | Out-Null
$userData = Join-Path $userDataDir 'keep.txt'
[IO.File]::WriteAllText($userData, 'preserve-after-uninstall')
[IO.File]::WriteAllText((Join-Path $installDir 'README.txt'), 'previous-installation')

Invoke-Installer (Resolve-Path -LiteralPath $InstallerPath).Path 'upgrade.log'
$installed = Get-ItemProperty -LiteralPath $registryPath
if ($installed.DisplayVersion -ne $ExpectedVersion -or
    $installed.InstallLocation.TrimEnd('\') -ne $installDir.TrimEnd('\')) {
    throw '升級後的版本或安裝目錄登錄不符。'
}
$stageDir = (Resolve-Path -LiteralPath $StageDirectory).Path.TrimEnd('\')
$payload = @(Get-ChildItem -LiteralPath $stageDir -Recurse -File)
foreach ($sourceFile in $payload) {
    $relativePath = $sourceFile.FullName.Substring($stageDir.Length + 1)
    $installedFile = Join-Path $installDir $relativePath
    if (-not (Test-Path -LiteralPath $installedFile -PathType Leaf) -or
        (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $installedFile -Algorithm SHA256).Hash) {
        throw "升級後的檔案內容不符：$relativePath"
    }
}
$version = & (Join-Path $installDir 'exe-blueprint-cli.exe') --version
if ($LASTEXITCODE -ne 0 -or $version.Trim() -ne $ExpectedVersion) {
    throw '安裝後的 CLI 版本驗證失敗。'
}
if ([IO.File]::ReadAllText($userData) -ne 'preserve-after-uninstall') {
    throw '升級覆寫了非安裝檔案。'
}

$uninstallerPath = Join-Path $installDir 'unins000.exe'
if (-not (Test-Path -LiteralPath $uninstallerPath -PathType Leaf) -or
    -not $installed.UninstallString.StartsWith(('"' + $uninstallerPath + '"'), [StringComparison]::OrdinalIgnoreCase)) {
    throw '解除安裝程式不在預期的測試目錄。'
}
$uninstallLog = Join-Path $evidenceDir 'uninstall.log'
$process = Start-Process -FilePath $uninstallerPath -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES',
    '/NORESTART', ('/LOG="' + $uninstallLog + '"')) -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "移除失敗：$($process.ExitCode)" }
if ((Test-Path -LiteralPath $registryPath) -or (Test-Path -LiteralPath $shortcutPath)) {
    throw '移除後仍有登錄或捷徑。'
}
foreach ($sourceFile in $payload) {
    $relativePath = $sourceFile.FullName.Substring($stageDir.Length + 1)
    if (Test-Path -LiteralPath (Join-Path $installDir $relativePath)) {
        throw "移除後仍有安裝檔案：$relativePath"
    }
}
if ([IO.File]::ReadAllText($userData) -ne 'preserve-after-uninstall') {
    throw '移除時刪除了非安裝檔案。'
}
$summary = [ordered] @{
    previousInstallerVersion = '0.0.0'
    installedVersion = $ExpectedVersion
    installerSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    verifiedPayloadFiles = $payload.Count
    cliVersionVerified = $true
    upgradeVerified = $true
    uninstallVerified = $true
    userFilesPreserved = $true
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidenceDir 'acceptance.json') -Encoding UTF8
$summary | ConvertTo-Json
