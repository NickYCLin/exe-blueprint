param(
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][string] $FixtureAssembly,
    [ValidateRange(1, 1000)][int] $ProjectCount = 1000,
    [ValidateRange(0, 10)][int] $SourceFilesPerProject = 10,
    [ValidateRange(1, 1000)][int] $AssemblyCount = 1000,
    [string] $ExistingInputDirectory
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$cliPath = Join-Path $repositoryRoot 'src\ExeBlueprint.Cli\bin\Release\net10.0\exe-blueprint.dll'
$fixturePath = (Resolve-Path -LiteralPath $FixtureAssembly).Path
$evidenceRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $evidenceRoot) { throw 'Use a new output directory.' }
if (-not (Test-Path -LiteralPath $cliPath)) { throw 'Build the Release configuration first.' }
[IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
$inputRoot = if ($ExistingInputDirectory) { (Resolve-Path -LiteralPath $ExistingInputDirectory).Path } else { $evidenceRoot }
$sourceRoot = Join-Path $inputRoot 'source-input'
$binaryRoot = Join-Path $inputRoot 'binary-input'
$encoding = New-Object Text.UTF8Encoding($false)
if (-not $ExistingInputDirectory) {
[IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
[IO.Directory]::CreateDirectory($binaryRoot) | Out-Null
$solution = New-Object Text.StringBuilder
[void] $solution.Append('<Solution>')
for ($index = 0; $index -lt $ProjectCount; $index++) {
    $name = 'P{0:D4}' -f $index
    $projectDirectory = Join-Path $sourceRoot $name
    [IO.Directory]::CreateDirectory($projectDirectory) | Out-Null
    [void] $solution.Append(('<Project Path="{0}/{0}.csproj"/>' -f $name))
    $reference = ''
    if ($index -gt 0) {
        $previous = 'P{0:D4}' -f ($index - 1)
        $reference = '<ItemGroup><ProjectReference Include="../{0}/{0}.csproj"/></ItemGroup>' -f $previous
    }
    [IO.File]::WriteAllText((Join-Path $projectDirectory ($name + '.csproj')),
        ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>{0}</Project>' -f $reference), $encoding)
    for ($file = 0; $file -lt $SourceFilesPerProject; $file++) {
        [IO.File]::WriteAllText((Join-Path $projectDirectory ('C' + $file + '.cs')),
            ('namespace {0}; public class C{1} {{ public int Add(int x, int y) => x + y; }}' -f $name, $file), $encoding)
    }
}
[void] $solution.Append('</Solution>')
[IO.File]::WriteAllText((Join-Path $sourceRoot 'Large.slnx'), $solution.ToString(), $encoding)
for ($index = 0; $index -lt $AssemblyCount; $index++) {
    $assemblyDirectory = Join-Path $binaryRoot ('deployment-{0:D4}' -f $index)
    [IO.Directory]::CreateDirectory($assemblyDirectory) | Out-Null
    [IO.File]::Copy($fixturePath, (Join-Path $assemblyDirectory 'Fixture.dll'))
}
}

$measurements = @()
foreach ($case in @(
    @{ Name = 'source'; Input = (Join-Path $sourceRoot 'Large.slnx'); Files = 1 + $ProjectCount * (1 + $SourceFilesPerProject) },
    @{ Name = 'binary'; Input = $binaryRoot; Files = $AssemblyCount }
)) {
    $caseOutput = Join-Path $evidenceRoot ($case.Name + '-output')
    $arguments = @(('"' + $cliPath + '"'), 'analyze', ('"' + $case.Input + '"'), '--inventory', '-o', ('"' + $caseOutput + '"'))
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath (Get-Command dotnet).Source -ArgumentList ($arguments -join ' ') `
        -RedirectStandardOutput (Join-Path $evidenceRoot ($case.Name + '.stdout.log')) `
        -RedirectStandardError (Join-Path $evidenceRoot ($case.Name + '.stderr.log')) `
        -PassThru -WindowStyle Hidden
    # Hold the process handle so Windows PowerShell retains ExitCode after Refresh.
    $processHandle = $process.Handle
    $peakBytes = 0L
    while (-not $process.HasExited) {
        $process.Refresh()
        if (-not $process.HasExited) { $peakBytes = [Math]::Max($peakBytes, $process.PeakWorkingSet64) }
        [Threading.Thread]::Sleep(50)
    }
    $process.WaitForExit()
    $watch.Stop()
    if ($null -eq $process.ExitCode) { throw 'Process exit code unavailable; measurement is incomplete.' }
    if ($process.ExitCode -ne 0) { throw ($case.Name + ' CLI failed; inspect the saved logs.') }
    $document = Get-Content -LiteralPath (Join-Path $caseOutput 'blueprint.json') -Encoding UTF8 -Raw | ConvertFrom-Json
    if ($document.schemaVersion -ne '0.20' -or $document.analysisMode -ne 'inventory') { throw 'Unexpected result contract.' }
    if ($document.input.fileCount -ne $case.Files) { throw 'Input file count mismatch.' }
    if ($document.projectGraph.truncated) { throw 'Unexpected truncated project graph.' }
    if ($case.Name -eq 'source') {
        if ($document.projectGraph.components.Count -ne $ProjectCount + 1 -or
            $document.projectGraph.references.Count -ne 2 * $ProjectCount - 1) { throw 'Source graph count mismatch.' }
        if ($document.projectGraph.references | Where-Object status -NE 'resolved') { throw 'Unresolved source reference.' }
    }
    else {
        if ($document.summary.managedAssemblyCount -ne $AssemblyCount) { throw 'Managed assembly count mismatch.' }
        if ($document.files | Where-Object { $null -ne $_.code }) { throw 'Inventory unexpectedly read method bodies.' }
    }
    $measurements += [PSCustomObject]@{
        case = $case.Name
        files = $document.input.fileCount
        components = $document.projectGraph.components.Count
        references = $document.projectGraph.references.Count
        elapsedSeconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
        observedPeakWorkingSetMiB = [Math]::Round($peakBytes / 1MB, 1)
        reportBytes = (Get-Item -LiteralPath (Join-Path $caseOutput 'REPORT.md')).Length
        jsonBytes = (Get-Item -LiteralPath (Join-Path $caseOutput 'blueprint.json')).Length
        status = 'passed'
    }
}
$result = [PSCustomObject]@{
    measuredAt = (Get-Date -Format o)
    commit = (git -C $repositoryRoot rev-parse HEAD)
    sourceHasUncommittedChanges = [bool](git -C $repositoryRoot status --porcelain)
    os = [Environment]::OSVersion.VersionString
    processorCount = [Environment]::ProcessorCount
    fixtureSha256 = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    limitation = 'Synthetic source projects and repeated copies of one owned assembly; inventory only, not semantic source analysis or full IL reconstruction.'
    measurements = $measurements
}
$json = $result | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $evidenceRoot 'acceptance.json'), $json, $encoding)
$json
