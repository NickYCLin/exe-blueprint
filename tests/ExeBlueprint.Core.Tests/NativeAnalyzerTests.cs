using System.ComponentModel;
using System.Diagnostics;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class NativeAnalyzerTests
{
    private const string EmptyOutputJson =
        "{\"schemaVersion\":1,\"functionCount\":0,\"functions\":[],\"truncated\":false}";

    private const string SingleFunctionOutputJson =
        "{\"schemaVersion\":1,\"functionCount\":1,\"functions\":[{\"name\":\"main\",\"address\":\"0x401000\",\"signature\":\"void main\",\"external\":false}],\"truncated\":false}";

    [Fact]
    public void ParsesVersionedGhidraFunctionJson()
    {
        const string json =
            "{\"schemaVersion\":1,\"functionCount\":2,\"functions\":["
            + "{\"name\":\"main\",\"address\":\"0x401000\",\"signature\":\"int main\",\"external\":false},"
            + "{\"name\":\"printf\",\"address\":\"EXTERNAL\",\"signature\":\"int printf\",\"external\":true}"
            + "],\"truncated\":false}";

        var parsed = GhidraOutputParser.Parse(json);

        Assert.True(parsed.IsValid);
        Assert.Null(parsed.Error);
        Assert.Equal(2, parsed.FunctionCount);
        Assert.Equal(2, parsed.Functions.Count);
        Assert.False(parsed.Truncated);
        Assert.Equal("main", parsed.Functions[0].Name);
        Assert.Equal("0x401000", parsed.Functions[0].Address);
        Assert.False(parsed.Functions[0].IsExternal);
        Assert.True(parsed.Functions[1].IsExternal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"schemaVersion\":1,\"functionCount\":0,\"functions\":3,\"truncated\":false}")]
    [InlineData("{\"schemaVersion\":1,\"functionCount\":1,\"functions\":[null],\"truncated\":false}")]
    [InlineData("{\"schemaVersion\":1,\"functionCount\":2,\"functions\":[],\"truncated\":false}")]
    [InlineData("{\"schemaVersion\":2,\"functionCount\":0,\"functions\":[],\"truncated\":false}")]
    public void RejectsMalformedOrWrongSchemaGhidraJson(string json)
    {
        var parsed = GhidraOutputParser.Parse(json);

        Assert.False(parsed.IsValid);
        Assert.NotNull(parsed.Error);
        Assert.Empty(parsed.Functions);
    }

    [Fact]
    public void BoundsGhidraJsonFunctionsAndStrings()
    {
        const string json =
            "{\"schemaVersion\":1,\"functionCount\":3,\"functions\":["
            + "{\"name\":\"abcdef\",\"address\":\"123456\",\"signature\":\"abcdef\",\"external\":false},"
            + "{\"name\":\"second\",\"address\":\"2\",\"signature\":\"second\",\"external\":false},"
            + "{\"name\":\"third\",\"address\":\"3\",\"signature\":\"third\",\"external\":true}"
            + "],\"truncated\":false}";

        var parsed = GhidraOutputParser.Parse(json, maxJsonChars: 2_000, maxFunctions: 2, maxStringChars: 4);

        Assert.True(parsed.IsValid);
        Assert.Equal(3, parsed.FunctionCount);
        Assert.Equal(2, parsed.Functions.Count);
        Assert.True(parsed.Truncated);
        Assert.Equal("abcd", parsed.Functions[0].Name);
        Assert.Equal("1234", parsed.Functions[0].Address);
        Assert.Equal("abcd", parsed.Functions[0].Signature);

        var oversized = GhidraOutputParser.Parse(json, maxJsonChars: 10, maxFunctions: 2, maxStringChars: 4);
        Assert.False(oversized.IsValid);
        Assert.Contains("安全上限", oversized.Error);

        var exporterTruncated = GhidraOutputParser.Parse(
            SingleFunctionOutputJson.Replace("\"truncated\":false", "\"truncated\":true", StringComparison.Ordinal));
        Assert.True(exporterTruncated.IsValid);
        Assert.True(exporterTruncated.Truncated);
    }

    [Fact]
    public async Task ReportsMissingOrNonExecutableBackend()
    {
        await using var temp = new TemporaryDirectory();
        var missing = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(Path.Combine(temp.Path, "missing")),
            CancellationToken.None);

        Assert.Equal("none", missing.Backend);
        Assert.Contains("Ghidra", missing.Note, StringComparison.Ordinal);

        if (!OperatingSystem.IsWindows())
        {
            var launcher = await WriteLauncherAsync(temp.Path, "#!/bin/sh\nexit 0\n", "@exit /b 0\r\n");
            File.SetUnixFileMode(launcher, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            Assert.Null(NativeAnalyzer.LocateHeadless(CreateOptions(temp.Path)));
        }
    }

    [Fact]
    public async Task ExtractsEmbeddedScriptIntoPrivateWorkspaceAndCleansIt()
    {
        await using var temp = new TemporaryDirectory();
        await WriteLauncherAsync(temp.Path, "#!/bin/sh\nexit 0\n", "@exit /b 0\r\n");
        string? workspace = null;

        var result = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            async (request, cancellationToken) =>
            {
                workspace = request.WorkspacePath;
                var scriptPath = Path.Combine(request.ScriptDirectory, request.ScriptName);
                Assert.True(File.Exists(scriptPath));
                var script = await File.ReadAllTextAsync(scriptPath, cancellationToken);
                Assert.Contains("schemaVersion", script, StringComparison.Ordinal);
                Assert.Contains("max_functions = 100000", script, StringComparison.Ordinal);
                Assert.Contains("max_json_chars = 24 * 1024 * 1024", script, StringComparison.Ordinal);
                if (!OperatingSystem.IsWindows())
                {
                    var mode = File.GetUnixFileMode(request.WorkspacePath);
                    Assert.Equal(
                        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                        mode & (UnixFileMode.UserRead
                                | UnixFileMode.UserWrite
                                | UnixFileMode.UserExecute
                                | UnixFileMode.GroupRead
                                | UnixFileMode.GroupWrite
                                | UnixFileMode.GroupExecute
                                | UnixFileMode.OtherRead
                                | UnixFileMode.OtherWrite
                                | UnixFileMode.OtherExecute));
                }

                await File.WriteAllTextAsync(request.OutputPath, SingleFunctionOutputJson, cancellationToken);
                return new GhidraRunResult(0, string.Empty, string.Empty);
            },
            CancellationToken.None);

        Assert.Equal("ghidra", result.Backend);
        Assert.Equal(1, result.FunctionCount);
        Assert.False(result.FunctionsTruncated);
        Assert.NotNull(workspace);
        Assert.False(Directory.Exists(workspace));
    }

    [Fact]
    public async Task RejectsNonzeroExitEvenWhenValidOutputExists()
    {
        await using var temp = new TemporaryDirectory();
        await WriteLauncherAsync(temp.Path, "#!/bin/sh\nexit 0\n", "@exit /b 0\r\n");
        var stderr = new string('x', 2_000) + " stderr-tail-sentinel";

        var result = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            async (request, cancellationToken) =>
            {
                await File.WriteAllTextAsync(request.OutputPath, SingleFunctionOutputJson, cancellationToken);
                return new GhidraRunResult(7, "stdout", stderr);
            },
            CancellationToken.None);

        Assert.Equal("none", result.Backend);
        Assert.Empty(result.Functions);
        Assert.Contains("exit code 7", result.Note, StringComparison.Ordinal);
        Assert.Contains("stderr-tail-sentinel", result.Note, StringComparison.Ordinal);
        Assert.True(result.Note!.Length < 1_100);
    }

    [Fact]
    public async Task ReportsMalformedAndOversizedOutputWithoutEscapingAnalyzer()
    {
        await using var temp = new TemporaryDirectory();
        await WriteLauncherAsync(temp.Path, "#!/bin/sh\nexit 0\n", "@exit /b 0\r\n");

        var malformed = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            async (request, cancellationToken) =>
            {
                await File.WriteAllTextAsync(request.OutputPath, "{", cancellationToken);
                return new GhidraRunResult(0, string.Empty, string.Empty);
            },
            CancellationToken.None);
        Assert.Equal("none", malformed.Backend);
        Assert.Contains("JSON", malformed.Note, StringComparison.Ordinal);

        var invalidUtf8 = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            async (request, cancellationToken) =>
            {
                await File.WriteAllBytesAsync(request.OutputPath, [0xff, 0xfa, 0xfb], cancellationToken);
                return new GhidraRunResult(0, string.Empty, string.Empty);
            },
            CancellationToken.None);
        Assert.Equal("none", invalidUtf8.Backend);
        Assert.Contains("Ghidra 分析失敗", invalidUtf8.Note, StringComparison.Ordinal);

        var oversized = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            (request, _) =>
            {
                using var output = new FileStream(request.OutputPath, FileMode.CreateNew, FileAccess.Write);
                output.SetLength((long)GhidraOutputParser.MaxJsonBytes + 1);
                return Task.FromResult(new GhidraRunResult(0, string.Empty, string.Empty));
            },
            CancellationToken.None);
        Assert.Equal("none", oversized.Backend);
        Assert.Contains("安全上限", oversized.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidatesTimeoutAndHandlesProcessStartFailure()
    {
        await using var temp = new TemporaryDirectory();
        await WriteLauncherAsync(temp.Path, "#!/bin/sh\nexit 0\n", "@exit /b 0\r\n");
        var invoked = false;

        var invalidTimeout = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path, timeoutMs: 0),
            (_, _) =>
            {
                invoked = true;
                return Task.FromResult(new GhidraRunResult(0, string.Empty, string.Empty));
            },
            CancellationToken.None);
        Assert.Equal("none", invalidTimeout.Backend);
        Assert.Contains("大於 0", invalidTimeout.Note, StringComparison.Ordinal);
        Assert.False(invoked);

        var startFailure = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            (_, _) => throw new Win32Exception(2, "launcher sentinel"),
            CancellationToken.None);
        Assert.Equal("none", startFailure.Backend);
        Assert.Contains("launcher sentinel", startFailure.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RealLauncherDrainsFloodedStdoutAndStderr()
    {
        await using var temp = new TemporaryDirectory();
        var outputChunk = new string('O', 512);
        var errorChunk = new string('E', 512);
        var unixScript =
            "#!/bin/sh\n"
            + "[ -f \"$4\" ] || exit 8\n"
            + "[ -f \"$6/$8\" ] || exit 9\n"
            + "i=0\n"
            + "while [ \"$i\" -lt 512 ]; do\n"
            + $"  printf '%s' '{outputChunk}'\n"
            + $"  printf '%s' '{errorChunk}' >&2\n"
            + "  i=$((i + 1))\n"
            + "done\n"
            + $"printf '%s' '{SingleFunctionOutputJson}' > \"$9\"\n";
        var windowsScript =
            "@echo off\r\n"
            + "if not exist \"%~4\" exit /b 8\r\n"
            + "if not exist \"%~6\\%~8\" exit /b 9\r\n"
            + $"for /L %%i in (1,1,512) do @echo {outputChunk}\r\n"
            + $"for /L %%i in (1,1,512) do @echo {errorChunk} 1>&2\r\n"
            + $"> \"%~9\" echo {SingleFunctionOutputJson}\r\n"
            + "exit /b 0\r\n";
        var installDir = Path.Combine(temp.Path, "Ghidra & (Test)^");
        await WriteLauncherAsync(installDir, unixScript, windowsScript);
        var inputPath = Path.Combine(temp.Path, "input & symbols^.dll");
        File.Copy(typeof(NativeAnalyzer).Assembly.Location, inputPath);

        var stopwatch = Stopwatch.StartNew();
        var result = await NativeAnalyzer.AnalyzeAsync(
            inputPath,
            CreateOptions(installDir, timeoutMs: 10_000),
            CancellationToken.None);
        stopwatch.Stop();

        Assert.Equal("ghidra", result.Backend);
        Assert.Equal("main", Assert.Single(result.Functions).Name);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData("input %PATH%.dll")]
    [InlineData("input !PATH!.dll")]
    public async Task WindowsBatchSafelyRejectsExpansionCharactersInPath(string fileName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        await using var temp = new TemporaryDirectory();
        await WriteLauncherAsync(
            temp.Path,
            "#!/bin/sh\nexit 0\n",
            $"@echo off\r\n> \"%~9\" echo {EmptyOutputJson}\r\nexit /b 0\r\n");
        var inputPath = Path.Combine(temp.Path, fileName);
        File.Copy(typeof(NativeAnalyzer).Assembly.Location, inputPath);

        var result = await NativeAnalyzer.AnalyzeAsync(
            inputPath,
            CreateOptions(temp.Path),
            CancellationToken.None);

        Assert.Equal("none", result.Backend);
        Assert.Contains("無法安全處理", result.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RealLauncherPreservesNonzeroExitWhenOutputExists()
    {
        await using var temp = new TemporaryDirectory();
        var unixScript =
            "#!/bin/sh\n"
            + $"printf '%s' '{SingleFunctionOutputJson}' > \"$9\"\n"
            + "printf '%s' adapter-exit-sentinel >&2\n"
            + "exit 7\n";
        var windowsScript =
            "@echo off\r\n"
            + $"> \"%~9\" echo {SingleFunctionOutputJson}\r\n"
            + "echo adapter-exit-sentinel 1>&2\r\n"
            + "exit /b 7\r\n";
        await WriteLauncherAsync(temp.Path, unixScript, windowsScript);

        var result = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path),
            CancellationToken.None);

        Assert.Equal("none", result.Backend);
        Assert.Empty(result.Functions);
        Assert.Contains("exit code 7", result.Note, StringComparison.Ordinal);
        Assert.Contains("adapter-exit-sentinel", result.Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RealLauncherTimeoutKillsProcessBeforeReturning()
    {
        await using var temp = new TemporaryDirectory();
        var unixScript = "#!/bin/sh\nsleep 5\n";
        // 測試執行器的 PATH 有可能被精簡；用 SystemRoot 下的絕對路徑避免把環境差異誤判成逾時邏輯失敗。
        var windowsScript = "@echo off\r\n\"%SystemRoot%\\System32\\PING.EXE\" 127.0.0.1 -n 6 >nul\r\n";
        await WriteLauncherAsync(temp.Path, unixScript, windowsScript);

        var stopwatch = Stopwatch.StartNew();
        var result = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path, timeoutMs: 200),
            CancellationToken.None);
        stopwatch.Stop();

        Assert.Equal("none", result.Backend);
        Assert.Contains("逾時", result.Note, StringComparison.Ordinal);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(4));
    }

    [Fact]
    public async Task BackgroundPipeHolderCannotBlockAnalyzerIndefinitely()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await using var temp = new TemporaryDirectory();
        var workspaceMarker = Path.Combine(temp.Path, "unsafe-workspace.txt");
        var unixScript =
            "#!/bin/sh\n"
            + $"printf '%s' \"$1\" > '{workspaceMarker}'\n"
            + "( sleep 5 ) &\n"
            + $"printf '%s' '{EmptyOutputJson}' > \"$9\"\n"
            + "exit 0\n";
        await WriteLauncherAsync(temp.Path, unixScript, "@exit /b 0\r\n");

        var stopwatch = Stopwatch.StartNew();
        var result = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path, timeoutMs: 10_000),
            CancellationToken.None);
        stopwatch.Stop();

        Assert.Equal("none", result.Backend);
        Assert.Contains("輸出管線", result.Note, StringComparison.Ordinal);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5));
        var workspace = (await File.ReadAllTextAsync(workspaceMarker)).Trim();
        Assert.True(Directory.Exists(workspace));
        await Task.Delay(3_000);
        if (Directory.Exists(workspace))
        {
            Directory.Delete(workspace, recursive: true);
        }
    }

    [Fact]
    public async Task CallerCancellationKillsDescendantAndCleansWorkspace()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await using var temp = new TemporaryDirectory();
        var workspaceMarker = Path.Combine(temp.Path, "workspace.txt");
        var descendantMarker = Path.Combine(temp.Path, "descendant.txt");
        var unixScript =
            "#!/bin/sh\n"
            + $"( sleep 1; printf child > '{descendantMarker}' ) &\n"
            + $"printf '%s' \"$1\" > '{workspaceMarker}'\n"
            + "sleep 5\n";
        await WriteLauncherAsync(temp.Path, unixScript, "@exit /b 0\r\n");
        using var cancellation = new CancellationTokenSource();

        var analysis = NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            CreateOptions(temp.Path, timeoutMs: 10_000),
            cancellation.Token);
        await WaitForFileAsync(workspaceMarker);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis);

        Assert.True(File.Exists(workspaceMarker));
        var workspace = (await File.ReadAllTextAsync(workspaceMarker)).Trim();
        Assert.False(Directory.Exists(workspace));
        await Task.Delay(1_200);
        Assert.False(File.Exists(descendantMarker));
    }

    private static async Task WaitForFileAsync(string path)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!File.Exists(path))
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    private static AnalysisOptions CreateOptions(string installDir, int timeoutMs = 5_000) => new()
    {
        EnableNativeAnalysis = true,
        GhidraInstallDir = installDir,
        NativeAnalysisTimeoutMs = timeoutMs
    };

    private static async Task<string> WriteLauncherAsync(
        string installDir,
        string unixScript,
        string windowsScript)
    {
        var supportDir = Path.Combine(installDir, "support");
        Directory.CreateDirectory(supportDir);
        var launcher = Path.Combine(
            supportDir,
            OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless");
        await File.WriteAllTextAsync(launcher, OperatingSystem.IsWindows() ? windowsScript : unixScript);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                launcher,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        return launcher;
    }

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }
}
