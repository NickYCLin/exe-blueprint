using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 用 Ghidra headless 分析原生 PE，抽出函式清單。
// 找不到 Ghidra 或執行失敗時不會讓分析失敗，只回傳帶註記的結果（Backend="none"）。
internal static class NativeAnalyzer
{
    private const string ExportScriptResourceName = "ExeBlueprint.Analysis.ExportFunctions.py";
    private const int MaxProcessOutputTailChars = 16_384;
    private const int MaxDiagnosticChars = 1_000;
    private static readonly TimeSpan ProcessExitGrace = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan OutputDrainGrace = TimeSpan.FromSeconds(2);
    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static string? LocateHeadless(AnalysisOptions options)
    {
        var installDir = options.GhidraInstallDir ?? Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
        if (string.IsNullOrWhiteSpace(installDir))
        {
            return null;
        }

        var executable = OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless";
        var path = Path.Combine(installDir, "support", executable);
        if (!File.Exists(path))
        {
            return null;
        }

        if (!OperatingSystem.IsWindows())
        {
            try
            {
                var mode = File.GetUnixFileMode(path);
                const UnixFileMode executeBits =
                    UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
                if ((mode & executeBits) == 0)
                {
                    return null;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        return path;
    }

    public static async Task<NativeCodeModel> AnalyzeAsync(
        string filePath,
        AnalysisOptions options,
        CancellationToken cancellationToken) =>
        await AnalyzeAsync(filePath, options, RunHeadlessAsync, cancellationToken).ConfigureAwait(false);

    internal static async Task<NativeCodeModel> AnalyzeAsync(
        string filePath,
        AnalysisOptions options,
        GhidraProcessRunner processRunner,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (options.NativeAnalysisTimeoutMs <= 0)
        {
            return Failure("Ghidra 分析逾時必須大於 0 毫秒。");
        }

        var headless = LocateHeadless(options);
        if (headless is null)
        {
            return Failure(
                "未偵測到可執行的 Ghidra headless，原生 PE 未做函式分析。設定 GHIDRA_INSTALL_DIR 或用 --ghidra 指定安裝目錄即可啟用。");
        }

        string? workspace = null;
        try
        {
            workspace = Directory.CreateTempSubdirectory("exe-blueprint-ghidra-").FullName;
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    workspace,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            var scriptPath = Path.Combine(workspace, "ExportFunctions.py");
            var outputPath = Path.Combine(workspace, "functions.json");
            await WriteExportScriptAsync(scriptPath, cancellationToken).ConfigureAwait(false);

            var run = await processRunner(
                    new GhidraRunRequest(
                        headless,
                        workspace,
                        filePath,
                        Path.GetDirectoryName(scriptPath)!,
                        Path.GetFileName(scriptPath),
                        outputPath,
                        options.NativeAnalysisTimeoutMs),
                    cancellationToken)
                .ConfigureAwait(false);

            if (run.ExitCode != 0)
            {
                var diagnostic = FormatDiagnostic(run.StandardErrorTail, run.StandardOutputTail);
                return Failure($"Ghidra 執行失敗（exit code {run.ExitCode}）{diagnostic}");
            }

            if (!File.Exists(outputPath))
            {
                return Failure("Ghidra 執行成功但未產生 functions.json。");
            }

            var json = await ReadOutputJsonAsync(outputPath, cancellationToken).ConfigureAwait(false);
            var parsed = GhidraOutputParser.Parse(json);
            if (!parsed.IsValid)
            {
                return Failure(parsed.Error ?? "Ghidra JSON 輸出無法解析。");
            }

            return new NativeCodeModel
            {
                Backend = "ghidra",
                FunctionCount = parsed.FunctionCount,
                Functions = parsed.Functions,
                FunctionsTruncated = parsed.Truncated,
                Note = parsed.Truncated ? "Ghidra 函式輸出已達安全保留上限，結果已截斷。" : null
            };
        }
        catch (GhidraUnsafeCleanupException exception)
        {
            // Process tree / pipe 尚未證明已關閉時，不與它競爭刪除私有 workspace。
            workspace = null;
            if (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(
                    "Ghidra 已取消，但 process tree 未能在清理期限內完整退出。",
                    exception,
                    cancellationToken);
            }

            return Failure($"Ghidra 分析失敗：{exception.Message}");
        }
        catch (Exception exception) when (
            exception is IOException
                or InvalidDataException
                or UnauthorizedAccessException
                or InvalidOperationException
                or NotSupportedException
                or Win32Exception
                or DecoderFallbackException)
        {
            return Failure($"Ghidra 分析失敗：{exception.Message}");
        }
        finally
        {
            if (workspace is not null)
            {
                TryDeleteDirectory(workspace);
            }
        }
    }

    private static NativeCodeModel Failure(string note) => new()
    {
        Backend = "none",
        Note = note
    };

    private static async Task WriteExportScriptAsync(string scriptPath, CancellationToken cancellationToken)
    {
        await using var resource = typeof(NativeAnalyzer).Assembly.GetManifestResourceStream(ExportScriptResourceName)
            ?? throw new InvalidOperationException($"找不到內嵌 Ghidra script：{ExportScriptResourceName}。");
        await using var output = new FileStream(
            scriptPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 16_384,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await resource.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ReadOutputJsonAsync(
        string outputPath,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(
            outputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16_384,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length > GhidraOutputParser.MaxJsonBytes)
        {
            throw new InvalidDataException(
                $"Ghidra JSON 輸出超過 {GhidraOutputParser.MaxJsonBytes:N0} bytes 安全上限。");
        }

        var bytes = GC.AllocateUninitializedArray<byte>(checked((int)input.Length));
        await input.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return StrictUtf8.GetString(bytes);
    }

    private static async Task<GhidraRunResult> RunHeadlessAsync(
        GhidraRunRequest request,
        CancellationToken cancellationToken)
    {
        var startInfo = CreateStartInfo(request);
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException("無法啟動 Ghidra headless process。");
        }

        var standardOutputTask = ReadBoundedTailAsync(process.StandardOutput, MaxProcessOutputTailChars);
        var standardErrorTask = ReadBoundedTailAsync(process.StandardError, MaxProcessOutputTailChars);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(request.TimeoutMs);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            var exited = await WaitForExitAfterKillAsync(process).ConfigureAwait(false);
            var output = await CollectOutputAsync(process, standardOutputTask, standardErrorTask)
                .ConfigureAwait(false);
            if (!exited || output is null)
            {
                throw new GhidraUnsafeCleanupException("Ghidra process 取消後未能在清理期限內完整退出。");
            }

            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException($"Ghidra 分析超過 {request.TimeoutMs} 毫秒逾時。");
        }

        var completedOutput = await CollectOutputAsync(process, standardOutputTask, standardErrorTask)
            .ConfigureAwait(false)
            ?? throw new GhidraUnsafeCleanupException("Ghidra process 結束後輸出管線未在清理期限內關閉。");
        return new GhidraRunResult(
            process.ExitCode,
            completedOutput.StandardOutput,
            completedOutput.StandardError);
    }

    private static ProcessStartInfo CreateStartInfo(GhidraRunRequest request)
    {
        var isWindowsBatch = OperatingSystem.IsWindows()
            && Path.GetExtension(request.LauncherPath).ToLowerInvariant() is ".bat" or ".cmd";
        var arguments = new[]
        {
            request.WorkspacePath,
            "exe-blueprint",
            "-import",
            request.InputPath,
            "-scriptPath",
            request.ScriptDirectory,
            "-postScript",
            request.ScriptName,
            request.OutputPath,
            "-deleteProject"
        };
        var startInfo = new ProcessStartInfo
        {
            FileName = isWindowsBatch ? GetCommandInterpreter() : request.LauncherPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        if (isWindowsBatch)
        {
            const string adapterName = "run-headless.cmd";
            var adapterPath = Path.Combine(request.WorkspacePath, adapterName);
            File.WriteAllText(
                adapterPath,
                "@echo off\r\n"
                + string.Join(
                    " ",
                    new[] { request.LauncherPath }.Concat(arguments).Select(QuoteWindowsBatchArgument))
                + "\r\n",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            startInfo.WorkingDirectory = request.WorkspacePath;
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/v:off");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add(adapterName);
        }

        if (!isWindowsBatch)
        {
            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }
        }

        return startInfo;
    }

    private static string QuoteWindowsBatchArgument(string value)
    {
        if (value.IndexOfAny(['"', '\r', '\n', '%', '!']) >= 0)
        {
            throw new InvalidOperationException(
                "Ghidra 的 Windows batch launcher 無法安全處理含雙引號、換行、百分號或驚嘆號的路徑。");
        }

        return $"\"{value}\"";
    }

    private static string GetCommandInterpreter()
    {
        var comSpec = Environment.GetEnvironmentVariable("ComSpec");
        if (!string.IsNullOrWhiteSpace(comSpec) && File.Exists(comSpec))
        {
            return comSpec;
        }

        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
    }

    private static async Task<string> ReadBoundedTailAsync(StreamReader reader, int maxChars)
    {
        var tail = new StringBuilder(maxChars);
        var buffer = new char[4_096];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) > 0)
        {
            if (read >= maxChars)
            {
                tail.Clear();
                tail.Append(buffer, read - maxChars, maxChars);
                continue;
            }

            var overflow = tail.Length + read - maxChars;
            if (overflow > 0)
            {
                tail.Remove(0, overflow);
            }

            tail.Append(buffer, 0, read);
        }

        return tail.ToString();
    }

    private static string FormatDiagnostic(string standardErrorTail, string standardOutputTail)
    {
        var value = string.IsNullOrWhiteSpace(standardErrorTail)
            ? standardOutputTail
            : standardErrorTail;
        if (string.IsNullOrWhiteSpace(value))
        {
            return "。";
        }

        var sanitized = new string(value
            .Where(character => !char.IsControl(character) || character is '\r' or '\n' or '\t')
            .ToArray())
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ')
            .Trim();
        if (sanitized.Length > MaxDiagnosticChars)
        {
            sanitized = sanitized[^MaxDiagnosticChars..];
        }

        return string.IsNullOrWhiteSpace(sanitized) ? "。" : $"：{sanitized}";
    }

    private static async Task<(string StandardOutput, string StandardError)?> CollectOutputAsync(
        Process process,
        Task<string> standardOutputTask,
        Task<string> standardErrorTask)
    {
        var combined = Task.WhenAll(standardOutputTask, standardErrorTask);
        if (await Task.WhenAny(combined, Task.Delay(OutputDrainGrace)).ConfigureAwait(false) == combined)
        {
            var output = await combined.ConfigureAwait(false);
            return (output[0], output[1]);
        }

        process.StandardOutput.Dispose();
        process.StandardError.Dispose();
        try
        {
            await combined.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException
                or ObjectDisposedException
                or TimeoutException
                or AggregateException)
        {
        }

        return null;
    }

    private static async Task<bool> WaitForExitAfterKillAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync(CancellationToken.None)
                .WaitAsync(ProcessExitGrace)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception or TimeoutException)
        {
            return false;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or NotSupportedException
                or Win32Exception
                or AggregateException)
        {
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

}

internal delegate Task<GhidraRunResult> GhidraProcessRunner(
    GhidraRunRequest request,
    CancellationToken cancellationToken);

internal sealed record GhidraRunRequest(
    string LauncherPath,
    string WorkspacePath,
    string InputPath,
    string ScriptDirectory,
    string ScriptName,
    string OutputPath,
    int TimeoutMs);

internal sealed record GhidraRunResult(
    int ExitCode,
    string StandardOutputTail,
    string StandardErrorTail);

internal sealed class GhidraUnsafeCleanupException(string message) : Exception(message);
