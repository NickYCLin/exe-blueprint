using System.Diagnostics;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 用 Ghidra headless 分析原生 PE，抽出函式清單。
// 找不到 Ghidra 或執行失敗時不會讓分析失敗，只回傳帶註記的結果（Backend="none"）。
internal static class NativeAnalyzer
{
    private const string ExportScript =
        """
        # 由 ExeBlueprint 產生：把目前程式的函式匯出成 JSON。
        import json
        args = getScriptArgs()
        out = args[0]
        fm = currentProgram.getFunctionManager()
        funcs = []
        for f in fm.getFunctions(True):
            funcs.append({
                "name": f.getName(),
                "address": str(f.getEntryPoint()),
                "signature": f.getPrototypeString(False, False),
                "external": f.isExternal(),
            })
        with open(out, "w") as fh:
            json.dump({"functions": funcs}, fh)
        """;

    public static string? LocateHeadless(AnalysisOptions options)
    {
        var installDir = options.GhidraInstallDir ?? Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
        if (string.IsNullOrWhiteSpace(installDir))
        {
            return null;
        }

        var executable = OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless";
        var path = Path.Combine(installDir, "support", executable);
        return File.Exists(path) ? path : null;
    }

    public static async Task<NativeCodeModel> AnalyzeAsync(
        string filePath,
        AnalysisOptions options,
        CancellationToken cancellationToken)
    {
        var headless = LocateHeadless(options);
        if (headless is null)
        {
            return new NativeCodeModel
            {
                Backend = "none",
                Note = "未偵測到 Ghidra，原生 PE 未做函式分析。設定 GHIDRA_INSTALL_DIR 或用 --ghidra 指定安裝目錄即可啟用。"
            };
        }

        var workspace = Path.Combine(Path.GetTempPath(), "exe-blueprint-ghidra", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workspace);
        try
        {
            var scriptPath = Path.Combine(workspace, "ExportFunctions.py");
            var outputPath = Path.Combine(workspace, "functions.json");
            await File.WriteAllTextAsync(scriptPath, ExportScript, cancellationToken).ConfigureAwait(false);

            var exitCode = await RunHeadlessAsync(headless, workspace, filePath, scriptPath, outputPath, options, cancellationToken)
                .ConfigureAwait(false);

            if (!File.Exists(outputPath))
            {
                return new NativeCodeModel
                {
                    Backend = "none",
                    Note = $"Ghidra 執行未產生輸出（exit code {exitCode}）。"
                };
            }

            var json = await File.ReadAllTextAsync(outputPath, cancellationToken).ConfigureAwait(false);
            var functions = GhidraOutputParser.Parse(json);
            return new NativeCodeModel
            {
                Backend = "ghidra",
                FunctionCount = functions.Count,
                Functions = functions
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new NativeCodeModel { Backend = "none", Note = $"Ghidra 分析失敗：{exception.Message}" };
        }
        finally
        {
            TryDeleteDirectory(workspace);
        }
    }

    private static async Task<int> RunHeadlessAsync(
        string headless,
        string workspace,
        string filePath,
        string scriptPath,
        string outputPath,
        AnalysisOptions options,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = headless,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add(workspace);
        startInfo.ArgumentList.Add("exe-blueprint");
        startInfo.ArgumentList.Add("-import");
        startInfo.ArgumentList.Add(filePath);
        startInfo.ArgumentList.Add("-scriptPath");
        startInfo.ArgumentList.Add(Path.GetDirectoryName(scriptPath)!);
        startInfo.ArgumentList.Add("-postScript");
        startInfo.ArgumentList.Add(Path.GetFileName(scriptPath));
        startInfo.ArgumentList.Add(outputPath);
        startInfo.ArgumentList.Add("-deleteProject");

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.NativeAnalysisTimeoutMs);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw new InvalidOperationException($"Ghidra 分析超過 {options.NativeAnalysisTimeoutMs} 毫秒逾時。");
        }

        return process.ExitCode;
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
        catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException)
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
