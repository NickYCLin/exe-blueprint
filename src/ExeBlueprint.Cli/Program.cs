using System.Reflection;
using System.Text;
using ExeBlueprint.Application;

Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

return await RunAsync(args, cancellation.Token);

static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        PrintHelp();
        return args.Length == 0 ? 2 : 0;
    }

    if (args[0] is "-v" or "--version" or "version")
    {
        Console.WriteLine(GetVersion());
        return 0;
    }

    try
    {
        var parsed = ParseArguments(args);
        Console.WriteLine($"正在分析：{Path.GetFullPath(parsed.InputPath)}");
        var service = new BlueprintExportService();
        var result = await service.RunAsync(new BlueprintExportRequest
        {
            InputPath = parsed.InputPath,
            OutputDirectory = parsed.OutputDirectory,
            Overwrite = parsed.Force,
            JsonOnly = parsed.JsonOnly,
            EmitCSharp = parsed.EmitCSharp,
            EmitCpp = parsed.EmitCpp,
            EmitRust = parsed.EmitRust,
            EmitGo = parsed.EmitGo,
            EnableNativeAnalysis = parsed.Native,
            GhidraInstallDir = parsed.GhidraDir
        }, cancellationToken: cancellationToken);

        foreach (var skeleton in result.Skeletons)
        {
            Console.WriteLine($"{skeleton.Language} 骨架：{skeleton.FileCount:N0} 個檔案 → {skeleton.Directory}");
        }

        var document = result.Document;
        Console.WriteLine($"完成：{result.OutputDirectory}");
        Console.WriteLine($"檔案：{document.Input.FileCount:N0}");
        Console.WriteLine($"PE 執行檔：{document.Summary.ExecutableCount:N0}");
        Console.WriteLine($"程式庫：{document.Summary.LibraryCount:N0}");
        Console.WriteLine($"型別／方法：{document.Summary.TypeCount:N0}／{document.Summary.MethodCount:N0}");
        Console.WriteLine($"辨識結果：{FormatTechnologies(document.Technologies.Select(item => item.Name))}");
        if (document.Warnings.Count > 0)
        {
            Console.WriteLine($"警告：{document.Warnings.Count:N0}，請查看報告。");
        }

        return 0;
    }
    catch (OperationCanceledException)
    {
        Console.Error.WriteLine("分析已取消。");
        return 130;
    }
    catch (Exception exception) when (exception is ArgumentException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"無法完成分析：{exception.Message}");
        return 3;
    }
}

static ParsedArguments ParseArguments(string[] args)
{
    var index = args[0].Equals("analyze", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
    if (index >= args.Length || args[index].StartsWith('-'))
    {
        throw new ArgumentException("請指定要分析的檔案、資料夾或 ZIP。");
    }

    var inputPath = args[index++];
    string? outputDirectory = null;
    var force = false;
    var jsonOnly = false;
    var emitCSharp = false;
    var emitCpp = false;
    var emitRust = false;
    var emitGo = false;
    var native = false;
    string? ghidraDir = null;

    while (index < args.Length)
    {
        var option = args[index++];
        switch (option)
        {
            case "--native":
                native = true;
                break;
            case "--ghidra":
                if (index >= args.Length)
                {
                    throw new ArgumentException("--ghidra 後面需要 Ghidra 安裝目錄。");
                }

                ghidraDir = args[index++];
                native = true;
                break;
            case "-o":
            case "--output":
                if (index >= args.Length)
                {
                    throw new ArgumentException($"{option} 後面需要輸出目錄。");
                }

                outputDirectory = Path.GetFullPath(args[index++]);
                break;
            case "--force":
                force = true;
                break;
            case "--json-only":
                jsonOnly = true;
                break;
            case "--emit-csharp":
                emitCSharp = true;
                break;
            case "--emit-cpp":
                emitCpp = true;
                break;
            case "--emit-rust":
                emitRust = true;
                break;
            case "--emit-go":
                emitGo = true;
                break;
            default:
                throw new ArgumentException($"不支援的選項：{option}");
        }
    }

    return new ParsedArguments(inputPath, outputDirectory, force, jsonOnly, emitCSharp, emitCpp, emitRust, emitGo, native, ghidraDir);
}

static string FormatTechnologies(IEnumerable<string> technologies)
{
    var values = technologies.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    return values.Length == 0 ? "尚未判斷" : string.Join("、", values);
}

static string GetVersion() =>
    Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

static void PrintHelp()
{
    Console.WriteLine("ExeBlueprint - Windows 應用程式套件分析工具");
    Console.WriteLine();
    Console.WriteLine("用法：");
    Console.WriteLine("  exe-blueprint analyze <檔案|資料夾|ZIP> [選項]");
    Console.WriteLine("  exe-blueprint <檔案|資料夾|ZIP> [選項]");
    Console.WriteLine();
    Console.WriteLine("選項：");
    Console.WriteLine("  -o, --output <目錄>  指定輸出目錄");
    Console.WriteLine("  --json-only          只輸出 blueprint.json");
    Console.WriteLine("  --emit-csharp        另外產生 .NET 型別的 C# 骨架（含還原的方法體）");
    Console.WriteLine("  --emit-cpp           另外產生 C++ 型別骨架");
    Console.WriteLine("  --emit-rust          另外產生 Rust 型別骨架");
    Console.WriteLine("  --emit-go            另外產生 Go 型別骨架");
    Console.WriteLine("  --native             對原生 PE 用 Ghidra 抽函式（需 GHIDRA_INSTALL_DIR）");
    Console.WriteLine("  --ghidra <目錄>      指定 Ghidra 安裝目錄並開啟原生分析");
    Console.WriteLine("  --force              覆寫既有 blueprint.json 與 REPORT.md");
    Console.WriteLine("  -v, --version        顯示版本");
    Console.WriteLine("  -h, --help           顯示說明");
    Console.WriteLine();
    Console.WriteLine("預設只做靜態分析，不會執行輸入程式。");
}

internal sealed record ParsedArguments(
    string InputPath,
    string? OutputDirectory,
    bool Force,
    bool JsonOnly,
    bool EmitCSharp,
    bool EmitCpp,
    bool EmitRust,
    bool EmitGo,
    bool Native,
    string? GhidraDir);
