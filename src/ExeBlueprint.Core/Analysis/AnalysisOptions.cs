namespace ExeBlueprint.Analysis;

public sealed record AnalysisOptions
{
    // 先盤點組件與專案關係，不讀取 IL、內嵌資源或啟動 Ghidra。
    public bool InventoryOnly { get; init; }

    // 原始碼目錄略過版本控制、建置輸出及已安裝的相依套件。
    public bool SourceMode { get; init; }

    // 使用 Roslyn 建立 C# 宣告與呼叫索引；不執行 MSBuild 或還原套件。
    public bool EnableSourceAnalysis { get; init; }

    internal string? ExcludedOutputDirectory { get; init; }

    public int MaxFiles { get; init; } = 25_000;

    public long MaxTotalBytes { get; init; } = 20L * 1024 * 1024 * 1024;

    public long MaxFileBytes { get; init; } = 4L * 1024 * 1024 * 1024;

    public int MaxArchiveDepth { get; init; } = 8;

    internal int MaxWorkspacePathCharacters { get; init; } = 8 * 1024 * 1024;

    internal int MaxWorkspaceArchives { get; init; } = 1_024;

    internal long MaxWorkspaceArchiveHeaderBytes { get; init; } = 64L * 1024 * 1024;

    internal int MaxWorkspaceArchiveNodes { get; init; } = 100_000;

    public int BinarySignalSampleBytes { get; init; } = 4 * 1024 * 1024;

    // 開啟後會對原生 PE 呼叫 Ghidra headless 抽函式；沒裝 Ghidra 時只會加註記，不會失敗。
    public bool EnableNativeAnalysis { get; init; }

    // Ghidra 安裝目錄；null 時改讀環境變數 GHIDRA_INSTALL_DIR。
    public string? GhidraInstallDir { get; init; }

    // 單一原生檔的 Ghidra 分析逾時（毫秒）。
    public int NativeAnalysisTimeoutMs { get; init; } = 180_000;

    public NativeDecompilationLimits? NativeDecompilation { get; init; }
}

public sealed record NativeDecompilationLimits
{
    public int MaxFunctions { get; init; } = 256;
    public int MaxFunctionCharacters { get; init; } = 65_536;
    public int MaxTotalCharacters { get; init; } = 1_048_576;
    public int FunctionTimeoutSeconds { get; init; } = 10;
    public int TotalTimeoutSeconds { get; init; } = 60;

    internal bool IsValid => MaxFunctions is > 0 and <= 4096
        && MaxFunctionCharacters is > 0 and <= 262_144
        && MaxTotalCharacters is > 0 and <= 8_388_608
        && FunctionTimeoutSeconds is > 0 and <= 60
        && TotalTimeoutSeconds is > 0 and <= 600;
}
