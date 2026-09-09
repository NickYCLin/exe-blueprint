namespace ExeBlueprint.Analysis;

public sealed record AnalysisOptions
{
    // 先盤點組件與專案關係，不讀取 IL、內嵌資源或啟動 Ghidra。
    public bool InventoryOnly { get; init; }

    // 原始碼目錄略過版本控制、建置輸出及已安裝的相依套件。
    public bool SourceMode { get; init; }

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
}
