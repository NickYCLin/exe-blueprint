namespace ExeBlueprint.Analysis;

public sealed record AnalysisOptions
{
    public int MaxFiles { get; init; } = 25_000;

    public long MaxTotalBytes { get; init; } = 20L * 1024 * 1024 * 1024;

    public long MaxFileBytes { get; init; } = 4L * 1024 * 1024 * 1024;

    public int BinarySignalSampleBytes { get; init; } = 4 * 1024 * 1024;

    // 開啟後會對原生 PE 呼叫 Ghidra headless 抽函式；沒裝 Ghidra 時只會加註記，不會失敗。
    public bool EnableNativeAnalysis { get; init; }

    // Ghidra 安裝目錄；null 時改讀環境變數 GHIDRA_INSTALL_DIR。
    public string? GhidraInstallDir { get; init; }

    // 單一原生檔的 Ghidra 分析逾時（毫秒）。
    public int NativeAnalysisTimeoutMs { get; init; } = 180_000;
}
