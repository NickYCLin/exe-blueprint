namespace ExeBlueprint.Analysis;

public sealed record AnalysisOptions
{
    public int MaxFiles { get; init; } = 25_000;

    public long MaxTotalBytes { get; init; } = 20L * 1024 * 1024 * 1024;

    public long MaxFileBytes { get; init; } = 4L * 1024 * 1024 * 1024;

    public int BinarySignalSampleBytes { get; init; } = 4 * 1024 * 1024;
}
