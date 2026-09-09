namespace ExeBlueprint.Analysis;

public sealed record AnalysisProgress(int CompletedFiles, int TotalFiles, string? CurrentFile, string Stage = "files");

internal sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}
