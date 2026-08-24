namespace ExeBlueprint.Generation;

public sealed record GeneratedFile
{
    public required string RelativePath { get; init; }

    public required string Content { get; init; }
}
