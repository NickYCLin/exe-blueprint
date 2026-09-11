namespace ExeBlueprint.Models;

public sealed record SourceCodeAnalysis
{
    public bool Truncated { get; init; }

    public IReadOnlyList<SourceProjectSummary> Projects { get; init; } = [];

    public IReadOnlyList<SourceDeclaration> Declarations { get; init; } = [];

    public IReadOnlyList<SourceCall> Calls { get; init; } = [];

    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record SourceProjectSummary
{
    public required string Project { get; init; }

    public int FileCount { get; init; }

    public int DeclarationCount { get; init; }

    public int CallCount { get; init; }

    public int ErrorCount { get; init; }

    public IReadOnlyList<string> ErrorCodes { get; init; } = [];

    public bool Complete { get; init; }

    public IReadOnlyList<string> Notes { get; init; } = [];
}

public sealed record SourceDeclaration
{
    public required string Id { get; init; }

    public required string Project { get; init; }

    public required string File { get; init; }

    public int Line { get; init; }

    public required string Kind { get; init; }

    public required string Name { get; init; }
}

public sealed record SourceCall
{
    public required string Caller { get; init; }

    public required string Target { get; init; }

    public required string SourceProject { get; init; }

    public string? TargetProject { get; init; }

    public required string File { get; init; }

    public int Line { get; init; }

    public required string Kind { get; init; }

    // resolved-source、external、ambiguous、unresolved。
    public required string Status { get; init; }
}
