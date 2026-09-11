namespace ExeBlueprint.Models;

// 原始碼節點只表示檔案內明確宣告的結構，不代表 MSBuild 求值結果。
public sealed record ProjectGraph
{
    public bool Truncated { get; init; }
    public IReadOnlyList<ProjectComponent> Components { get; init; } = [];
    public IReadOnlyList<ProjectReference> References { get; init; } = [];
}

public sealed record ProjectComponent
{
    public required string Id { get; init; }
    public required string Kind { get; init; }
    public required string Name { get; init; }
    public string? Framework { get; init; }
    public string? OutputType { get; init; }
    public string? AssemblyName { get; init; }
    public IReadOnlyList<string> Notes { get; init; } = [];
}

public sealed record ProjectReference
{
    public required string Source { get; init; }
    public required string Target { get; init; }
    public required string Kind { get; init; }
    // resolved、missing、ambiguous、conditional、unevaluated、external。
    public required string Status { get; init; }
    public string? Version { get; init; }
    public string? VersionSource { get; init; }
}
