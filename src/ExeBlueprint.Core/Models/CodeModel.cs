namespace ExeBlueprint.Models;

public sealed record CodeModel
{
    public required string Kind { get; init; }

    public string? EntryPointMethod { get; init; }

    public int NamespaceCount { get; init; }

    public int TypeCount { get; init; }

    public int MethodCount { get; init; }

    public int CallEdgeCount { get; init; }

    public bool Truncated { get; init; }

    public IReadOnlyList<TypeModel> Types { get; init; } = [];

    public IReadOnlyList<CallEdge> CallGraph { get; init; } = [];
}

public sealed record TypeModel
{
    public required string FullName { get; init; }

    public required string Namespace { get; init; }

    public required string Name { get; init; }

    public required string Kind { get; init; }

    public required string Accessibility { get; init; }

    public string? BaseType { get; init; }

    public IReadOnlyList<MethodModel> Methods { get; init; } = [];
}

public sealed record MethodModel
{
    public required string Name { get; init; }

    public required string Signature { get; init; }

    public required string Accessibility { get; init; }

    public bool IsStatic { get; init; }

    public bool IsAbstract { get; init; }

    public bool IsVirtual { get; init; }

    public bool IsEntryPoint { get; init; }

    public bool HasBody { get; init; }
}

public sealed record CallEdge
{
    public required string Caller { get; init; }

    public required string Callee { get; init; }

    public required string Kind { get; init; }
}
