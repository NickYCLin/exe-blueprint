namespace ExeBlueprint.Models;

public sealed record NativeCodeModel
{
    // "ghidra" 代表成功用 Ghidra 分析；"none" 代表沒有可用後端（見 Note）。
    public required string Backend { get; init; }

    public string? Note { get; init; }

    public int FunctionCount { get; init; }

    public IReadOnlyList<NativeFunction> Functions { get; init; } = [];
}

public sealed record NativeFunction
{
    public required string Name { get; init; }

    public string? Address { get; init; }

    public string? Signature { get; init; }

    public bool IsExternal { get; init; }
}
