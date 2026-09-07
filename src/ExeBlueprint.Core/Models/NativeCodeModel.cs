namespace ExeBlueprint.Models;

public sealed record NativeCodeModel
{
    // "ghidra" 代表成功用 Ghidra 分析；"none" 代表沒有可用後端（見 Note）。
    public required string Backend { get; init; }

    public string? Note { get; init; }

    public int FunctionCount { get; init; }

    public IReadOnlyList<NativeFunction> Functions { get; init; } = [];

    public bool FunctionsTruncated { get; init; }

    // null 表示後端沒有匯出呼叫圖，與已掃描但沒有呼叫不同。
    public NativeCallGraph? CallGraph { get; init; }
}

public sealed record NativeCallGraph
{
    public IReadOnlyList<NativeCall> Calls { get; init; } = [];

    public bool Truncated { get; init; }

    // 只計算已保留的紀錄；間接呼叫即使有目標，也不代表所有執行期目標已知。
    public int UnresolvedCallCount => Calls.Count(call => call.TargetAddress is null);
}

public sealed record NativeCall
{
    public required string CallerAddress { get; init; }

    public required string CallSiteAddress { get; init; }

    public string? TargetAddress { get; init; }

    public bool IsIndirect { get; init; }
}

public sealed record NativeFunction
{
    public required string Name { get; init; }

    public string? Address { get; init; }

    public string? Signature { get; init; }

    public bool IsExternal { get; init; }
}
