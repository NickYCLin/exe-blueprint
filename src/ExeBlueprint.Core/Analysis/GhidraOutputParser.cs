using System.Text.Json;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// v1 是函式清單；v2 另含 callGraph；v3 區分 CALL 與直接 JUMP tail call。
internal static class GhidraOutputParser
{
    internal const int MaxJsonBytes = 32 * 1024 * 1024;
    internal const int MaxJsonChars = MaxJsonBytes;
    private const int MaxFunctions = 100_000;
    private const int MaxStringChars = 16_384;
    private const int MaxJsonDepth = 16;
    private const int MaxCalls = 100_000;
    private const int MaxAddressChars = 256;

    public static GhidraOutputParseResult Parse(string json) =>
        Parse(json, MaxJsonChars, MaxFunctions, MaxStringChars);

    internal static GhidraOutputParseResult Parse(
        string json,
        int maxJsonChars,
        int maxFunctions,
        int maxStringChars,
        int maxCalls = MaxCalls)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxJsonChars, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFunctions, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxStringChars, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxCalls, 1);

        if (string.IsNullOrWhiteSpace(json))
        {
            return GhidraOutputParseResult.Invalid("Ghidra JSON 輸出是空的。");
        }

        if (json.Length > maxJsonChars)
        {
            return GhidraOutputParseResult.Invalid(
                $"Ghidra JSON 輸出超過 {maxJsonChars:N0} 字元安全上限。");
        }

        try
        {
            using var document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = MaxJsonDepth
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || HasDuplicateProperties(root)
                || !root.TryGetProperty("schemaVersion", out var schemaVersion)
                || schemaVersion.ValueKind != JsonValueKind.Number
                || !schemaVersion.TryGetInt32(out var schemaVersionNumber)
                || schemaVersionNumber is not (1 or 2 or 3)
                || !root.TryGetProperty("functionCount", out var functionCountValue)
                || functionCountValue.ValueKind != JsonValueKind.Number
                || !functionCountValue.TryGetInt32(out var functionCount)
                || functionCount < 0
                || !root.TryGetProperty("functions", out var functions)
                || functions.ValueKind != JsonValueKind.Array)
            {
                return GhidraOutputParseResult.Invalid("Ghidra JSON root schema 不正確。");
            }

            var truncated = false;
            if (root.TryGetProperty("truncated", out var truncatedValue))
            {
                if (truncatedValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    return GhidraOutputParseResult.Invalid("Ghidra JSON 的 truncated 欄位不是 boolean。");
                }

                truncated = truncatedValue.GetBoolean();
            }

            var sourceFunctionCount = functions.GetArrayLength();
            if (functionCount < sourceFunctionCount)
            {
                return GhidraOutputParseResult.Invalid("Ghidra JSON 的 functionCount 小於 functions 筆數。");
            }

            if (!truncated && functionCount != sourceFunctionCount)
            {
                return GhidraOutputParseResult.Invalid("Ghidra JSON 的 functionCount 與未截斷 functions 筆數不一致。");
            }

            var result = new List<NativeFunction>(Math.Min(sourceFunctionCount, maxFunctions));
            var functionAddresses = new Dictionary<string, bool>(StringComparer.Ordinal);
            var retainedAddresses = new HashSet<string>(StringComparer.Ordinal);
            var index = 0;
            foreach (var element in functions.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object
                    || HasDuplicateProperties(element)
                    || !TryGetRequiredString(element, "name", maxStringChars, ref truncated, out var name)
                    || string.IsNullOrWhiteSpace(name)
                    || !TryGetRequiredString(element, "address", maxStringChars, ref truncated, out var address)
                    || !TryGetRequiredString(element, "signature", maxStringChars, ref truncated, out var signature)
                    || !element.TryGetProperty("external", out var external)
                    || external.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    return GhidraOutputParseResult.Invalid(
                        $"Ghidra JSON 的 functions[{index}] schema 不正確。");
                }

                // 位址是 v2 呼叫圖的 identity，不能像顯示文字一樣截短。
                if (schemaVersionNumber >= 2
                    && (!TryGetAddress(element, "address", out address)
                        || !functionAddresses.TryAdd(address, external.GetBoolean())))
                {
                    return GhidraOutputParseResult.Invalid("Ghidra JSON 的函式位址無效或重複。");
                }

                if (result.Count < maxFunctions)
                {
                    retainedAddresses.Add(address);
                    result.Add(new NativeFunction
                    {
                        Name = name,
                        Address = address,
                        Signature = signature,
                        IsExternal = external.GetBoolean()
                    });
                }
                else
                {
                    truncated = true;
                }

                index++;
            }

            NativeCallGraph? callGraph = null;
            if (schemaVersionNumber >= 2)
            {
                callGraph = ParseCallGraph(root, functionAddresses, retainedAddresses, truncated, maxCalls, schemaVersionNumber);
                if (callGraph is null)
                {
                    return GhidraOutputParseResult.Invalid("Ghidra JSON 的 callGraph schema 或函式參照不正確。");
                }
            }
            else if (root.TryGetProperty("callGraph", out _))
            {
                return GhidraOutputParseResult.Invalid("Ghidra JSON v1 不支援 callGraph。");
            }

            return new GhidraOutputParseResult(true, functionCount, result, truncated, null)
            {
                CallGraph = callGraph
            };
        }
        catch (JsonException exception)
        {
            return GhidraOutputParseResult.Invalid($"Ghidra JSON 格式錯誤：{exception.Message}");
        }
    }

    private static NativeCallGraph? ParseCallGraph(
        JsonElement root,
        IReadOnlyDictionary<string, bool> functionAddresses,
        HashSet<string> retainedAddresses,
        bool functionsTruncated,
        int maxCalls,
        int schemaVersion)
    {
        if (!root.TryGetProperty("callGraph", out var graph)
            || graph.ValueKind != JsonValueKind.Object
            || HasDuplicateProperties(graph)
            || !graph.TryGetProperty("calls", out var calls)
            || calls.ValueKind != JsonValueKind.Array
            || !graph.TryGetProperty("truncated", out var truncatedValue)
            || truncatedValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return null;
        }

        var truncated = functionsTruncated || truncatedValue.GetBoolean();
        var result = new List<NativeCall>(Math.Min(calls.GetArrayLength(), maxCalls));
        // 同一 call site 可有多個已知目標，但相同 edge 不可重複計數。
        var identities = new HashSet<(string Caller, string Site, string? Target)>();
        var sites = new Dictionary<(string Caller, string Site), (bool Indirect, bool Tail)>();
        foreach (var call in calls.EnumerateArray())
        {
            if (call.ValueKind != JsonValueKind.Object
                || HasDuplicateProperties(call)
                || !TryGetAddress(call, "callerAddress", out var caller)
                || !functionAddresses.TryGetValue(caller, out var callerIsExternal)
                || callerIsExternal
                || !TryGetAddress(call, "callSiteAddress", out var site)
                || !call.TryGetProperty("targetAddress", out var targetValue)
                || !call.TryGetProperty("isIndirect", out var indirect)
                || indirect.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return null;
            }

            string? target = null;
            if (targetValue.ValueKind != JsonValueKind.Null
                && (!TryGetAddress(call, "targetAddress", out target)
                    || !functionAddresses.ContainsKey(target)))
            {
                return null;
            }

            var tail = false;
            if (schemaVersion >= 3)
            {
                if (!call.TryGetProperty("isTailCall", out var tailValue)
                    || tailValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    return null;
                }
                tail = tailValue.GetBoolean();
            }
            else if (call.TryGetProperty("isTailCall", out _))
            {
                return null;
            }

            if (tail && (indirect.GetBoolean() || target is null || target == caller))
            {
                return null;
            }

            var siteKind = (indirect.GetBoolean(), tail);
            if (sites.TryGetValue((caller, site), out var previousKind)
                && (previousKind != siteKind || tail))
            {
                return null;
            }
            sites[(caller, site)] = siteKind;

            if (!identities.Add((caller, site, target)))
            {
                return null;
            }

            if (result.Count >= maxCalls
                || !retainedAddresses.Contains(caller)
                || (target is not null && !retainedAddresses.Contains(target)))
            {
                truncated = true;
                continue;
            }

            result.Add(new NativeCall
            {
                CallerAddress = caller,
                CallSiteAddress = site,
                TargetAddress = target,
                IsIndirect = indirect.GetBoolean(),
                IsTailCall = tail
            });
        }

        return new NativeCallGraph { Calls = result, Truncated = truncated, TailCallsAnalyzed = schemaVersion >= 3 };
    }

    private static bool TryGetAddress(JsonElement element, string property, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(property, out var address) || address.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = address.GetString() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value)
            && value.Length <= MaxAddressChars
            && !value.Any(char.IsControl);
    }

    private static bool HasDuplicateProperties(JsonElement element)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        return element.EnumerateObject().Any(property => !names.Add(property.Name));
    }

    private static bool TryGetRequiredString(
        JsonElement element,
        string property,
        int maxStringChars,
        ref bool truncated,
        out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(property, out var jsonValue)
            || jsonValue.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = jsonValue.GetString() ?? string.Empty;
        if (value.Length <= maxStringChars)
        {
            return true;
        }

        var length = maxStringChars;
        if (char.IsHighSurrogate(value[length - 1]))
        {
            length--;
        }

        value = value[..length];
        truncated = true;
        return true;
    }
}

internal sealed record GhidraOutputParseResult(
    bool IsValid,
    int FunctionCount,
    IReadOnlyList<NativeFunction> Functions,
    bool Truncated,
    string? Error)
{
    public NativeCallGraph? CallGraph { get; init; }

    public static GhidraOutputParseResult Invalid(string error) => new(false, 0, [], false, error);
}
