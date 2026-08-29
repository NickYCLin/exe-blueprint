using System.Text.Json;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 解析 Ghidra 匯出腳本產生的 JSON（{ "functions": [ { name, address, signature, external } ] }）。
internal static class GhidraOutputParser
{
    internal const int MaxJsonBytes = 32 * 1024 * 1024;
    internal const int MaxJsonChars = MaxJsonBytes;
    private const int MaxFunctions = 100_000;
    private const int MaxStringChars = 16_384;
    private const int MaxJsonDepth = 16;

    public static GhidraOutputParseResult Parse(string json) =>
        Parse(json, MaxJsonChars, MaxFunctions, MaxStringChars);

    internal static GhidraOutputParseResult Parse(
        string json,
        int maxJsonChars,
        int maxFunctions,
        int maxStringChars)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxJsonChars, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFunctions, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxStringChars, 1);

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
                || !root.TryGetProperty("schemaVersion", out var schemaVersion)
                || schemaVersion.ValueKind != JsonValueKind.Number
                || !schemaVersion.TryGetInt32(out var schemaVersionNumber)
                || schemaVersionNumber != 1
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
            var index = 0;
            foreach (var element in functions.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object
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

                if (result.Count < maxFunctions)
                {
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

            return new GhidraOutputParseResult(true, functionCount, result, truncated, null);
        }
        catch (JsonException exception)
        {
            return GhidraOutputParseResult.Invalid($"Ghidra JSON 格式錯誤：{exception.Message}");
        }
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
    public static GhidraOutputParseResult Invalid(string error) => new(false, 0, [], false, error);
}
