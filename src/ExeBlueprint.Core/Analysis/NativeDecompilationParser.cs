using System.Text.Json;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

internal static class NativeDecompilationParser
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    internal static NativeDecompilation? Parse(string json, IReadOnlyList<NativeFunction> functions)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.EnumerateObject().Count(property => property.Name == "decompilation") > 1)
            throw new InvalidDataException("Ghidra 偽碼證據含重複欄位。");
        if (!document.RootElement.TryGetProperty("decompilation", out var evidence))
            return null;
        ValidateProperties(evidence);
        RequireKind(evidence, JsonValueKind.Object);
        foreach (var property in new[] { "candidateCount", "complete", "truncated", "functions" })
            if (!evidence.TryGetProperty(property, out _))
                throw new InvalidDataException("Ghidra 偽碼證據缺少必要欄位。");
        if (!evidence.TryGetProperty("limits", out var limitValues))
            throw new InvalidDataException("Ghidra 偽碼證據缺少限制。");
        RequireKind(limitValues, JsonValueKind.Object);
        foreach (var property in new[] { "maxFunctions", "maxFunctionCharacters", "maxTotalCharacters", "functionTimeoutSeconds", "totalTimeoutSeconds" })
            if (!limitValues.TryGetProperty(property, out _))
                throw new InvalidDataException("Ghidra 偽碼限制缺少必要欄位。");
        RequireKind(evidence.GetProperty("functions"), JsonValueKind.Array);
        foreach (var function in evidence.GetProperty("functions").EnumerateArray())
        {
            RequireKind(function, JsonValueKind.Object);
            foreach (var property in new[] { "address", "status", "code", "diagnostic", "elapsedMilliseconds" })
                if (!function.TryGetProperty(property, out _))
                    throw new InvalidDataException("Ghidra 逐函式偽碼缺少必要欄位。");
        }
        var result = evidence.Deserialize<NativeDecompilation>(Options)
            ?? throw new InvalidDataException("Ghidra 偽碼證據不可為 null。");
        if (result.InputSha256 is null || result.InputSha256.Length != 64
            || !result.InputSha256.All(Uri.IsHexDigit)
            || string.IsNullOrWhiteSpace(result.AnalyzerVersion) || result.AnalyzerVersion.Length > 256
            || result.Limits is null || !result.Limits.IsValid || result.Functions is null
            || result.CandidateCount != functions.Count(function => !function.IsExternal)
            || result.Functions.Count > result.Limits.MaxFunctions
            || result.Functions.Count > result.CandidateCount
            || result.LimitReason?.Length > 256
            || (result.Complete && result.Functions.Count != result.CandidateCount))
            throw new InvalidDataException("Ghidra 偽碼證據或限制不正確。");
        var addresses = functions.Where(function => !function.IsExternal)
            .Select(function => function.Address).ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        foreach (var function in result.Functions)
        {
            if (!addresses.Contains(function.Address) || !seen.Add(function.Address)
                || function.Status is not ("success" or "failed" or "timeout" or "truncated")
                || function.ElapsedMilliseconds < 0 || function.Diagnostic?.Length > 1000
                || function.Code?.Length > result.Limits.MaxFunctionCharacters
                || (function.Status is "success" or "truncated" ? function.Code is null : function.Code is not null)
                || (function.Status == "truncated" && !result.Truncated))
                throw new InvalidDataException("Ghidra 逐函式偽碼紀錄不正確。");
            total += function.Code?.Length ?? 0;
        }
        if (total > result.Limits.MaxTotalCharacters)
            throw new InvalidDataException("Ghidra 偽碼超過全局字元預算。");
        return result;
    }

    private static void RequireKind(JsonElement element, JsonValueKind kind)
    {
        if (element.ValueKind != kind)
            throw new InvalidDataException("Ghidra 偽碼證據的欄位型別不正確。");
    }

    private static void ValidateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new InvalidDataException("Ghidra 偽碼證據含重複欄位。");
                ValidateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in element.EnumerateArray())
                ValidateProperties(child);
        }
    }
}
