using System.Text.Json;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 解析 Ghidra 匯出腳本產生的 JSON（{ "functions": [ { name, address, signature, external } ] }）。
internal static class GhidraOutputParser
{
    private const int MaxFunctions = 100_000;

    public static IReadOnlyList<NativeFunction> Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("functions", out var functions) ||
            functions.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var result = new List<NativeFunction>();
        foreach (var element in functions.EnumerateArray())
        {
            if (result.Count >= MaxFunctions)
            {
                break;
            }

            var name = GetString(element, "name");
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            result.Add(new NativeFunction
            {
                Name = name,
                Address = GetString(element, "address"),
                Signature = GetString(element, "signature"),
                IsExternal = element.TryGetProperty("external", out var external) &&
                             external.ValueKind is JsonValueKind.True
            });
        }

        return result;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
