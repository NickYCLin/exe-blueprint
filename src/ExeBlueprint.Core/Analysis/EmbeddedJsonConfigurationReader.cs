using System.Text.Json;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 僅保留 JSON 設定的欄位結構；設定值不會進入分析結果。
internal static class EmbeddedJsonConfigurationReader
{
    internal const int MaxBytes = 1024 * 1024;
    private const int MaxDepth = 32;
    private const int MaxNodes = 20_000;
    private const int MaxProperties = 10_000;
    private const int MaxPropertyPaths = 200;
    private const int MaxPathLength = 512;
    private const string HiddenPath = "\u0000";

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = MaxDepth
    };

    public static ManagedResourceConfigurationModel Read(byte[] data)
    {
        if (data.Length > MaxBytes)
        {
            return Partial("JSON 設定檔超過 1 MB 安全解析上限。");
        }

        try
        {
            using var document = JsonDocument.Parse(data, DocumentOptions);
            var state = new SummaryState();
            state.Visit(document.RootElement, parentPath: null, depth: 0);
            return new ManagedResourceConfigurationModel
            {
                Format = "json",
                Status = state.Complete ? "parsed" : "partial",
                RootKind = GetKind(document.RootElement.ValueKind),
                PropertyCount = state.PropertyCount,
                PropertyPaths = state.PropertyPaths,
                PropertyPathsTruncated = state.PropertyPathsTruncated,
                Error = state.Error
            };
        }
        catch (JsonException)
        {
            return Invalid("JSON 設定檔格式無效、UTF-8 不正確或巢狀過深。");
        }
    }

    public static ManagedResourceConfigurationModel Unavailable(string error) =>
        Partial(error);

    private static ManagedResourceConfigurationModel Partial(string error) =>
        new()
        {
            Format = "json",
            Status = "partial",
            PropertyCount = 0,
            PropertyPaths = [],
            PropertyPathsTruncated = false,
            Error = error
        };

    private static ManagedResourceConfigurationModel Invalid(string error) =>
        new()
        {
            Format = "json",
            Status = "invalid",
            PropertyCount = 0,
            PropertyPaths = [],
            PropertyPathsTruncated = false,
            Error = error
        };

    private static string GetKind(JsonValueKind kind) => kind switch
    {
        JsonValueKind.Object => "object",
        JsonValueKind.Array => "array",
        JsonValueKind.String => "string",
        JsonValueKind.Number => "number",
        JsonValueKind.True or JsonValueKind.False => "boolean",
        JsonValueKind.Null => "null",
        _ => "unknown"
    };

    private sealed class SummaryState
    {
        private readonly HashSet<string> _paths = new(StringComparer.Ordinal);
        private readonly List<string> _propertyPaths = [];

        public int PropertyCount { get; private set; }

        public IReadOnlyList<string> PropertyPaths => _propertyPaths;

        public bool PropertyPathsTruncated { get; private set; }

        public bool Complete { get; private set; } = true;

        public string? Error { get; private set; }

        private int NodeCount { get; set; }

        public void Visit(JsonElement element, string? parentPath, int depth)
        {
            if (!Complete)
            {
                return;
            }

            NodeCount++;
            if (NodeCount > MaxNodes)
            {
                Stop("JSON 設定結構超過 20,000 個節點安全解析上限。");
                return;
            }

            if (depth > MaxDepth)
            {
                Stop($"JSON 設定結構超過 {MaxDepth} 層安全解析上限。");
                return;
            }

            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        if (PropertyCount >= MaxProperties)
                        {
                            Stop($"JSON 設定結構超過 {MaxProperties:N0} 個欄位安全解析上限。");
                            return;
                        }

                        PropertyCount++;
                        var path = CombinePath(parentPath, property.Name);
                        AddPath(path);
                        Visit(property.Value, path, depth + 1);
                        if (!Complete)
                        {
                            return;
                        }
                    }

                    break;

                case JsonValueKind.Array:
                    var itemPath = parentPath switch
                    {
                        null => null,
                        HiddenPath => HiddenPath,
                        _ => $"{parentPath}[]"
                    };
                    if (itemPath is { } arrayPath)
                    {
                        AddPath(arrayPath);
                    }

                    foreach (var item in element.EnumerateArray())
                    {
                        Visit(item, itemPath, depth + 1);
                        if (!Complete)
                        {
                            return;
                        }
                    }

                    break;
            }
        }

        private static string? CombinePath(string? parentPath, string propertyName)
        {
            if (parentPath == HiddenPath)
            {
                return HiddenPath;
            }

            var length = (parentPath?.Length ?? 0) + (parentPath is null ? 0 : 1) + propertyName.Length;
            if (length > MaxPathLength)
            {
                return HiddenPath;
            }

            return parentPath is null ? propertyName : $"{parentPath}.{propertyName}";
        }

        private void AddPath(string? path)
        {
            if (path is null || path == HiddenPath)
            {
                PropertyPathsTruncated = true;
                return;
            }

            if (!_paths.Add(path))
            {
                return;
            }

            if (_propertyPaths.Count >= MaxPropertyPaths)
            {
                PropertyPathsTruncated = true;
                return;
            }

            _propertyPaths.Add(path);
        }

        private void Stop(string error)
        {
            Complete = false;
            Error = error;
        }
    }
}
