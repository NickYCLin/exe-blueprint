using System.Xml;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 僅保留 XML 設定的元素與屬性結構；設定值不會進入分析結果。
internal static class EmbeddedXmlConfigurationReader
{
    internal const int MaxBytes = EmbeddedJsonConfigurationReader.MaxBytes;
    private const int MaxDepth = 32;
    private const int MaxNodes = 20_000;
    private const int MaxProperties = 10_000;
    private const int MaxPropertyPaths = 200;
    private const int MaxPathLength = 512;
    private const string HiddenPath = "\u0000";

    private static readonly XmlReaderSettings ReaderSettings = new()
    {
        Async = false,
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = MaxBytes,
        MaxCharactersFromEntities = 0,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = true,
        CloseInput = true
    };

    public static ManagedResourceConfigurationModel Read(byte[] data)
    {
        if (data.Length > MaxBytes)
        {
            return Partial("XML 設定檔超過 1 MB 安全解析上限。");
        }

        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var reader = XmlReader.Create(stream, ReaderSettings);
            var state = new SummaryState();

            while (reader.Read())
            {
                state.ObserveNode();
                if (!state.Complete)
                {
                    break;
                }

                if (reader.NodeType == XmlNodeType.Element)
                {
                    state.VisitElement(reader);
                }
                else if (reader.NodeType == XmlNodeType.EndElement)
                {
                    state.LeaveElement(reader.Depth);
                }

                if (!state.Complete)
                {
                    break;
                }
            }

            if (!state.SawRoot)
            {
                return Invalid("XML 設定檔沒有根元素。");
            }

            return new ManagedResourceConfigurationModel
            {
                Format = "xml",
                Status = state.Complete ? "parsed" : "partial",
                RootKind = state.RootKind,
                PropertyCount = state.PropertyCount,
                PropertyPaths = state.PropertyPaths,
                PropertyPathsTruncated = state.PropertyPathsTruncated,
                Error = state.Error
            };
        }
        catch (XmlException)
        {
            return Invalid("XML 設定檔格式無效、含禁止的 DTD 或超過安全解析上限。");
        }
    }

    public static ManagedResourceConfigurationModel Unavailable(string error) =>
        Partial(error);

    private static ManagedResourceConfigurationModel Partial(string error) =>
        new()
        {
            Format = "xml",
            Status = "partial",
            PropertyCount = 0,
            PropertyPaths = [],
            PropertyPathsTruncated = false,
            Error = error
        };

    private static ManagedResourceConfigurationModel Invalid(string error) =>
        new()
        {
            Format = "xml",
            Status = "invalid",
            PropertyCount = 0,
            PropertyPaths = [],
            PropertyPathsTruncated = false,
            Error = error
        };

    private sealed class SummaryState
    {
        private readonly HashSet<string> _paths = new(StringComparer.Ordinal);
        private readonly List<string> _propertyPaths = [];
        private readonly List<string> _openElementPaths = [];

        public int PropertyCount { get; private set; }

        public IReadOnlyList<string> PropertyPaths => _propertyPaths;

        public bool PropertyPathsTruncated { get; private set; }

        public bool Complete { get; private set; } = true;

        public string? Error { get; private set; }

        public bool SawRoot { get; private set; }

        public string? RootKind { get; private set; }

        private int NodeCount { get; set; }

        public void ObserveNode()
        {
            NodeCount++;
            if (NodeCount > MaxNodes)
            {
                Stop("XML 設定結構超過 20,000 個節點安全解析上限。");
            }
        }

        public void VisitElement(XmlReader reader)
        {
            if (reader.Depth >= MaxDepth)
            {
                Stop($"XML 設定結構超過 {MaxDepth} 層安全解析上限。");
                return;
            }

            while (_openElementPaths.Count > reader.Depth)
            {
                _openElementPaths.RemoveAt(_openElementPaths.Count - 1);
            }

            var name = reader.Name;
            if (reader.Depth == 0)
            {
                SawRoot = true;
                RootKind = name.Length <= MaxPathLength ? name : null;
            }

            var parentPath = reader.Depth == 0 ? null : _openElementPaths[reader.Depth - 1];
            var path = CombinePath(parentPath, name);
            AddStructureNode(path);
            if (!Complete)
            {
                return;
            }

            for (var index = 0; index < reader.AttributeCount; index++)
            {
                reader.MoveToAttribute(index);
                AddStructureNode(CombinePath(path, $"@{reader.Name}"));
                if (!Complete)
                {
                    reader.MoveToElement();
                    return;
                }
            }

            reader.MoveToElement();
            if (!reader.IsEmptyElement)
            {
                _openElementPaths.Add(path);
            }
        }

        public void LeaveElement(int depth)
        {
            if (_openElementPaths.Count > depth)
            {
                _openElementPaths.RemoveRange(depth, _openElementPaths.Count - depth);
            }
        }

        private void AddStructureNode(string path)
        {
            if (PropertyCount >= MaxProperties)
            {
                Stop($"XML 設定結構超過 {MaxProperties:N0} 個結構節點安全解析上限。");
                return;
            }

            PropertyCount++;
            AddPath(path);
        }

        private static string CombinePath(string? parentPath, string name)
        {
            if (parentPath == HiddenPath)
            {
                return HiddenPath;
            }

            var length = (parentPath?.Length ?? 0) + (parentPath is null ? 0 : 1) + name.Length;
            if (length > MaxPathLength)
            {
                return HiddenPath;
            }

            return parentPath is null ? name : $"{parentPath}/{name}";
        }

        private void AddPath(string path)
        {
            if (path == HiddenPath)
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
