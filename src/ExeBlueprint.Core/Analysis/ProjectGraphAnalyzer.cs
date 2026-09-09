using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using ExeBlueprint.Input;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

internal static class ProjectGraphAnalyzer
{
    private const int MaxManifestBytes = 1024 * 1024;
    private const int MaxManifestItems = 4096;
    private const int MaxValueCharacters = 2048;
    private const int MaxSourceComponents = 4096;
    private const int MaxReferences = 100_000;
    private const int MaxReferenceCharacters = 8 * 1024 * 1024;
    private static readonly HashSet<string> ProjectExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".csproj", ".vbproj", ".fsproj", ".vcxproj"
    };
    private static readonly Regex SolutionProject = new(
        "^Project\\(\"[^\"]+\"\\)\\s*=\\s*\"[^\"]*\",\\s*\"(?<path>[^\"]+)\"",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));

    internal static bool IsSourceEntry(string path) => IsProject(path) ||
        Path.GetExtension(path).Equals(".sln", StringComparison.OrdinalIgnoreCase) ||
        Path.GetExtension(path).Equals(".slnx", StringComparison.OrdinalIgnoreCase);

    private static bool IsProject(string path) => ProjectExtensions.Contains(Path.GetExtension(path));

    public static async Task<ProjectGraph> AnalyzeAsync(
        IReadOnlyList<WorkspaceFile> files,
        IReadOnlyList<FileArtifact> artifacts,
        IReadOnlyList<DependencyEdge> dependencies,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var components = new List<ProjectComponent>();
        var references = new List<ProjectReference>();
        var artifactLookup = artifacts.ToDictionary(file => file.Id, StringComparer.Ordinal);
        var projectFiles = files.Where(file => IsSourceEntry(file.LogicalPath) &&
            (!artifactLookup.TryGetValue(file.LogicalPath, out var artifact) || !artifact.IsPortableExecutable)).ToArray();
        var truncated = projectFiles.Length > MaxSourceComponents;
        var referenceCharacters = 0;
        var retainedSourceIds = projectFiles.Take(MaxSourceComponents).Select(file => file.LogicalPath).ToHashSet(StringComparer.Ordinal);
        var paths = projectFiles.GroupBy(file => Normalize(file.LogicalPath), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Select(file => file.LogicalPath).ToArray(), StringComparer.OrdinalIgnoreCase);

        foreach (var file in projectFiles.Take(MaxSourceComponents))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var notes = new List<string>();
            var component = new ProjectComponent
            {
                Id = file.LogicalPath,
                Name = Path.GetFileNameWithoutExtension(Normalize(file.LogicalPath)),
                Kind = IsProject(file.LogicalPath) ? "source-project" : "solution"
            };
            try
            {
                if (artifactLookup.TryGetValue(file.LogicalPath, out var artifact) && artifact.AnalysisError is not null)
                    throw new InvalidDataException("未讀取專案宣告：" + artifact.AnalysisError);
                if (file.Size > MaxManifestBytes)
                {
                    throw new InvalidDataException("專案描述檔超過 1 MiB，未讀取其宣告。");
                }

                await using var stream = new FileStream(file.PhysicalPath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 4096, useAsync: true);
                if (stream.Length > MaxManifestBytes)
                {
                    throw new InvalidDataException("專案描述檔超過 1 MiB，未讀取其宣告。");
                }

                if (Path.GetExtension(file.LogicalPath).Equals(".sln", StringComparison.OrdinalIgnoreCase))
                {
                    using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    var buffer = new char[MaxManifestBytes + 1];
                    var length = await reader.ReadBlockAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                    if (length > MaxManifestBytes) throw new InvalidDataException("方案文字超過讀取上限。");
                    var text = new string(buffer, 0, length);
                    if (!text.TrimStart().StartsWith("Microsoft Visual Studio Solution File, Format Version", StringComparison.Ordinal))
                        throw new InvalidDataException("無法辨識方案檔標頭，未解析專案清單。");
                    var count = 0;
                    foreach (var line in text.Split('\n'))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var match = SolutionProject.Match(line.Trim());
                        if (!match.Success) continue;
                        var path = match.Groups["path"].Value;
                        // .sln 的 solution folder 不是實體專案路徑。
                        if (!IsProject(path))
                        {
                            if (Path.HasExtension(path)) notes.Add("包含尚未支援的方案項目。");
                            continue;
                        }
                        if (++count > MaxManifestItems) throw new InvalidDataException("方案項目超過 4,096 筆，後續項目未讀取。");
                        AddPathReference(path, "solution-project", false);
                    }
                }
                else
                {
                    using var reader = XmlReader.Create(stream, new XmlReaderSettings
                    {
                        Async = true,
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                        MaxCharactersInDocument = MaxManifestBytes,
                        IgnoreComments = true
                    });
                    var xml = await XDocument.LoadAsync(reader, LoadOptions.None, cancellationToken).ConfigureAwait(false);
                    var expectedRoot = component.Kind == "solution" ? "Solution" : "Project";
                    if (xml.Root?.Name.LocalName != expectedRoot)
                        throw new InvalidDataException($"描述檔根節點不是 {expectedRoot}。");
                    if (xml.Root.Name.NamespaceName is not ("" or "http://schemas.microsoft.com/developer/msbuild/2003"))
                        throw new InvalidDataException("描述檔使用不支援的 XML namespace。");
                    var elements = xml.Root.Descendants().Take(MaxManifestItems + 1).ToArray();
                    if (elements.Length > MaxManifestItems)
                        throw new InvalidDataException("描述檔節點超過 4,096 筆，未解析宣告。");
                    if (elements.Any(element => element.Ancestors().Take(65).Count() > 64))
                        throw new InvalidDataException("描述檔巢狀深度超過 64 層，未解析宣告。");

                    if (component.Kind == "source-project")
                    {
                        component = component with
                        {
                            Framework = ReadProperty("TargetFramework") ?? ReadProperty("TargetFrameworks") ?? ReadProperty("TargetFrameworkVersion"),
                            OutputType = ReadProperty("OutputType"),
                            AssemblyName = ReadProperty("AssemblyName")
                        };
                        if (elements.Any(element => element.Name.LocalName is "Import" or "ImportGroup" or "Choose"))
                            notes.Add("包含 Import 或 Choose；僅列出檔內宣告，未執行條件或匯入求值。");
                    }

                    foreach (var element in elements)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (element.Name.Namespace != xml.Root.Name.Namespace) continue;
                        var conditional = element.AncestorsAndSelf().Any(parent => parent.Attribute("Condition") is not null ||
                            parent.Name.LocalName is "Choose" or "When" or "Otherwise" or "Target");
                        if (component.Kind == "solution" && element.Name.LocalName == "Project" &&
                            element.Parent?.Name.LocalName is "Solution" or "Folder")
                            AddPathReference((string?)element.Attribute("Path") ?? "", "solution-project", conditional);
                        else if (component.Kind == "source-project" && element.Parent?.Name.LocalName == "ItemGroup" &&
                                 element.Name.LocalName == "ProjectReference" && element.Attribute("Include") is not null)
                            AddPathReference((string)element.Attribute("Include")!, "project-reference", conditional);
                        else if (component.Kind == "source-project" && element.Parent?.Name.LocalName == "ItemGroup" &&
                                 element.Name.LocalName == "PackageReference" && element.Attribute("Include") is not null)
                        {
                            var include = (string?)element.Attribute("Include");
                            var versionElement = element.Elements().FirstOrDefault(child => child.Name.LocalName == "Version");
                            var version = (string?)element.Attribute("Version") ?? versionElement?.Value;
                            var literalName = IsLiteral(include);
                            AddReference(new ProjectReference
                            {
                                Source = file.LogicalPath,
                                Target = literalName ? include! : "（套件名稱需求值）",
                                Kind = "package-reference",
                                Status = conditional || versionElement?.Attribute("Condition") is not null ? "conditional" :
                                    !literalName || !IsLiteral(version) ? "unevaluated" : "external",
                                Version = IsLiteral(version) ? version : null
                            });
                        }
                    }

                    string? ReadProperty(string name)
                    {
                        var declarations = xml.Root.Elements().Where(group => group.Name.LocalName == "PropertyGroup")
                            .SelectMany(group => group.Elements()).Where(element => element.Name.LocalName == name &&
                                element.Name.Namespace == xml.Root.Name.Namespace).ToArray();
                        if (declarations.Length == 0) return null;
                        if (declarations.Length != 1 || declarations[0].HasElements ||
                            declarations[0].AncestorsAndSelf().Any(element => element.Attribute("Condition") is not null) ||
                            !(name == "TargetFrameworks"
                                ? declarations[0].Value.Length <= MaxValueCharacters && declarations[0].Value.Split(';').All(value => IsLiteral(value.Trim()))
                                : IsLiteral(declarations[0].Value.Trim())))
                        {
                            notes.Add($"{name} 含有條件、重複宣告或運算式，未求值。");
                            return null;
                        }
                        return declarations[0].Value.Trim();
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or XmlException or InvalidDataException or RegexMatchTimeoutException)
            {
                notes.Add(exception is XmlException ? "XML 無效或包含禁止的 DTD，未完整解析宣告。" : exception.Message);
            }
            components.Add(component with { Notes = notes.Distinct().Take(20).ToArray() });

            void AddPathReference(string path, string kind, bool conditional)
            {
                var normalized = ResolveLogicalPath(file, path);
                var status = normalized is null ? "unevaluated" : "missing";
                string target = normalized ?? "（路徑需求值或超出輸入範圍）";
                if (normalized is not null && paths.TryGetValue(normalized, out var matches))
                {
                    var exact = matches.Where(item => Normalize(item).Equals(normalized, StringComparison.Ordinal)).ToArray();
                    if (exact.Length == 1 || matches.Length == 1)
                    {
                        target = exact.Length == 1 ? exact[0] : matches[0];
                        status = retainedSourceIds.Contains(target) ? "resolved" : "unevaluated";
                    }
                    else status = "ambiguous";
                }
                if (conditional) status = "conditional";
                AddReference(new ProjectReference { Source = file.LogicalPath, Target = target, Kind = kind, Status = status });
            }
        }

        var binaryIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in artifacts.Where(file => file.IsPortableExecutable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            binaryIds.Add(file.Id);
            components.Add(new ProjectComponent
            {
                Id = file.Id,
                Name = file.AssemblyName ?? file.FileName,
                Kind = file.IsManaged ? "managed-assembly" : "native-binary",
                AssemblyName = file.AssemblyName,
                OutputType = file.IsExecutable ? "executable" : "library"
            });
        }
        foreach (var edge in dependencies.Where(edge => binaryIds.Contains(edge.Source)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (edge.ResolvedInsidePackage && artifactLookup.TryGetValue(edge.Target, out var targetFile) &&
                !retainedSourceIds.Contains(edge.Target) && !binaryIds.Contains(edge.Target))
            {
                components.Add(new ProjectComponent { Id = targetFile.Id, Name = targetFile.FileName, Kind = "package-file" });
                retainedSourceIds.Add(targetFile.Id);
            }
            AddReference(new ProjectReference
            {
                Source = edge.Source,
                Target = edge.Target,
                Kind = edge.Kind,
                Status = edge.ResolvedInsidePackage ? "resolved" : "external"
            });
        }
        return new ProjectGraph
        {
            Truncated = truncated,
            Components = components.OrderBy(component => component.Id, StringComparer.Ordinal).ToArray(),
            References = references.Distinct().OrderBy(reference => reference.Source, StringComparer.Ordinal)
                .ThenBy(reference => reference.Kind, StringComparer.Ordinal).ThenBy(reference => reference.Target, StringComparer.Ordinal).ToArray()
        };

        void AddReference(ProjectReference reference)
        {
            var characters = reference.Source.Length + reference.Target.Length + (reference.Version?.Length ?? 0);
            if (references.Count >= MaxReferences || characters > MaxReferenceCharacters - referenceCharacters)
            {
                truncated = true;
                return;
            }
            referenceCharacters += characters;
            references.Add(reference);
        }
    }

    private static bool IsLiteral(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= MaxValueCharacters &&
        value.IndexOfAny(['$', '@', '%', '*', '?', ';', '\0', '\r', '\n']) < 0;

    private static string Normalize(string path) => path.Replace('\\', '/');

    private static string? ResolveLogicalPath(WorkspaceFile source, string path)
    {
        if (!IsLiteral(path)) return null;
        path = Normalize(path);
        if (path.StartsWith('/') || path.Contains(':')) return null;
        var normalizedSource = Normalize(source.LogicalPath);
        var minimumDepth = source.Origin.Kind == "asar" && source.Origin.Container is not null
            ? Normalize(source.Origin.Container).Split('/').Length : 0;
        var slash = normalizedSource.LastIndexOf('/');
        var segments = slash < 0 ? [] : normalizedSource[..slash].Split('/').ToList();
        foreach (var segment in path.Split('/'))
        {
            if (segment is "" or ".") continue;
            if (segment == "..")
            {
                if (segments.Count <= minimumDepth) return null;
                segments.RemoveAt(segments.Count - 1);
            }
            else segments.Add(segment);
        }
        return string.Join('/', segments);
    }
}
