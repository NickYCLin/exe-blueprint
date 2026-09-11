using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using ExeBlueprint.Input;
using ExeBlueprint.Models;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ExeBlueprint.Analysis;

internal static class SourceSemanticAnalyzer
{
    private const int MaxProjectCount = 256;
    private const int MaxSourceFileCount = 10_000;
    private const int MaxProjectFileBytes = 1024 * 1024;
    private const int MaxSourceFileBytes = 1024 * 1024;
    private const int MaxProjectElements = 4096;
    private const long MaxSourceBytes = 32L * 1024 * 1024;
    private const int MaxSyntaxNodesAndTokens = 2_000_000;
    private const int MaxDeclarations = 100_000;
    private const int MaxCalls = 100_000;
    private const int MaxRetainedSymbolCharacters = 32 * 1024 * 1024;
    private const int MaxWarnings = 200;
    private const int MaxNotesPerProject = 20;
    private const int MaxSymbolCharacters = 512;
    private static readonly HashSet<string> ExcludedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".svn", ".hg", ".vs", ".idea", "bin", "obj", "node_modules", ".venv", "venv",
        "artifacts", "exe-blueprint-output"
    };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly CSharpParseOptions ParseOptions = new(
        LanguageVersion.Preview,
        DocumentationMode.Parse,
        SourceCodeKind.Regular);

    public static async Task<SourceCodeAnalysis> AnalyzeAsync(
        IReadOnlyList<WorkspaceFile> files,
        ProjectGraph graph,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var warnings = new WarningCollector();
        warnings.Add("C# 語意分析使用分析器執行環境的 framework 參考組件，不等同各專案目標框架；不會還原 NuGet 套件。");
        warnings.Add("C# 語意分析不執行 SDK targets、Analyzer 或 source generator；產生的來源不在索引內。");
        var workspacePaths = files.GroupBy(file => Normalize(file.LogicalPath), StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        var allProjectFiles = files.Where(file => Path.GetExtension(file.LogicalPath)
                .Equals(".csproj", StringComparison.OrdinalIgnoreCase))
            .OrderBy(file => file.LogicalPath, StringComparer.Ordinal).ToArray();
        var truncated = allProjectFiles.Length > MaxProjectCount;
        if (truncated) warnings.Add($"C# 語意分析最多處理 {MaxProjectCount:N0} 個專案；其餘專案未載入。");

        var plans = new List<ProjectPlan>();
        foreach (var file in allProjectFiles.Take(MaxProjectCount))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var component = graph.Components.FirstOrDefault(item => item.Id == file.LogicalPath);
            var plan = await ReadProjectPlanAsync(file, component, workspacePaths, cancellationToken).ConfigureAwait(false);
            plans.Add(plan);
        }
        foreach (var group in plans.GroupBy(plan => plan.AssemblyName, StringComparer.OrdinalIgnoreCase))
        {
            var sameName = group.OrderBy(plan => plan.Project, StringComparer.Ordinal).ToArray();
            for (var index = 0; index < sameName.Length; index++)
            {
                sameName[index].CompilationName = sameName.Length == 1
                    ? sameName[index].AssemblyName
                    : $"ExeBlueprint.Source.{plans.IndexOf(sameName[index]):D4}";
                if (sameName.Length > 1)
                    sameName[index].MarkIncomplete($"AssemblyName 與其他專案重複（{sameName[index].AssemblyName}），語意分析改用內部代號。");
            }
        }

        var projectDirectories = plans.GroupBy(plan => plan.Directory, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        var allProjectDirectories = allProjectFiles.GroupBy(file => GetDirectory(file.LogicalPath), StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        var sourceFiles = files.Where(file => Path.GetExtension(file.LogicalPath)
                .Equals(".cs", StringComparison.OrdinalIgnoreCase) && !HasExcludedDirectory(file.LogicalPath))
            .OrderBy(file => file.LogicalPath, StringComparer.Ordinal).ToArray();
        var projectDirectoriesByDepth = allProjectDirectories.Keys
            .OrderByDescending(directory => directory.Length).ThenBy(directory => directory, StringComparer.Ordinal)
            .ToArray();
        var defaultSources = projectDirectories.Keys.ToDictionary(directory => directory,
            _ => new List<WorkspaceFile>(), StringComparer.Ordinal);
        foreach (var source in sourceFiles)
        {
            var owner = projectDirectoriesByDepth.FirstOrDefault(directory => IsUnderDirectory(source.LogicalPath, directory));
            if (owner is not null && defaultSources.TryGetValue(owner, out var ownedSources)) ownedSources.Add(source);
        }
        var totalSourceFiles = 0;
        long totalSourceBytes = 0;
        var totalSyntaxNodes = 0;
        var sourceLimitReached = false;

        foreach (var plan in plans)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var selected = new Dictionary<string, WorkspaceFile>(StringComparer.Ordinal);
            if (plan.DefaultCompileItems)
            {
                if (allProjectDirectories[plan.Directory].Length > 1)
                {
                    plan.MarkIncomplete("同一個目錄包含多個 C# 專案，無法確定預設 Compile 項目歸屬。");
                }
                else
                {
                    foreach (var source in defaultSources[plan.Directory]) selected[source.LogicalPath] = source;
                }
            }
            foreach (var include in plan.Includes)
            {
                if (workspacePaths.TryGetValue(include, out var matches) && matches.Length == 1 &&
                    Path.GetExtension(matches[0].LogicalPath).Equals(".cs", StringComparison.OrdinalIgnoreCase))
                    selected[matches[0].LogicalPath] = matches[0];
                else plan.MarkIncomplete($"找不到明確的 Compile Include：{include}");
            }
            foreach (var remove in plan.Removes) selected.Remove(remove);

            foreach (var source in selected.Values.OrderBy(file => file.LogicalPath, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (sourceLimitReached)
                {
                    plan.MarkIncomplete("已達 C# 來源分析總量上限，後續檔案未載入。");
                    continue;
                }
                if (totalSourceFiles >= MaxSourceFileCount)
                {
                    truncated = sourceLimitReached = true;
                    plan.MarkIncomplete($"C# 來源檔案超過 {MaxSourceFileCount:N0} 個，後續檔案未載入。");
                    continue;
                }
                if (source.Size > MaxSourceFileBytes)
                {
                    truncated = true;
                    plan.MarkIncomplete($"{source.LogicalPath} 超過 1 MiB，未載入語意分析。");
                    continue;
                }
                if (source.Size > MaxSourceBytes - totalSourceBytes)
                {
                    truncated = sourceLimitReached = true;
                    plan.MarkIncomplete("C# 來源檔累計超過 32 MiB，後續檔案未載入。");
                    continue;
                }

                try
                {
                    var text = await ReadSourceTextAsync(source, cancellationToken).ConfigureAwait(false);
                    var tree = CSharpSyntaxTree.ParseText(text, ParseOptions, source.LogicalPath,
                        Encoding.UTF8, cancellationToken);
                    var root = await tree.GetRootAsync(cancellationToken).ConfigureAwait(false);
                    if (root.DescendantTrivia(descendIntoTrivia: true).Any(trivia => trivia.Kind() is
                            SyntaxKind.IfDirectiveTrivia or SyntaxKind.ElifDirectiveTrivia or
                            SyntaxKind.ElseDirectiveTrivia or SyntaxKind.EndIfDirectiveTrivia))
                    {
                        plan.MarkIncomplete("來源碼包含條件式編譯指示；目前未求值 DefineConstants，只索引預設符號分支。");
                    }
                    var remainingNodes = MaxSyntaxNodesAndTokens - totalSyntaxNodes;
                    var nodeCount = root.DescendantNodesAndTokens(descendIntoTrivia: false)
                        .Take(remainingNodes + 1).Count();
                    if (nodeCount > remainingNodes)
                    {
                        truncated = sourceLimitReached = true;
                        plan.MarkIncomplete($"C# 語法節點累計超過 {MaxSyntaxNodesAndTokens:N0} 筆，後續檔案未載入。");
                        continue;
                    }
                    totalSourceFiles++;
                    totalSourceBytes += source.Size;
                    totalSyntaxNodes += nodeCount;
                    plan.Documents.Add(new SourceDocument(source.LogicalPath, tree, root));
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                                  DecoderFallbackException or InvalidDataException)
                {
                    plan.MarkIncomplete($"無法讀取 {source.LogicalPath}：{exception.Message}");
                }
            }
        }

        var byId = plans.ToDictionary(plan => plan.Project, StringComparer.Ordinal);
        foreach (var plan in plans)
        {
            plan.Dependencies.AddRange(graph.References.Where(reference =>
                    reference.Source == plan.Project && reference.Kind == "project-reference" &&
                    reference.Status == "resolved" && byId.ContainsKey(reference.Target))
                .Select(reference => reference.Target).Distinct(StringComparer.Ordinal));
        }

        var frameworkReferences = CreateFrameworkReferences(warnings);
        var buildStates = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var plan in plans)
            BuildCompilation(plan, byId, buildStates, frameworkReferences, cancellationToken);

        var assemblyProjects = plans.Where(plan => plan.Compilation is not null)
            .ToDictionary(plan => plan.Compilation!.AssemblyName!, plan => plan.Project, StringComparer.Ordinal);
        var declarations = new List<SourceDeclaration>();
        var calls = new List<SourceCall>();
        var summaries = new List<SourceProjectSummary>();
        var retainedSymbolCharacters = 0;
        foreach (var plan in plans)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var declarationStart = declarations.Count;
            var callStart = calls.Count;
            if (plan.Compilation is not null)
            {
                var diagnostics = plan.Compilation.GetDiagnostics(cancellationToken)
                    .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToArray();
                plan.ErrorCount = diagnostics.Length;
                plan.ErrorCodes.AddRange(diagnostics.GroupBy(diagnostic => diagnostic.Id, StringComparer.Ordinal)
                    .OrderByDescending(group => group.Count()).ThenBy(group => group.Key, StringComparer.Ordinal)
                    .Take(10).Select(group => $"{group.Key} × {group.Count():N0}"));
                if (diagnostics.Length > 0)
                    plan.MarkIncomplete($"Roslyn 回報 {diagnostics.Length:N0} 個編譯錯誤；仍保留能確定的宣告與呼叫。");

                foreach (var document in plan.Documents)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var model = plan.Compilation.GetSemanticModel(document.Tree, ignoreAccessibility: true);
                    foreach (var node in document.Root.DescendantNodes())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var declared = GetDeclaredSymbol(model, node, cancellationToken);
                        if (declared is not null)
                        {
                            if (declarations.Count >= MaxDeclarations)
                            {
                                truncated = true;
                                plan.MarkIncomplete($"C# 宣告超過 {MaxDeclarations:N0} 筆，後續宣告未保留。");
                            }
                            else
                            {
                                var declaration = new SourceDeclaration
                                {
                                    Id = CreateSourceSymbolId(plan.Project, declared),
                                    Project = plan.Project,
                                    File = document.Path,
                                    Line = GetLine(node),
                                    Kind = GetDeclarationKind(declared),
                                    Name = BoundSymbolText(declared.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat))
                                };
                                var characters = declaration.Id.Length + declaration.Project.Length +
                                    declaration.File.Length + declaration.Kind.Length + declaration.Name.Length;
                                if (characters > MaxRetainedSymbolCharacters - retainedSymbolCharacters)
                                {
                                    truncated = true;
                                    plan.MarkIncomplete("C# 符號文字累計超過 32 Mi 個字元，後續宣告未保留。");
                                }
                                else
                                {
                                    retainedSymbolCharacters += characters;
                                    declarations.Add(declaration);
                                }
                            }
                        }

                        if (!TryGetCallSymbolInfo(model, node, cancellationToken, out var info, out var kind)) continue;
                        if (calls.Count >= MaxCalls)
                        {
                            truncated = true;
                            plan.MarkIncomplete($"C# 呼叫超過 {MaxCalls:N0} 筆，後續呼叫未保留。");
                            continue;
                        }
                        var enclosing = model.GetEnclosingSymbol(node.SpanStart, cancellationToken);
                        var caller = enclosing is null ? $"{plan.Project}::(全域程式碼)" :
                            CreateSourceSymbolId(plan.Project, enclosing);
                        var method = info.Symbol as IMethodSymbol;
                        string target;
                        string status;
                        string? targetProject = null;
                        if (method is not null)
                        {
                            method = method.ReducedFrom ?? method;
                            if (method.ContainingAssembly is not null &&
                                assemblyProjects.TryGetValue(method.ContainingAssembly.Name, out targetProject))
                            {
                                target = CreateSourceSymbolId(targetProject, method);
                                status = "resolved-source";
                            }
                            else
                            {
                                target = CreateExternalSymbolId(method);
                                status = "external";
                            }
                        }
                        else if (info.CandidateSymbols.Length > 0)
                        {
                            target = CreateExternalSymbolId(info.CandidateSymbols[0]);
                            status = "ambiguous";
                        }
                        else
                        {
                            target = "（無法解析）";
                            status = "unresolved";
                        }
                        var call = new SourceCall
                        {
                            Caller = caller,
                            Target = target,
                            SourceProject = plan.Project,
                            TargetProject = targetProject,
                            File = document.Path,
                            Line = GetLine(node),
                            Kind = kind,
                            Status = status
                        };
                        var callCharacters = call.Caller.Length + call.Target.Length + call.SourceProject.Length +
                            (call.TargetProject?.Length ?? 0) + call.File.Length + call.Kind.Length + call.Status.Length;
                        if (callCharacters > MaxRetainedSymbolCharacters - retainedSymbolCharacters)
                        {
                            truncated = true;
                            plan.MarkIncomplete("C# 符號文字累計超過 32 Mi 個字元，後續呼叫未保留。");
                        }
                        else
                        {
                            retainedSymbolCharacters += callCharacters;
                            calls.Add(call);
                        }
                    }
                }
            }

            summaries.Add(new SourceProjectSummary
            {
                Project = plan.Project,
                FileCount = plan.Documents.Count,
                DeclarationCount = declarations.Count - declarationStart,
                CallCount = calls.Count - callStart,
                ErrorCount = plan.ErrorCount,
                ErrorCodes = plan.ErrorCodes.ToArray(),
                Complete = plan.Complete,
                Notes = plan.Notes.Distinct(StringComparer.Ordinal).Take(MaxNotesPerProject).ToArray()
            });
        }

        return new SourceCodeAnalysis
        {
            Truncated = truncated,
            Projects = summaries,
            Declarations = declarations,
            Calls = calls,
            Warnings = warnings.ToArray()
        };
    }

    private static async Task<ProjectPlan> ReadProjectPlanAsync(
        WorkspaceFile file,
        ProjectComponent? component,
        IReadOnlyDictionary<string, WorkspaceFile[]> workspacePaths,
        CancellationToken cancellationToken)
    {
        var assemblyName = component?.AssemblyName ?? component?.Name ?? Path.GetFileNameWithoutExtension(file.LogicalPath);
        var replacedAssemblyName = !IsSafeAssemblyName(assemblyName);
        if (replacedAssemblyName)
            assemblyName = $"ExeBlueprint.Source.{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(file.LogicalPath)))[..12]}";
        var plan = new ProjectPlan(file.LogicalPath, GetDirectory(file.LogicalPath), assemblyName);
        if (replacedAssemblyName) plan.MarkIncomplete("AssemblyName 無法安全用於 Roslyn compilation，已改用內部代號。");
        var validImplicitUsings = ApplyImplicitUsingsSetting(component?.ImplicitUsings, out var implicitUsings);
        var validUnsafe = ApplyBooleanSetting(component?.AllowUnsafeBlocks, false, out var allowUnsafe);
        var validDefaultItems = ApplyBooleanSetting(component?.EnableDefaultItems, true, out var defaultItems);
        var validDefaultCompileItems = ApplyBooleanSetting(component?.EnableDefaultCompileItems, true, out var defaultCompileItems);
        if (!validImplicitUsings || !validUnsafe || !validDefaultItems || !validDefaultCompileItems)
        {
            plan.Disable("ImplicitUsings、AllowUnsafeBlocks 或預設 Compile 設定不是可確認的值。");
            return plan;
        }
        plan.ImplicitUsings = implicitUsings;
        plan.AllowUnsafe = allowUnsafe;
        plan.DefaultCompileItems = defaultItems && defaultCompileItems;
        plan.OutputKind = component?.OutputType?.Equals("Exe", StringComparison.OrdinalIgnoreCase) == true
            ? OutputKind.ConsoleApplication
            : component?.OutputType?.Equals("WinExe", StringComparison.OrdinalIgnoreCase) == true
                ? OutputKind.WindowsApplication
                : OutputKind.DynamicallyLinkedLibrary;
        if (file.Size > MaxProjectFileBytes)
        {
            plan.Disable("專案檔超過 1 MiB，未建立 C# 語意分析。");
            return plan;
        }

        try
        {
            await using var stream = new FileStream(file.PhysicalPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                Async = true,
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxProjectFileBytes,
                IgnoreComments = true
            });
            var xml = await XDocument.LoadAsync(reader, LoadOptions.None, cancellationToken).ConfigureAwait(false);
            if (xml.Root?.Name.LocalName != "Project" ||
                xml.Root.Name.NamespaceName is not ("" or "http://schemas.microsoft.com/developer/msbuild/2003"))
            {
                plan.Disable("不是支援的 MSBuild C# 專案檔。");
                return plan;
            }
            var ns = xml.Root.Name.Namespace;
            var elements = xml.Root.Descendants().Take(MaxProjectElements + 1).ToArray();
            if (elements.Length > MaxProjectElements || elements.Any(element => element.Ancestors().Take(65).Count() > 64))
            {
                plan.Disable("專案檔超過節點或巢狀深度限制。");
                return plan;
            }
            var sdk = (string?)xml.Root.Attribute("Sdk");
            var sdkElements = xml.Root.Elements().Where(element => element.Name.Namespace == ns &&
                element.Name.LocalName == "Sdk").ToArray();
            var sdkName = sdk ?? (sdkElements.Length == 1 ? (string?)sdkElements[0].Attribute("Name") : null);
            var sdkStyle = IsLiteral(sdk) || sdkElements.Length == 1 &&
                IsLiteral((string?)sdkElements[0].Attribute("Name")) && sdkElements[0].Attribute("Condition") is null;
            if (!sdkStyle)
            {
                plan.Disable("目前只支援可確認的 SDK-style C# 專案。");
                return plan;
            }
            if (!sdkName!.Split('/', 2)[0].Equals("Microsoft.NET.Sdk", StringComparison.OrdinalIgnoreCase))
                plan.MarkIncomplete($"專案使用 {sdkName}；未執行 SDK 特有的來源產生與 implicit usings。");
            if (!await SharedBuildFilesKeepCompileItemsDeterministicAsync(file, workspacePaths, cancellationToken)
                    .ConfigureAwait(false))
            {
                plan.Disable("共用 props／targets 含自訂建置邏輯，無法安全確定 Compile 項目。");
                return plan;
            }
            if (elements.Any(element => element.Name.Namespace == ns &&
                element.Name.LocalName is "Import" or "ImportGroup" or "Choose" or "Target"))
            {
                plan.Disable("專案含自訂 Import、Choose 或 Target，無法安全確定 Compile 項目。");
                return plan;
            }

            var booleanProperties = new[] { "EnableDefaultItems", "EnableDefaultCompileItems", "AllowUnsafeBlocks" };
            foreach (var propertyName in booleanProperties)
            {
                var declarations = xml.Root.Elements().Where(group => group.Name.Namespace == ns &&
                        group.Name.LocalName == "PropertyGroup")
                    .SelectMany(group => group.Elements()).Where(element => element.Name.Namespace == ns &&
                        element.Name.LocalName == propertyName).ToArray();
                if (declarations.Length == 0) continue;
                if (declarations.Length != 1 || declarations[0].AncestorsAndSelf().Any(HasCondition) ||
                    !bool.TryParse(declarations[0].Value.Trim(), out var enabled))
                {
                    plan.Disable($"{propertyName} 含條件、重複宣告或運算式。");
                    return plan;
                }
                if (!enabled && propertyName is "EnableDefaultItems" or "EnableDefaultCompileItems")
                    plan.DefaultCompileItems = false;
            }
            var implicitUsingsDeclarations = ReadDirectPropertyDeclarations(xml.Root, ns, "ImplicitUsings");
            if (implicitUsingsDeclarations.Length > 0 &&
                (implicitUsingsDeclarations.Length != 1 ||
                 implicitUsingsDeclarations[0].AncestorsAndSelf().Any(HasCondition) ||
                 !ApplyImplicitUsingsSetting(implicitUsingsDeclarations[0].Value.Trim(), out _)))
            {
                plan.Disable("ImplicitUsings 含條件、重複宣告或無法辨識的值。");
                return plan;
            }
            if (elements.Any(element => element.Name.Namespace == ns &&
                element.Name.LocalName is "DefaultItemExcludes" or "DefaultItemExcludesInProjectFolder"))
            {
                plan.Disable("專案自訂 DefaultItemExcludes，無法安全確定來源檔歸屬。");
                return plan;
            }
            if (elements.Any(element => element.Name.Namespace == ns &&
                element.Parent?.Name.Namespace == ns && element.Parent.Name.LocalName == "ItemGroup" &&
                element.Name.LocalName is "Using" or "Analyzer" or "AdditionalFiles"))
            {
                plan.MarkIncomplete("專案含 Using、Analyzer 或 AdditionalFiles 項目；未執行隱含 using、分析器或來源產生器。");
            }

            foreach (var compile in elements.Where(element => element.Name.Namespace == ns &&
                         element.Name.LocalName == "Compile" && element.Parent?.Name.Namespace == ns &&
                         element.Parent.Name.LocalName == "ItemGroup"))
            {
                if (compile.AncestorsAndSelf().Any(HasCondition) || compile.Attribute("Exclude") is not null)
                {
                    plan.Disable("Compile 項目含條件或 Exclude，無法安全確定來源檔歸屬。");
                    return plan;
                }
                var include = (string?)compile.Attribute("Include");
                var remove = (string?)compile.Attribute("Remove");
                if (include is not null && remove is not null)
                {
                    plan.Disable("同一個 Compile 項目同時宣告 Include 與 Remove，無法安全確定來源歸屬。");
                    return plan;
                }
                if (include is null && remove is null) continue;
                var value = include ?? remove!;
                var resolved = ResolveLogicalPath(file, value);
                if (resolved is null)
                {
                    plan.Disable("Compile Include／Remove 含變數、萬用字元或工作區外路徑。");
                    return plan;
                }
                if (include is not null) plan.Includes.Add(resolved);
                else plan.Removes.Add(resolved);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or XmlException or InvalidDataException)
        {
            plan.Disable(exception is XmlException
                ? "專案 XML 無效或包含禁止的 DTD。" : exception.Message);
        }
        return plan;
    }

    private static bool ApplyBooleanSetting(string? value, bool defaultValue, out bool enabled)
    {
        if (value is null)
        {
            enabled = defaultValue;
            return true;
        }
        return bool.TryParse(value, out enabled);
    }

    private static bool ApplyImplicitUsingsSetting(string? value, out bool enabled)
    {
        if (value is null)
        {
            enabled = false;
            return true;
        }
        if (value.Equals("enable", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            enabled = true;
            return true;
        }
        if (value.Equals("disable", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("false", StringComparison.OrdinalIgnoreCase))
        {
            enabled = false;
            return true;
        }
        enabled = false;
        return false;
    }

    private static XElement[] ReadDirectPropertyDeclarations(XElement root, XNamespace ns, string propertyName) =>
        root.Elements().Where(group => group.Name.Namespace == ns && group.Name.LocalName == "PropertyGroup")
            .SelectMany(group => group.Elements()).Where(element => element.Name.Namespace == ns &&
                element.Name.LocalName == propertyName).ToArray();

    private static async Task<bool> SharedBuildFilesKeepCompileItemsDeterministicAsync(
        WorkspaceFile project,
        IReadOnlyDictionary<string, WorkspaceFile[]> workspacePaths,
        CancellationToken cancellationToken)
    {
        if (FindNearestSharedFile(project, "Directory.Build.targets", workspacePaths) is not null) return false;
        var props = FindNearestSharedFile(project, "Directory.Build.props", workspacePaths);
        if (props is null) return true;
        if (props.Size > MaxProjectFileBytes) return false;
        try
        {
            await using var stream = new FileStream(props.PhysicalPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stream.Length > MaxProjectFileBytes) return false;
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                Async = true,
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxProjectFileBytes,
                IgnoreComments = true
            });
            var xml = await XDocument.LoadAsync(reader, LoadOptions.None, cancellationToken).ConfigureAwait(false);
            if (xml.Root?.Name.LocalName != "Project" ||
                xml.Root.Name.NamespaceName is not ("" or "http://schemas.microsoft.com/developer/msbuild/2003")) return false;
            var ns = xml.Root.Name.Namespace;
            var elements = xml.Root.Descendants().Take(MaxProjectElements + 1).ToArray();
            if (elements.Length > MaxProjectElements || elements.Any(element => element.Ancestors().Take(65).Count() > 64))
                return false;
            foreach (var propertyName in new[] { "EnableDefaultItems", "EnableDefaultCompileItems", "AllowUnsafeBlocks" })
            {
                var declarations = ReadDirectPropertyDeclarations(xml.Root, ns, propertyName);
                if (declarations.Length > 0 && (declarations.Length != 1 ||
                    declarations[0].AncestorsAndSelf().Any(HasCondition) ||
                    !bool.TryParse(declarations[0].Value.Trim(), out _))) return false;
            }
            var implicitUsingsDeclarations = ReadDirectPropertyDeclarations(xml.Root, ns, "ImplicitUsings");
            if (implicitUsingsDeclarations.Length > 0 &&
                (implicitUsingsDeclarations.Length != 1 ||
                 implicitUsingsDeclarations[0].AncestorsAndSelf().Any(HasCondition) ||
                 !ApplyImplicitUsingsSetting(implicitUsingsDeclarations[0].Value.Trim(), out _))) return false;
            return !elements.Any(element => element.Name.Namespace == ns &&
                element.Name.LocalName is "Compile" or "Import" or "ImportGroup" or "Choose" or "Target" or
                    "DefaultItemExcludes" or "DefaultItemExcludesInProjectFolder" or "Using" or "Analyzer" or
                    "AdditionalFiles");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or XmlException or InvalidDataException)
        {
            return false;
        }
    }

    private static WorkspaceFile? FindNearestSharedFile(
        WorkspaceFile project,
        string fileName,
        IReadOnlyDictionary<string, WorkspaceFile[]> workspacePaths)
    {
        var segments = GetDirectory(project.LogicalPath).Split('/', StringSplitOptions.RemoveEmptyEntries).ToList();
        var minimumDepth = project.Origin.Kind == "asar" && project.Origin.Container is not null
            ? Normalize(project.Origin.Container).Split('/').Length : 0;
        while (segments.Count >= minimumDepth)
        {
            var candidate = segments.Count == 0 ? fileName : string.Join('/', segments) + "/" + fileName;
            if (workspacePaths.TryGetValue(candidate, out var matches) && matches.Length == 1) return matches[0];
            if (segments.Count == minimumDepth) break;
            segments.RemoveAt(segments.Count - 1);
        }
        return null;
    }

    private static void BuildCompilation(
        ProjectPlan plan,
        IReadOnlyDictionary<string, ProjectPlan> plans,
        IDictionary<string, int> states,
        IReadOnlyList<MetadataReference> frameworkReferences,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!plan.CanCompile)
        {
            states[plan.Project] = 2;
            return;
        }
        if (states.TryGetValue(plan.Project, out var state))
        {
            if (state == 1) plan.MarkIncomplete("ProjectReference 形成循環，相依專案未完整加入 Roslyn compilation。");
            return;
        }
        states[plan.Project] = 1;
        var references = new List<MetadataReference>(frameworkReferences);
        foreach (var dependencyId in plan.Dependencies)
        {
            if (!plans.TryGetValue(dependencyId, out var dependency)) continue;
            if (states.TryGetValue(dependencyId, out var dependencyState) && dependencyState == 1)
            {
                plan.MarkIncomplete($"與 {dependencyId} 形成循環 ProjectReference；該方向未加入 compilation。");
                dependency.MarkIncomplete($"與 {plan.Project} 形成循環 ProjectReference；該方向未加入 compilation。");
                continue;
            }
            BuildCompilation(dependency, plans, states, frameworkReferences, cancellationToken);
            if (dependency.Compilation is not null)
            {
                references.Add(dependency.Compilation.ToMetadataReference());
                if (!dependency.Complete)
                    plan.MarkIncomplete($"相依專案 {dependencyId} 的語意索引不完整。");
            }
            else plan.MarkIncomplete($"無法載入相依專案 {dependencyId} 的 compilation。");
        }
        var syntaxTrees = plan.Documents.Select(document => document.Tree).ToList();
        if (plan.ImplicitUsings)
            syntaxTrees.Insert(0, CSharpSyntaxTree.ParseText("""
                global using System;
                global using System.Collections.Generic;
                global using System.IO;
                global using System.Linq;
                global using System.Net.Http;
                global using System.Threading;
                global using System.Threading.Tasks;
                """, ParseOptions, $"{plan.Project}::(implicit-usings)", Encoding.UTF8, cancellationToken));
        plan.Compilation = CSharpCompilation.Create(
            plan.CompilationName,
            syntaxTrees,
            references,
            new CSharpCompilationOptions(plan.OutputKind,
                nullableContextOptions: NullableContextOptions.Enable,
                allowUnsafe: plan.AllowUnsafe,
                concurrentBuild: false));
        states[plan.Project] = 2;
    }

    private static IReadOnlyList<MetadataReference> CreateFrameworkReferences(WarningCollector warnings)
    {
        var trusted = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string;
        if (string.IsNullOrWhiteSpace(trusted))
        {
            warnings.Add("執行環境未提供 TRUSTED_PLATFORM_ASSEMBLIES；framework 呼叫可能無法解析。");
            return [];
        }
        var references = new List<MetadataReference>();
        var runtimeDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(RuntimeEnvironment.GetRuntimeDirectory()));
        foreach (var path in trusted.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .Where(path => Path.GetDirectoryName(Path.GetFullPath(path))?.Equals(runtimeDirectory,
                         OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) == true))
        {
            try { references.Add(MetadataReference.CreateFromFile(path)); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or BadImageFormatException)
            {
                warnings.Add($"無法載入 framework 參考組件 {Path.GetFileName(path)}：{exception.Message}");
            }
        }
        return references;
    }

    private static ISymbol? GetDeclaredSymbol(SemanticModel model, SyntaxNode node, CancellationToken token) => node switch
    {
        BaseTypeDeclarationSyntax declaration => model.GetDeclaredSymbol(declaration, token),
        DelegateDeclarationSyntax declaration => model.GetDeclaredSymbol(declaration, token),
        BaseMethodDeclarationSyntax declaration => model.GetDeclaredSymbol(declaration, token),
        AccessorDeclarationSyntax declaration => model.GetDeclaredSymbol(declaration, token),
        LocalFunctionStatementSyntax declaration => model.GetDeclaredSymbol(declaration, token),
        _ => null
    };

    private static bool TryGetCallSymbolInfo(
        SemanticModel model,
        SyntaxNode node,
        CancellationToken token,
        out SymbolInfo info,
        out string kind)
    {
        switch (node)
        {
            case InvocationExpressionSyntax invocation:
                info = model.GetSymbolInfo(invocation, token);
                kind = "invocation";
                return true;
            case ObjectCreationExpressionSyntax creation:
                info = model.GetSymbolInfo(creation, token);
                kind = "object-creation";
                return true;
            case ImplicitObjectCreationExpressionSyntax creation:
                info = model.GetSymbolInfo(creation, token);
                kind = "object-creation";
                return true;
            case ConstructorInitializerSyntax initializer:
                info = model.GetSymbolInfo(initializer, token);
                kind = "constructor-initializer";
                return true;
            default:
                info = default;
                kind = string.Empty;
                return false;
        }
    }

    private static string GetDeclarationKind(ISymbol symbol) => symbol switch
    {
        INamedTypeSymbol type => type.TypeKind.ToString().ToLowerInvariant(),
        IMethodSymbol method => method.MethodKind switch
        {
            MethodKind.Constructor or MethodKind.StaticConstructor => "constructor",
            MethodKind.Destructor => "destructor",
            MethodKind.PropertyGet or MethodKind.PropertySet => "accessor",
            MethodKind.UserDefinedOperator or MethodKind.Conversion => "operator",
            MethodKind.LocalFunction => "local-function",
            _ => "method"
        },
        _ => symbol.Kind.ToString().ToLowerInvariant()
    };

    private static string CreateSourceSymbolId(string project, ISymbol symbol) =>
        BoundSymbolText($"{project}::{CreateExternalSymbolId(symbol)}");

    private static string CreateExternalSymbolId(ISymbol symbol)
    {
        var value = symbol.GetDocumentationCommentId() ??
            symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return BoundSymbolText(value);
    }

    private static string BoundSymbolText(string value)
    {
        var builder = new StringBuilder(Math.Min(value.Length, MaxSymbolCharacters));
        foreach (var character in value)
        {
            var category = char.GetUnicodeCategory(character);
            if (char.IsControl(character) || category == UnicodeCategory.Format)
                builder.Append($"\\u{(int)character:X4}");
            else builder.Append(character);
        }
        var safe = builder.ToString();
        if (safe.Length <= MaxSymbolCharacters) return safe;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(safe)))[..16].ToLowerInvariant();
        return safe[..(MaxSymbolCharacters - hash.Length - 2)] + "…#" + hash;
    }

    private static int GetLine(SyntaxNode node) =>
        node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

    private static async Task<string> ReadSourceTextAsync(WorkspaceFile file, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(file.PhysicalPath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > MaxSourceFileBytes)
            throw new InvalidDataException("來源檔案在分析期間超過 1 MiB。");
        using var reader = new StreamReader(stream, StrictUtf8, detectEncodingFromByteOrderMarks: true);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    private static bool HasCondition(XElement element) => element.Attribute("Condition") is not null ||
        element.Name.LocalName is "Choose" or "When" or "Otherwise" or "Target";

    private static bool IsLiteral(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 2048 &&
        value.IndexOfAny(['$', '@', '%', '*', '?', ';', '\0', '\r', '\n']) < 0;

    private static bool IsSafeAssemblyName(string value) => value.Length is > 0 and <= 256 &&
        value.All(character => char.IsLetterOrDigit(character) || character is '.' or '_' or '-');

    private static string? ResolveLogicalPath(WorkspaceFile project, string path)
    {
        if (!IsLiteral(path)) return null;
        path = Normalize(path);
        if (path.StartsWith('/') || path.Contains(':')) return null;
        var segments = GetDirectory(project.LogicalPath).Split('/', StringSplitOptions.RemoveEmptyEntries).ToList();
        var minimumDepth = project.Origin.Kind == "asar" && project.Origin.Container is not null
            ? Normalize(project.Origin.Container).Split('/').Length : 0;
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

    private static bool IsUnderDirectory(string path, string directory) => directory.Length == 0 ||
        Normalize(path).StartsWith(directory + "/", StringComparison.Ordinal);

    private static string GetDirectory(string path)
    {
        path = Normalize(path);
        var slash = path.LastIndexOf('/');
        return slash < 0 ? string.Empty : path[..slash];
    }

    private static bool HasExcludedDirectory(string path)
    {
        return Normalize(path).Split('/').SkipLast(1).Any(ExcludedDirectories.Contains);
    }

    private static string Normalize(string path) => path.Replace('\\', '/');

    private sealed record SourceDocument(string Path, SyntaxTree Tree, SyntaxNode Root);

    private sealed class ProjectPlan(string project, string directory, string assemblyName)
    {
        public string Project { get; } = project;
        public string Directory { get; } = directory;
        public string AssemblyName { get; } = assemblyName;
        public string CompilationName { get; set; } = assemblyName;
        public bool DefaultCompileItems { get; set; } = true;
        public bool ImplicitUsings { get; set; }
        public bool AllowUnsafe { get; set; }
        public bool CanCompile { get; private set; } = true;
        public bool Complete { get; private set; } = true;
        public int ErrorCount { get; set; }
        public OutputKind OutputKind { get; set; } = OutputKind.DynamicallyLinkedLibrary;
        public List<string> Includes { get; } = [];
        public List<string> Removes { get; } = [];
        public List<string> Dependencies { get; } = [];
        public List<string> Notes { get; } = [];
        public List<string> ErrorCodes { get; } = [];
        public List<SourceDocument> Documents { get; } = [];
        public CSharpCompilation? Compilation { get; set; }

        public void MarkIncomplete(string note)
        {
            Complete = false;
            if (Notes.Count < MaxNotesPerProject) Notes.Add(note);
        }

        public void Disable(string note)
        {
            CanCompile = false;
            DefaultCompileItems = false;
            Includes.Clear();
            Removes.Clear();
            MarkIncomplete(note);
        }
    }

    private sealed class WarningCollector
    {
        private readonly List<string> _warnings = [];
        private int _omitted;

        public void Add(string warning)
        {
            if (_warnings.Count < MaxWarnings) _warnings.Add(warning);
            else _omitted++;
        }

        public IReadOnlyList<string> ToArray() => _omitted == 0 ? _warnings.ToArray() :
            [.. _warnings, $"另有 {_omitted:N0} 個 C# 語意分析警告未列出。"];
    }
}
