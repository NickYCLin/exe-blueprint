using System.Text;
using System.Text.Json;
using ExeBlueprint.Analysis;
using ExeBlueprint.Application;
using ExeBlueprint.Input;
using ExeBlueprint.Models;
using ExeBlueprint.Reporting;

namespace ExeBlueprint.Core.Tests;

public sealed class ProjectAnalysisTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "ExeBlueprint-project-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task SourceSolutionLinksProjectsAndKeepsConditionsUnevaluated()
    {
        var solution = Write("repo/Demo.slnx", """
            <Solution><Folder Name="/src/"><Project Path="App/App.csproj" /><Project Path="Library/Library.csproj" /></Folder></Solution>
            """);
        Write("repo/App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net8.0;net10.0</TargetFrameworks><OutputType>Exe</OutputType></PropertyGroup>
            <ItemGroup><ProjectReference Include="../Library/Library.csproj"/><PackageReference Include="Example.Package" Version="1.2.3"/>
            <ProjectReference Include="../Missing/Missing.csproj"/><ProjectReference Include="$(SharedProject)"/>
            <PackageReference Include="Central.Package"/></ItemGroup>
            <ItemGroup Condition="'$(Flag)' == 'true'"><ProjectReference Include="../Library/Library.csproj"/></ItemGroup>
            <Import Project="../../outside.props"/>
            <Target Name="BeforeBuild"><Exec Command="must never execute"/></Target></Project>
            """);
        Write("repo/Library/Library.csproj", "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>");
        Write("repo/App/Program.cs", "Console.WriteLine(1);");
        Write("repo/App/bin/Debug/stale.csproj", "invalid");
        Write("repo/.git/objects/private", "not part of the analysis");
        Write("outside.props", "<Project><PropertyGroup><Secret>must not read</Secret></PropertyGroup></Project>");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(solution, new AnalysisOptions { InventoryOnly = true });

        Assert.Equal("source-directory", result.Input.Kind);
        Assert.Equal(4, result.Files.Count);
        Assert.Equal(3, result.ProjectGraph.Components.Count);
        Assert.Equal(2, result.ProjectGraph.References.Count(reference => reference.Kind == "solution-project" && reference.Status == "resolved"));
        var app = Assert.Single(result.ProjectGraph.Components, component => component.Id == "App/App.csproj");
        Assert.Equal("net8.0;net10.0", app.Framework);
        Assert.Equal("Exe", app.OutputType);
        Assert.NotEmpty(app.Notes);
        Assert.Contains(result.ProjectGraph.References, reference => reference.Kind == "project-reference" && reference.Target == "Library/Library.csproj" && reference.Status == "resolved");
        Assert.Contains(result.ProjectGraph.References, reference => reference.Status == "conditional");
        Assert.Contains(result.ProjectGraph.References, reference => reference.Status == "missing");
        Assert.Contains(result.ProjectGraph.References, reference => reference.Status == "unevaluated");
        Assert.Contains(result.ProjectGraph.References, reference => reference.Target == "Example.Package" && reference.Version == "1.2.3");
        Assert.Contains(result.ProjectGraph.References, reference => reference.Target == "Central.Package" && reference.Status == "unevaluated");
        Assert.DoesNotContain("must not read", JsonSerializer.Serialize(result));
        Assert.Contains("未求值", MarkdownReportWriter.Build(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LegacySolutionAndXmlNamespacesAreSupportedWithoutEvaluatingProjects()
    {
        var solution = Write("Demo.sln", """
            Microsoft Visual Studio Solution File, Format Version 12.00
            Project("{TYPE}") = "VB", "VB\Library.vbproj", "{ID}"
            EndProject
            """);
        Write("VB/Library.vbproj", """
            <Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
            <PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion><AssemblyName>Legacy.Library</AssemblyName></PropertyGroup>
            </Project>
            """);
        var result = await new BlueprintAnalyzer().AnalyzeAsync(solution, new AnalysisOptions { InventoryOnly = true });
        var project = Assert.Single(result.ProjectGraph.Components, component => component.Kind == "source-project");
        Assert.Equal("v4.8", project.Framework);
        Assert.Equal("Legacy.Library", project.AssemblyName);
        Assert.Equal("resolved", Assert.Single(result.ProjectGraph.References).Status);
    }

    [Fact]
    public async Task SharedBuildPropertiesAndCentralPackageVersionsAreResolvedFromNearestWorkspaceFiles()
    {
        Write("Directory.Build.props", """
            <Project><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType><ImplicitUsings>enable</ImplicitUsings><AllowUnsafeBlocks>true</AllowUnsafeBlocks></PropertyGroup></Project>
            """);
        Write("Directory.Packages.props", """
            <Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
            <ItemGroup><PackageVersion Include="Central.Package" Version="4.2.0" />
            <PackageVersion Include="Conditional.Package" Version="1.0" Condition="'$(UsePreview)' == 'true'" />
            <PackageVersion Include="Expression.Package" Version="$(SharedVersion)" /></ItemGroup></Project>
            """);
        Write("src/App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
            <PackageReference Include="Central.Package" />
            <PackageReference Include="Conditional.Package" />
            <PackageReference Include="Expression.Package" />
            <PackageReference Include="Override.Package" VersionOverride="9.1.0" />
            </ItemGroup></Project>
            """);
        Write("src/Nested/Directory.Build.props", """
            <Project><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>
            """);
        Write("src/Nested/Worker/Worker.csproj", "<Project />");
        Write("src/OptOut/OptOut.csproj", """
            <Project><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup>
            <ItemGroup><PackageReference Include="Central.Package" /></ItemGroup></Project>
            """);

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root,
            new AnalysisOptions { InventoryOnly = true, SourceMode = true });

        var app = Assert.Single(result.ProjectGraph.Components, component => component.Id == "src/App/App.csproj");
        Assert.Equal("net10.0", app.Framework);
        Assert.Equal("Library", app.OutputType);
        Assert.Equal("enable", app.ImplicitUsings);
        Assert.Equal("true", app.AllowUnsafeBlocks);
        Assert.Contains(app.Notes, note => note.Contains("Directory.Build.props", StringComparison.Ordinal));
        var worker = Assert.Single(result.ProjectGraph.Components, component => component.Id == "src/Nested/Worker/Worker.csproj");
        Assert.Equal("net9.0", worker.Framework);
        var central = Assert.Single(result.ProjectGraph.References,
            reference => reference.Source == "src/App/App.csproj" && reference.Target == "Central.Package");
        Assert.Equal("external", central.Status);
        Assert.Equal("4.2.0", central.Version);
        Assert.Equal("Directory.Packages.props", central.VersionSource);
        Assert.Equal("conditional", Assert.Single(result.ProjectGraph.References,
            reference => reference.Target == "Conditional.Package").Status);
        Assert.Equal("unevaluated", Assert.Single(result.ProjectGraph.References,
            reference => reference.Target == "Expression.Package").Status);
        var overridden = Assert.Single(result.ProjectGraph.References, reference => reference.Target == "Override.Package");
        Assert.Equal("9.1.0", overridden.Version);
        Assert.Null(overridden.VersionSource);
        var optedOut = Assert.Single(result.ProjectGraph.References,
            reference => reference.Source == "src/OptOut/OptOut.csproj" && reference.Target == "Central.Package");
        Assert.Equal("unevaluated", optedOut.Status);
        Assert.Null(optedOut.Version);
        var report = MarkdownReportWriter.Build(result);
        Assert.Contains("4.2.0（Directory.Packages.props）", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidSharedPropsDoNotReadEntitiesOrFallBackToOutsideWorkspace()
    {
        Write("input/Directory.Build.props", """
            <!DOCTYPE Project [<!ENTITY secret SYSTEM '../secret.txt'>]><Project><PropertyGroup><TargetFramework>&secret;</TargetFramework></PropertyGroup></Project>
            """);
        Write("input/App/App.csproj", "<Project><ItemGroup><PackageReference Include='No.Version'/></ItemGroup></Project>");
        Write("Directory.Packages.props", """
            <Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
            <ItemGroup><PackageVersion Include="No.Version" Version="99.0" /></ItemGroup></Project>
            """);
        Write("secret.txt", "must not be read");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(Path.Combine(_root, "input"),
            new AnalysisOptions { InventoryOnly = true, SourceMode = true });

        var project = Assert.Single(result.ProjectGraph.Components);
        Assert.Null(project.Framework);
        Assert.Contains(project.Notes, note => note.Contains("禁止的 DTD", StringComparison.Ordinal));
        var package = Assert.Single(result.ProjectGraph.References);
        Assert.Equal("unevaluated", package.Status);
        Assert.Null(package.Version);
        Assert.DoesNotContain("must not be read", JsonSerializer.Serialize(result));
        Assert.DoesNotContain("99.0", JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task SourceAnalysisResolvesCallsAcrossProjectReferences()
    {
        var solution = Write("Semantic.slnx", """
            <Solution><Project Path="Core/Core.csproj" /><Project Path="App/App.csproj" /></Solution>
            """);
        Write("Core/Core.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>
            """);
        Write("Core/Helper.cs", """
            namespace Demo;
            public static class Helper { public static int Twice(int value) => value * 2; }
            """);
        Write("App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
            <ItemGroup><ProjectReference Include="../Core/Core.csproj" /></ItemGroup></Project>
            """);
        Write("App/Runner.cs", """
            namespace Demo;
            public sealed class Runner { public int Run() { System.Console.WriteLine("running"); return Helper.Twice(21); } }
            """);

        var result = await new BlueprintAnalyzer().AnalyzeAsync(solution, new AnalysisOptions
        {
            InventoryOnly = true,
            EnableSourceAnalysis = true
        });

        var source = Assert.IsType<SourceCodeAnalysis>(result.SourceCode);
        Assert.False(source.Truncated);
        Assert.Equal(2, source.Projects.Count);
        Assert.All(source.Projects, project => Assert.True(project.Complete, string.Join("；", project.Notes)));
        Assert.Contains(source.Declarations, declaration => declaration.Project == "Core/Core.csproj" &&
            declaration.Kind == "method" && declaration.Name.Contains("Helper.Twice", StringComparison.Ordinal));
        Assert.Contains(source.Declarations, declaration => declaration.Project == "App/App.csproj" &&
            declaration.Kind == "method" && declaration.Name.Contains("Runner.Run", StringComparison.Ordinal));
        var call = Assert.Single(source.Calls, call => call.SourceProject == "App/App.csproj" &&
            call.TargetProject == "Core/Core.csproj");
        Assert.Equal("resolved-source", call.Status);
        Assert.Contains("Helper.Twice", call.Target, StringComparison.Ordinal);
        Assert.Contains(source.Calls, call => call.SourceProject == "App/App.csproj" &&
            call.Status == "external" && call.Target.Contains("System.Console.WriteLine", StringComparison.Ordinal));
        Assert.Contains("C# 原始碼語意索引", MarkdownReportWriter.Build(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SourceAnalysisHonorsLiteralCompileIncludeAndRemove()
    {
        Write("Shared.cs", "public sealed class SharedType { }");
        Write("App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
            <Compile Include="../Shared.cs" /><Compile Remove="Skip.cs" />
            </ItemGroup></Project>
            """);
        Write("App/Local.cs", "public sealed class LocalType { }");
        Write("App/Skip.cs", "public sealed class SkippedType { }");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions
        {
            InventoryOnly = true,
            EnableSourceAnalysis = true
        });

        var source = Assert.IsType<SourceCodeAnalysis>(result.SourceCode);
        Assert.Equal("source-directory", result.Input.Kind);
        var project = Assert.Single(source.Projects);
        Assert.True(project.Complete, string.Join("；", project.Notes));
        Assert.Equal(2, project.FileCount);
        Assert.Contains(source.Declarations, declaration => declaration.Name.Contains("SharedType", StringComparison.Ordinal));
        Assert.Contains(source.Declarations, declaration => declaration.Name.Contains("LocalType", StringComparison.Ordinal));
        Assert.DoesNotContain(source.Declarations, declaration => declaration.Name.Contains("SkippedType", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SourceAnalysisHonorsInheritedDefaultCompileItemSetting()
    {
        Write("Directory.Build.props", """
            <Project><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>
            """);
        Write("App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup><Compile Include="Included.cs" /></ItemGroup></Project>
            """);
        Write("App/Included.cs", "public sealed class IncludedType { }");
        Write("App/Ignored.cs", "public sealed class IgnoredType { }");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions
        {
            InventoryOnly = true,
            SourceMode = true,
            EnableSourceAnalysis = true
        });

        var source = Assert.IsType<SourceCodeAnalysis>(result.SourceCode);
        var project = Assert.Single(source.Projects);
        Assert.True(project.Complete, string.Join("；", project.Notes));
        Assert.Equal(1, project.FileCount);
        Assert.Contains(source.Declarations, declaration => declaration.Name.Contains("IncludedType", StringComparison.Ordinal));
        Assert.DoesNotContain(source.Declarations, declaration => declaration.Name.Contains("IgnoredType", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SourceAnalysisDoesNotKeepPartialIncludesFromUnsupportedProject()
    {
        Write("App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
            <Compile Include="Included.cs" />
            <Compile Include="Conditional.cs" Condition="'$(IncludeConditional)' == 'true'" />
            </ItemGroup></Project>
            """);
        Write("App/Included.cs", "public sealed class IncludedType { }");
        Write("App/Conditional.cs", "public sealed class ConditionalType { }");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions
        {
            InventoryOnly = true,
            EnableSourceAnalysis = true
        });

        var source = Assert.IsType<SourceCodeAnalysis>(result.SourceCode);
        var project = Assert.Single(source.Projects);
        Assert.False(project.Complete);
        Assert.Equal(0, project.FileCount);
        Assert.Empty(source.Declarations);
        Assert.Empty(source.Calls);
    }

    [Fact]
    public async Task SourceAnalysisMarksConditionalCompilationIncomplete()
    {
        Write("App/App.csproj", "<Project Sdk='Microsoft.NET.Sdk'/>");
        Write("App/Feature.cs", """
            public static class Feature
            {
            #if FEATURE_ENABLED
                public static void Run() { }
            #endif
            }
            """);

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions
        {
            InventoryOnly = true,
            EnableSourceAnalysis = true
        });

        var project = Assert.Single(Assert.IsType<SourceCodeAnalysis>(result.SourceCode).Projects);
        Assert.False(project.Complete);
        Assert.Contains(project.Notes, note => note.Contains("DefineConstants", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SourceAnalysisMarksCircularProjectReferencesIncomplete()
    {
        Write("A/A.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../B/B.csproj" /></ItemGroup></Project>
            """);
        Write("A/A.cs", "namespace Demo; public sealed class A { }");
        Write("B/B.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../A/A.csproj" /></ItemGroup></Project>
            """);
        Write("B/B.cs", "namespace Demo; public sealed class B { }");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions
        {
            InventoryOnly = true,
            SourceMode = true,
            EnableSourceAnalysis = true
        });

        var source = Assert.IsType<SourceCodeAnalysis>(result.SourceCode);
        Assert.Equal(2, source.Projects.Count);
        Assert.All(source.Projects, project =>
        {
            Assert.False(project.Complete);
            Assert.Contains(project.Notes, note => note.Contains("循環", StringComparison.Ordinal));
        });
    }

    [Fact]
    public async Task SourceAnalysisSkipsProjectsWithCustomBuildLogicInsteadOfGuessingCompileItems()
    {
        Write("Directory.Build.targets", "<Project><ItemGroup><Compile Include='Generated.cs'/></ItemGroup></Project>");
        Write("App/App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk"><Import Project="../Directory.Build.targets" /></Project>
            """);
        Write("App/Program.cs", "public static class Program { public static void Main() { } }");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions
        {
            InventoryOnly = true,
            SourceMode = true,
            EnableSourceAnalysis = true
        });

        var source = Assert.IsType<SourceCodeAnalysis>(result.SourceCode);
        var project = Assert.Single(source.Projects);
        Assert.False(project.Complete);
        Assert.Equal(0, project.FileCount);
        Assert.Empty(source.Declarations);
        Assert.Empty(source.Calls);
        Assert.Contains(project.Notes, note => note.Contains("建置邏輯", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SourceAnalysisCanRemainDisabled()
    {
        var project = Write("App.csproj", "<Project Sdk='Microsoft.NET.Sdk'/>");
        Write("Program.cs", "public static class Program { public static void Main() { } }");

        var result = await new BlueprintAnalyzer().AnalyzeAsync(project,
            new AnalysisOptions { InventoryOnly = true });

        Assert.Null(result.SourceCode);
    }

    [Fact]
    public async Task DtdTraversalAndPropertyExpressionsDoNotCreateResolvedReferences()
    {
        Write("input/App.csproj", """
            <Project><PropertyGroup Condition="'$(Flag)' == 'true'"><TargetFramework>net10.0</TargetFramework></PropertyGroup>
            <ItemGroup><ProjectReference Include="../Secret.csproj"/><ProjectReference Include="C:\outside.csproj"/>
            <ProjectReference Include="https://example.invalid/remote.csproj"/><ProjectReference Include="**/*.csproj"/></ItemGroup></Project>
            """);
        Write("input/Invalid.csproj", "<!DOCTYPE Project [<!ENTITY x SYSTEM 'file:///must-not-be-read'>]><Project>&x;</Project>");
        Write("Secret.csproj", "<Project><PropertyGroup><AssemblyName>DoNotRead</AssemblyName></PropertyGroup></Project>");
        var result = await new BlueprintAnalyzer().AnalyzeAsync(Path.Combine(_root, "input"), new AnalysisOptions { InventoryOnly = true, SourceMode = true });
        Assert.Equal(2, result.ProjectGraph.Components.Count);
        Assert.All(result.ProjectGraph.References, reference => Assert.Equal("unevaluated", reference.Status));
        Assert.All(result.ProjectGraph.Components, component => Assert.NotEmpty(component.Notes));
        Assert.All(result.ProjectGraph.Components, component => Assert.Null(component.Framework));
        Assert.DoesNotContain("DoNotRead", JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task CaseAmbiguousReferenceIsNotGuessed()
    {
        var file = Write("App.csproj", "<Project><ItemGroup><ProjectReference Include='LIB.csproj'/></ItemGroup></Project>");
        var library = Write("library.xml", "<Project/>");
        var inputs = new[] { new WorkspaceFile(file, "App.csproj", new FileInfo(file).Length, new()),
            new WorkspaceFile(library, "Lib.csproj", new FileInfo(library).Length, new()),
            new WorkspaceFile(library, "lib.csproj", new FileInfo(library).Length, new()) };
        var result = await ProjectGraphAnalyzer.AnalyzeAsync(inputs, [], [], default);
        Assert.Equal("ambiguous", Assert.Single(result.References).Status);
    }

    [Fact]
    public async Task InventoryKeepsManagedMetadataWithoutReadingBodiesOrGeneratingSkeletons()
    {
        var source = Write("input/readme.txt", "fixture");
        File.Copy(typeof(BlueprintAnalyzer).Assembly.Location, Path.Combine(Path.GetDirectoryName(source)!, "App.dll"));
        Write("input/result/old.csproj", "must not be analyzed");
        var progress = new List<BlueprintExportProgress>();
        var result = await new BlueprintExportService().RunAsync(new BlueprintExportRequest
        {
            InputPath = Path.GetDirectoryName(source)!,
            OutputDirectory = Path.Combine(_root, "input/result"),
            InventoryOnly = true,
            EmitCSharp = true
        }, new CaptureProgress<BlueprintExportProgress>(progress.Add));

        Assert.Equal("inventory", result.Document.AnalysisMode);
        Assert.Equal(2, result.Document.Files.Count);
        var assembly = Assert.Single(result.Document.Files, file => file.IsManaged);
        Assert.Null(assembly.Code);
        Assert.NotEmpty(assembly.ManagedReferences);
        Assert.Equal("managed-assembly", Assert.Single(result.Document.ProjectGraph.Components).Kind);
        Assert.NotEmpty(result.Document.ProjectGraph.References);
        Assert.Empty(result.Skeletons);
        Assert.Contains(progress, item => item.CompletedFiles == 0 && item.TotalFiles == 2);
        Assert.Contains(progress, item => item.CompletedFiles == 2 && item.TotalFiles == 2);
        Assert.Contains("不代表程式沒有內容", await File.ReadAllTextAsync(Path.Combine(result.OutputDirectory, "REPORT.md")), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, 3)]
    [InlineData(true, 1)]
    public async Task BinaryFoldersKeepBuildDirectoriesUnlessSourceModeIsSelected(bool sourceMode, int expectedFiles)
    {
        Write("App.csproj", "<Project/>");
        Write("bin/deployed.dll", "fixture");
        Write("obj/cache.txt", "fixture");
        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions { InventoryOnly = true, SourceMode = sourceMode });
        Assert.Equal(expectedFiles, result.Files.Count);
    }

    [Fact]
    public async Task ManyProjectsPreserveEveryReferenceAndProduceBoundedReadableReport()
    {
        const int count = 128;
        var solution = new StringBuilder("<Solution>");
        for (var index = 0; index < count; index++)
        {
            var name = $"P{index:D3}";
            solution.Append($"<Project Path='{name}/{name}.csproj'/>");
            var reference = index == 0 ? "" : $"<ItemGroup><ProjectReference Include='../P{index - 1:D3}/P{index - 1:D3}.csproj'/></ItemGroup>";
            Write($"{name}/{name}.csproj", $"<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>{reference}</Project>");
            for (var file = 0; file < 8; file++) Write($"{name}/C{file}.cs", $"namespace {name}; public class C{file} {{ }}");
        }
        solution.Append("</Solution>");
        var input = Write("Large.slnx", solution.ToString());
        var result = await new BlueprintAnalyzer().AnalyzeAsync(input, new AnalysisOptions { InventoryOnly = true });
        Assert.Equal(count * 9 + 1, result.Input.FileCount);
        Assert.Equal(count + 1, result.ProjectGraph.Components.Count);
        Assert.Equal(count * 2 - 1, result.ProjectGraph.References.Count);
        Assert.All(result.ProjectGraph.References, reference => Assert.Equal("resolved", reference.Status));
        Assert.False(result.ProjectGraph.Truncated);
        var report = MarkdownReportWriter.Build(result);
        Assert.Contains("僅列前 500 筆", report, StringComparison.Ordinal);
        Assert.True(report.Length < 200_000);
    }

    [Fact]
    public async Task ProjectGraphLimitsAreVisibleRatherThanSilent()
    {
        var path = Write("template.csproj", "<Project/>");
        var inputs = Enumerable.Range(0, 4097).Select(index => new WorkspaceFile(path, $"P{index}.csproj", new FileInfo(path).Length, new())).ToArray();
        var result = await ProjectGraphAnalyzer.AnalyzeAsync(inputs, [], [], default);
        Assert.True(result.Truncated);
        Assert.Equal(4096, result.Components.Count);
    }

    [Fact]
    public async Task CancellationAtInitialInventoryProgressStopsBeforeFileAnalysis()
    {
        Write("file.txt", "fixture");
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new BlueprintAnalyzer().AnalyzeAsync(_root,
            new AnalysisOptions { InventoryOnly = true }, cancellation.Token,
            new CaptureProgress<AnalysisProgress>(_ => cancellation.Cancel())));
    }

    [Fact]
    public async Task InventoryProgressIsMonotonicAndRetainsSortedResults()
    {
        for (var index = 50; index >= 0; index--) Write($"file-{index:D3}.txt", "fixture");
        var progress = new List<AnalysisProgress>();
        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions { InventoryOnly = true },
            progress: new CaptureProgress<AnalysisProgress>(progress.Add));
        var counts = progress.Where(item => item.Stage == "files").Select(item => item.CompletedFiles).ToArray();
        Assert.Equal(0, counts[0]);
        Assert.Equal(51, counts[^1]);
        Assert.Equal(counts.Order(), counts);
        Assert.Equal(result.Files.Select(file => file.Id).Order(StringComparer.Ordinal), result.Files.Select(file => file.Id));
        Assert.Contains(progress, item => item.Stage == "projects");
    }

    [Fact]
    public async Task LostFilesAndOversizeDescriptorsRemainExplicitlyUnanalyzed()
    {
        var missing = await new FileAnalyzer(new AnalysisOptions { InventoryOnly = true }).AnalyzeAsync(
            Path.Combine(_root, "missing.csproj"), "missing.csproj", default);
        Assert.NotNull(missing.AnalysisError);
        var input = Write("App.csproj", "<Project><ItemGroup><PackageReference Include='Example' Version='1.0'/></ItemGroup></Project>");
        var result = await new BlueprintAnalyzer().AnalyzeAsync(input, new AnalysisOptions { InventoryOnly = true, MaxFileBytes = 1 });
        Assert.Empty(result.ProjectGraph.References);
        Assert.NotEmpty(Assert.Single(result.ProjectGraph.Components).Notes);
    }

    [Fact]
    public async Task InvalidSolutionAndItemMetadataDoNotInventProjectDependencies()
    {
        Write("invalid.sln", "not a solution");
        Write("App.csproj", """
            <Project xmlns:x='urn:not-msbuild'><ItemDefinitionGroup><PackageReference><Version>1.0</Version></PackageReference></ItemDefinitionGroup>
            <ItemGroup><PackageReference Update='Central' Version='1.0'/></ItemGroup>
            <Something><ProjectReference Include='fake.csproj'/></Something>
            <x:PropertyGroup><TargetFramework>net99.0</TargetFramework></x:PropertyGroup>
            <x:ItemGroup><ProjectReference Include='also-fake.csproj'/></x:ItemGroup></Project>
            """);
        var result = await new BlueprintAnalyzer().AnalyzeAsync(_root, new AnalysisOptions { InventoryOnly = true });
        Assert.Empty(result.ProjectGraph.References);
        Assert.Null(Assert.Single(result.ProjectGraph.Components,
            component => component.Id == "App.csproj").Framework);
        Assert.NotEmpty(Assert.Single(result.ProjectGraph.Components,
            component => component.Kind == "solution").Notes);
    }

    [Fact]
    public async Task ArchiveProjectsCannotResolveReferencesOutsideTheirContainer()
    {
        var path = Write("template.csproj", "<Project><ItemGroup><ProjectReference Include='../outside.csproj'/></ItemGroup></Project>");
        var outside = Write("outside.csproj", "<Project/>");
        var files = new[]
        {
            new WorkspaceFile(path, "app.asar/App.csproj", new FileInfo(path).Length,
                new FileOrigin { Kind = "asar", Container = "app.asar", Entry = "App.csproj", Depth = 1 }),
            new WorkspaceFile(outside, "outside.csproj", new FileInfo(outside).Length, new())
        };
        var result = await ProjectGraphAnalyzer.AnalyzeAsync(files, [], [], default);
        Assert.Equal("unevaluated", Assert.Single(result.References).Status);
    }

    [Fact]
    public async Task BinaryReferencesToNonPeFilesHaveGraphNodes()
    {
        var files = new[]
        {
            new FileArtifact { Id = "app.exe", RelativePath = "app.exe", FileName = "app.exe", Category = "executable", Format = "PE", Size = 1, Sha256 = "", IsPortableExecutable = true },
            new FileArtifact { Id = "runtime.fnr", RelativePath = "runtime.fnr", FileName = "runtime.fnr", Category = "unknown", Format = "FNR", Size = 1, Sha256 = "" }
        };
        var edges = new[] { new DependencyEdge { Source = "app.exe", Target = "runtime.fnr", Kind = "pe-import", ResolvedInsidePackage = true } };
        var result = await ProjectGraphAnalyzer.AnalyzeAsync([], files, edges, default);
        Assert.Equal(2, result.Components.Count);
        Assert.Contains(result.Components, item => item.Id == "runtime.fnr" && item.Kind == "package-file");
        Assert.Equal("resolved", Assert.Single(result.References).Status);
    }

    [Fact]
    public async Task EmptyProjectGraphStillHonorsCancellation()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProjectGraphAnalyzer.AnalyzeAsync([], [], [], new CancellationToken(true)));
    }

    private string Write(string relative, string content)
    {
        var path = Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    private sealed class CaptureProgress<T>(Action<T> capture) : IProgress<T>
    {
        public void Report(T value) => capture(value);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
