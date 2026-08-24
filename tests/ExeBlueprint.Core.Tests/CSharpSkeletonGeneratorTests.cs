using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class CSharpSkeletonGeneratorTests
{
    [Fact]
    public async Task GeneratesReadableSkeletonFromManagedAssembly()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var files = CSharpSkeletonGenerator.Generate(document);

        Assert.Contains(files, file => file.RelativePath.EndsWith(".csproj", StringComparison.Ordinal));
        Assert.Contains(files, file => file.RelativePath == "README.md");

        var modelsFile = Assert.Single(
            files,
            file => file.RelativePath.EndsWith("ExeBlueprint.Models.cs", StringComparison.Ordinal));
        Assert.Contains("namespace ExeBlueprint.Models;", modelsFile.Content);
        Assert.Contains("class FileArtifact", modelsFile.Content);
        Assert.Contains("throw new global::System.NotImplementedException();", modelsFile.Content);
    }

    [Fact]
    public async Task GeneratedTypeSignaturesAreCleanOfMetadataArtifacts()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var sourceFiles = CSharpSkeletonGenerator.Generate(document)
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(sourceFiles);
        foreach (var file in sourceFiles)
        {
            // 註解裡的原始 IL 允許帶原始名稱；字串常值裡也可能剛好有反引號。
            // 這裡只檢查真正的 metadata 殘留：泛型 arity（`1）與運算子方法呼叫（.op_）。
            var codeLines = file.Content
                .Split('\n')
                .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));
            foreach (var line in codeLines)
            {
                Assert.DoesNotMatch(@"`\d", line);
                Assert.DoesNotContain(".op_", line, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void GenerateReturnsEmptyWhenNoManagedCode()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "sample",
                Kind = "file",
                SourcePath = "sample",
                FileCount = 0,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary()
        };

        Assert.Empty(CSharpSkeletonGenerator.Generate(document));
    }

    [Fact]
    public async Task PreservesMemberShapesInGeneratedCSharp()
    {
        var assemblyPath = typeof(MemberShapeFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("public const string Label = \"blueprint\";", source);
        Assert.Contains("protected internal static readonly int Counter;", source);
        Assert.Contains("public virtual string Name { get; protected set; }", source);
        Assert.Contains("public System.Text.StringBuilder Builder { get; }", source);
        Assert.Contains("internal static event System.EventHandler Changed;", source);
        Assert.Contains("protected virtual event System.EventHandler Updated;", source);
        Assert.Equal(1, source.Split(" Changed;", StringSplitOptions.None).Length - 1);
        Assert.Equal(1, source.Split(" Updated;", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("add_Changed", source, StringComparison.Ordinal);
        Assert.DoesNotContain("remove_Changed", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsOverrideSealedAndFinalInterfaceMethodModifiers()
    {
        var assemblyPath = typeof(DispatchDerivedFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("public abstract string Describe();", source);
        Assert.Contains("public virtual int Transform(int value)", source);
        Assert.Contains("public override string Describe()", source);
        Assert.Contains("public sealed override int Transform(int value)", source);
        Assert.Contains("public override int Value { get; }", source);
        Assert.Contains("public sealed override event System.EventHandler Dispatched;", source);
        Assert.Contains("public void Dispose()", source);
        Assert.DoesNotContain("virtual void Dispose()", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsNestedTypesWithOwnedGenericParameters()
    {
        var assemblyPath = typeof(NestedTypeFixture<>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("internal class NestedTypeFixture<T>", source);
        Assert.Contains("    public sealed class Child<U>", source);
        Assert.DoesNotContain("class Child<T, U>", source, StringComparison.Ordinal);
        Assert.Contains("        public T OuterValue { get; set; }", source);
        Assert.Contains("        public U InnerValue { get; set; }", source);
        Assert.Contains("        public enum State : byte", source);
        Assert.Contains("            Ready = 2,", source);
        Assert.Contains("        public struct Leaf", source);
    }

    [Fact]
    public async Task EmitsRefStructAndComputedRefLikePropertyStubs()
    {
        var assemblyPath = typeof(RefStructFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("internal ref struct RefStructFixture", source);
        Assert.Contains("public System.Span<byte> Buffer", source);
        Assert.Contains("get => throw new global::System.NotImplementedException();", source);
        Assert.Contains("set { }", source);
        Assert.Contains("public System.ReadOnlySpan<byte> Header", source);
        Assert.DoesNotContain("System.ReadOnlySpan<byte> Header { get; }", source, StringComparison.Ordinal);
    }

    [Fact]
    public void GeneratesSolutionAndReferencesForRelatedAssemblies()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "package",
                Kind = "directory",
                SourcePath = "package",
                FileCount = 2,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files =
            [
                CreateManagedArtifact("Demo.Core", []),
                CreateManagedArtifact("Demo.App", ["Demo.Core"])
            ]
        };

        var files = CSharpSkeletonGenerator.Generate(document);
        var solution = Assert.Single(files, file => file.RelativePath == "Reconstructed.slnx").Content;
        var appProject = Assert.Single(files, file => file.RelativePath == "Demo.App/Demo.App.csproj").Content;

        Assert.Contains("<Project Path=\"Demo.App/Demo.App.csproj\" />", solution);
        Assert.Contains("<Project Path=\"Demo.Core/Demo.Core.csproj\" />", solution);
        Assert.Contains("<ProjectReference Include=\"../Demo.Core/Demo.Core.csproj\" />", appProject);
    }

    [Fact]
    public void KeepsSanitizedProjectDirectoryNamesUnique()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "package",
                Kind = "directory",
                SourcePath = "package",
                FileCount = 2,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files =
            [
                CreateManagedArtifact("Demo/App", []),
                CreateManagedArtifact("Demo:App", [])
            ]
        };

        var files = CSharpSkeletonGenerator.Generate(document);

        Assert.Contains(files, file => file.RelativePath == "Demo_App/Demo_App.csproj");
        Assert.Contains(files, file => file.RelativePath == "Demo_App_2/Demo_App_2.csproj");
        Assert.Equal(files.Count, files.Select(file => file.RelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    private static FileArtifact CreateManagedArtifact(string assemblyName, IReadOnlyList<string> references) =>
        new()
        {
            Id = assemblyName,
            RelativePath = assemblyName + ".dll",
            FileName = assemblyName + ".dll",
            Size = 0,
            Sha256 = "",
            Category = "library",
            Format = "pe",
            IsManaged = true,
            AssemblyName = assemblyName,
            ManagedReferences = references,
            Code = new CodeModel
            {
                Kind = "managed",
                TypeCount = 1,
                Types =
                [
                    new TypeModel
                    {
                        FullName = assemblyName + ".Placeholder",
                        Namespace = assemblyName,
                        Name = "Placeholder",
                        Kind = "class",
                        Accessibility = "public"
                    }
                ]
            }
        };
}
