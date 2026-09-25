using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class SkeletonFileNameSafetyTests
{
    [Theory]
    [InlineData("Normal", "Normal")]
    [InlineData("With Space", "With_Space")]
    [InlineData("My.Dotted.Name", "My_Dotted_Name")]
    [InlineData("", "Fallback")]
    [InlineData("CON", "_CON")]
    [InlineData("nul", "_nul")]
    [InlineData("COM1", "_COM1")]
    [InlineData("LPT9", "_LPT9")]
    [InlineData("COM0", "COM0")]
    [InlineData("CONSOLE", "CONSOLE")]
    public void SanitizeFileStemProducesWritableStems(string value, string expected)
    {
        Assert.Equal(expected, SkeletonSupport.SanitizeFileStem(value, "Fallback"));
    }

    [Theory]
    [InlineData("My.Namespace", "My.Namespace")]
    [InlineData("Trailing.", "Trailing")]
    [InlineData("Padded ", "Padded")]
    [InlineData("", "Fallback")]
    [InlineData(".", "Fallback")]
    [InlineData("..", "Fallback")]
    [InlineData("NUL", "_NUL")]
    [InlineData("NUL.Sub", "_NUL.Sub")]
    [InlineData("Con.Console", "_Con.Console")]
    public void EnsureWritableSegmentKeepsInnerDotsButGuardsReservedAndTrailing(
        string segment,
        string expected)
    {
        Assert.Equal(expected, SkeletonSupport.EnsureWritableSegment(segment, "Fallback"));
    }

    [Fact]
    public async Task DeviceNamedAssemblyStaysWritableAcrossAllGenerators()
    {
        var document = await BuildDocumentWithAssembly("CON", "NUL");

        var csharp = CSharpSkeletonGenerator.Generate(document);
        Assert.Contains(csharp, file => file.RelativePath == "_CON/_NUL.cs");
        Assert.Contains(csharp, file => file.RelativePath == "_CON/_CON.csproj");

        Assert.Equal(
            "_CON.hpp",
            CppSkeletonGenerator.Generate(document).Single(file => file.RelativePath.EndsWith(".hpp", StringComparison.Ordinal)).RelativePath);
        Assert.Equal(
            "_CON.rs",
            RustSkeletonGenerator.Generate(document).Single(file => file.RelativePath.EndsWith(".rs", StringComparison.Ordinal)).RelativePath);
        Assert.Equal(
            "_CON.go",
            GoSkeletonGenerator.Generate(document).Single(file => file.RelativePath.EndsWith(".go", StringComparison.Ordinal)).RelativePath);

        // 端對端：所有語言的骨架都要能通過 writer 的路徑檢查並實際落地。
        var output = Path.Combine(Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
        try
        {
            foreach (var files in new[]
            {
                CSharpSkeletonGenerator.Generate(document),
                CppSkeletonGenerator.Generate(document),
                RustSkeletonGenerator.Generate(document),
                GoSkeletonGenerator.Generate(document)
            })
            {
                await GeneratedProjectWriter.WriteAsync(files, Path.Combine(output, Guid.NewGuid().ToString("N")));
            }
        }
        finally
        {
            if (Directory.Exists(output))
            {
                Directory.Delete(output, recursive: true);
            }
        }
    }

    // 同名組件（例如各 RID 各一份）在 C++／Rust／Go 會整理成同一個檔名主幹，writer 把重複路徑當錯誤，
    // 整包匯出就失敗；C# 早已替專案目錄加序號，這三種語言也要。
    [Fact]
    public async Task DuplicateAssemblyNamesGetDistinctSourceFilesInEveryLanguage()
    {
        var document = await BuildDocument(("Same", ["Tests"]), ("Same", ["Other"]));

        foreach (var (files, extension) in new (IReadOnlyList<GeneratedFile>, string)[]
        {
            (CppSkeletonGenerator.Generate(document), ".hpp"),
            (RustSkeletonGenerator.Generate(document), ".rs"),
            (GoSkeletonGenerator.Generate(document), ".go")
        })
        {
            var sources = files
                .Where(file => file.RelativePath.EndsWith(extension, StringComparison.Ordinal))
                .Select(file => file.RelativePath)
                .ToArray();
            Assert.Equal(2, sources.Length);
            Assert.Contains($"Same{extension}", sources);
            Assert.Contains($"Same_2{extension}", sources);
            await WriteToTemp(files);
        }
    }

    // 命名空間直接來自 metadata：含 / 會變成子目錄、含 : * 等會讓 writer 拒收，大小寫只差的兩個
    // 命名空間則會產生同一個檔名。整理成合法片段並在專案內保證唯一。
    [Fact]
    public async Task NamespaceFileNamesAreSanitizedAndUniqueWithinAProject()
    {
        var document = await BuildDocument(("Probe", ["Foo", "foo", "Bad/Name:*"]));

        var files = CSharpSkeletonGenerator.Generate(document);
        var sources = files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.Ordinal))
            .Select(file => file.RelativePath)
            .ToArray();

        Assert.Equal(3, sources.Length);
        Assert.Contains("Probe/Foo.cs", sources);
        Assert.Contains("Probe/foo_2.cs", sources);
        Assert.Contains("Probe/Bad_Name__.cs", sources);
        await WriteToTemp(files);
    }

    // 組件名剛好是 README.md 或 Reconstructed.slnx 時，專案目錄會撞到根目錄的同名檔案。
    [Fact]
    public async Task ProjectDirectoryAvoidsRootFileNames()
    {
        var document = await BuildDocument(("README.md", ["Tests"]));

        var files = CSharpSkeletonGenerator.Generate(document);
        var project = Assert.Single(files, file => file.RelativePath.EndsWith(".csproj", StringComparison.Ordinal));

        Assert.StartsWith("README.md_2/", project.RelativePath, StringComparison.Ordinal);
        await WriteToTemp(files);
    }

    private static async Task WriteToTemp(IReadOnlyList<GeneratedFile> files)
    {
        var output = Path.Combine(Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
        try
        {
            await GeneratedProjectWriter.WriteAsync(files, output);
        }
        finally
        {
            if (Directory.Exists(output))
            {
                Directory.Delete(output, recursive: true);
            }
        }
    }

    // 每個 tuple 是一個組件：組件名加上其內每個命名空間各放一個型別。
    private static async Task<BlueprintDocument> BuildDocument(params (string Assembly, string[] Namespaces)[] assemblies)
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(SkeletonFileNameSafetyTests).Assembly.Location);
        var artifacts = assemblies.Select((item, index) => analyzed.Files[0] with
        {
            Id = $"artifact-{index}",
            RelativePath = $"{index}/{item.Assembly}.dll",
            FileName = $"{item.Assembly}.dll",
            AssemblyName = item.Assembly,
            ManagedReferences = [],
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = item.Namespaces.Length,
                TypeCount = item.Namespaces.Length,
                Types = item.Namespaces.Select(typeNamespace => new TypeModel
                {
                    FullName = $"{typeNamespace}.Probe",
                    Namespace = typeNamespace,
                    Name = "Probe",
                    Kind = "class",
                    Accessibility = "internal"
                }).ToArray()
            }
        }).ToArray();

        return analyzed with { Files = artifacts };
    }

    private static async Task<BlueprintDocument> BuildDocumentWithAssembly(
        string assemblyName,
        string typeNamespace)
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(SkeletonFileNameSafetyTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "device-named",
            RelativePath = $"{assemblyName}.dll",
            FileName = $"{assemblyName}.dll",
            AssemblyName = assemblyName,
            ManagedReferences = [],
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 1,
                Types =
                [
                    new TypeModel
                    {
                        FullName = $"{typeNamespace}.Probe",
                        Namespace = typeNamespace,
                        Name = "Probe",
                        Kind = "class",
                        Accessibility = "internal"
                    }
                ]
            }
        };

        return analyzed with { Files = [artifact] };
    }
}
