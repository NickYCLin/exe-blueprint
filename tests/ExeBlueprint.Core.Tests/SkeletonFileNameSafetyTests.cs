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
