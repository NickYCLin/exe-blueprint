using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

// C# 骨架裡由不受信任 metadata 直接決定、且必然無法編譯的語法，這裡逐一鎖定。
public sealed class CSharpSkeletonSyntaxTests
{
    // 同名參數是 CS0100；第二個起加序號。
    [Fact]
    public async Task DuplicateParameterNamesGetUniqueNames()
    {
        var document = await BuildDocument(new TypeModel
        {
            FullName = "Tests.Probe",
            Namespace = "Tests",
            Name = "Probe",
            Kind = "class",
            Accessibility = "internal",
            Methods =
            [
                new MethodModel
                {
                    Name = "Run",
                    Signature = "Run(...)",
                    ReturnType = "void",
                    Accessibility = "public",
                    Parameters = [Parameter("x", "int"), Parameter("x", "int"), Parameter("class", "int"), Parameter("class", "int")]
                }
            ]
        });

        var csharp = CSharpSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith("/Tests.cs", StringComparison.Ordinal))
            .Content;

        Assert.Contains("Run(int x, int x_2, int @class, int @class_2)", csharp, StringComparison.Ordinal);
    }

    private static ParameterModel Parameter(string name, string type) => new() { Name = name, Type = type };

    private static async Task<BlueprintDocument> BuildDocument(params TypeModel[] types)
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(CSharpSkeletonSyntaxTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "csharp-syntax",
            RelativePath = "Probe.dll",
            FileName = "Probe.dll",
            AssemblyName = "Probe",
            ManagedReferences = [],
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = types.Length,
                Types = types
            }
        };

        return analyzed with { Files = [artifact] };
    }
}
