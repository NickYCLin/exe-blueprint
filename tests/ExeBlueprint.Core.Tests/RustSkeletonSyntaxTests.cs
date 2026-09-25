using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

// Rust 骨架有幾種輸出是必然無法編譯的語法，這裡逐一鎖定。
public sealed class RustSkeletonSyntaxTests
{
    // trait 裡的方法帶 pub 是 E0449；只有 impl 裡的方法才需要 pub。
    [Fact]
    public async Task TraitMethodsAreEmittedWithoutPub()
    {
        var document = await BuildDocument(new TypeModel
        {
            FullName = "Tests.IProbe",
            Namespace = "Tests",
            Name = "IProbe",
            Kind = "interface",
            Accessibility = "internal",
            Methods = [Method("Run")]
        });

        var rust = RustSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".rs", StringComparison.Ordinal))
            .Content;

        Assert.Contains("pub trait IProbe {", rust, StringComparison.Ordinal);
        Assert.Contains("    fn Run(&self);", rust, StringComparison.Ordinal);
        Assert.DoesNotContain("pub fn Run", rust, StringComparison.Ordinal);
    }

    private static MethodModel Method(string name, string returnType = "void") => new()
    {
        Name = name,
        Signature = $"{name}(...)",
        ReturnType = returnType,
        Accessibility = "public",
        Parameters = []
    };

    private static async Task<BlueprintDocument> BuildDocument(params TypeModel[] types)
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(RustSkeletonSyntaxTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "rust-syntax",
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
