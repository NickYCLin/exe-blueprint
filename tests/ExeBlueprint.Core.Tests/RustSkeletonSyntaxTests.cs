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

    // 零變體的列舉不能帶 #[repr]（E0084）；.NET 常見的別名成員（A = 1, Default = 1）在 Rust 是重複
    // 判別值（E0081），改成關聯常數。
    [Fact]
    public async Task EnumAliasesBecomeAssociatedConstantsAndEmptyEnumsHaveNoRepr()
    {
        var document = await BuildDocument(
            new TypeModel
            {
                FullName = "Tests.Probe",
                Namespace = "Tests",
                Name = "Probe",
                Kind = "enum",
                Accessibility = "internal",
                Fields =
                [
                    new FieldModel { Name = "value__", Type = "int", Accessibility = "public" },
                    EnumMember("A", "1"),
                    EnumMember("B", "2"),
                    EnumMember("Default", "1")
                ]
            },
            new TypeModel
            {
                FullName = "Tests.Empty",
                Namespace = "Tests",
                Name = "Empty",
                Kind = "enum",
                Accessibility = "internal",
                Fields = [new FieldModel { Name = "value__", Type = "int", Accessibility = "public" }]
            });

        var rust = RustSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".rs", StringComparison.Ordinal))
            .Content;
        var lines = rust.Split('\n').Select(line => line.TrimEnd('\r')).ToArray();

        Assert.Contains("    A = 1,", lines);
        Assert.Contains("    B = 2,", lines);
        Assert.DoesNotContain("    Default = 1,", lines);
        Assert.Contains("impl Probe {", lines);
        Assert.Contains("    pub const Default: Self = Self::A;", lines);

        var empty = Array.IndexOf(lines, "pub enum Empty {}");
        Assert.True(empty > 0, "空列舉應輸出成 `pub enum Empty {}`");
        Assert.False(lines[empty - 1].StartsWith("#[repr(", StringComparison.Ordinal));
    }

    private static FieldModel EnumMember(string name, string value) => new()
    {
        Name = name,
        Type = "Tests.Probe",
        Accessibility = "public",
        IsStatic = true,
        IsConstant = true,
        ConstantValue = new ConstantValueModel { Type = "int", Value = value }
    };

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
