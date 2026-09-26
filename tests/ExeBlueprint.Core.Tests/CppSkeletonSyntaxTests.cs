using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

// C++ 骨架有幾種輸出是必然無法編譯的語法，這裡逐一鎖定。
public sealed class CppSkeletonSyntaxTests
{
    // 介面的靜態成員先前被寫成 virtual static ... = 0;，這不是合法 C++。
    [Fact]
    public async Task StaticInterfaceMembersAreNotPureVirtual()
    {
        var document = await BuildDocument(new TypeModel
        {
            FullName = "Tests.IFactory",
            Namespace = "Tests",
            Name = "IFactory",
            Kind = "interface",
            Accessibility = "internal",
            Methods =
            [
                Method("Create", "int", isStatic: true),
                Method("Run", "void")
            ]
        });

        var cpp = CppSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".hpp", StringComparison.Ordinal))
            .Content;

        Assert.DoesNotContain("virtual static", cpp, StringComparison.Ordinal);
        Assert.Contains("static int32_t Create() { throw std::runtime_error(\"not implemented\"); }", cpp, StringComparison.Ordinal);
        Assert.Contains("virtual void Run() = 0;", cpp, StringComparison.Ordinal);
    }

    // C++ 沒有原始識別字語法，撞到關鍵字或開頭是數字的名稱只能改名，否則整個檔案無法編譯。
    [Fact]
    public async Task KeywordAndDigitLeadingNamesAreRenamed()
    {
        var document = await BuildDocument(new TypeModel
        {
            FullName = "Tests.union",
            Namespace = "Tests",
            Name = "union",
            Kind = "class",
            Accessibility = "internal",
            Fields = [new FieldModel { Name = "template", Type = "int", Accessibility = "public" }],
            Methods =
            [
                Method("delete", "void") with { Parameters = [Parameter("class", "int"), Parameter("2nd", "int")] }
            ]
        });

        var cpp = CppSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".hpp", StringComparison.Ordinal))
            .Content;

        Assert.Contains("class union_ {", cpp, StringComparison.Ordinal);
        Assert.Contains("    int32_t template_;", cpp, StringComparison.Ordinal);
        Assert.Contains("void delete_(int32_t class_, int32_t arg1) { }", cpp, StringComparison.Ordinal);
    }

    // 所有命名空間攤平到同一個檔案，A.Foo 與 B.Foo 攤平後同名；第二個要加序號，否則重複定義。
    [Fact]
    public async Task SameSimpleTypeNameAcrossNamespacesGetsUniqueName()
    {
        var document = await BuildDocument(
            new TypeModel { FullName = "A.Foo", Namespace = "A", Name = "Foo", Kind = "class", Accessibility = "internal" },
            new TypeModel { FullName = "B.Foo", Namespace = "B", Name = "Foo", Kind = "class", Accessibility = "internal" });

        var cpp = CppSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".hpp", StringComparison.Ordinal))
            .Content;

        Assert.Contains("class Foo {", cpp, StringComparison.Ordinal);
        Assert.Contains("class Foo_2 {", cpp, StringComparison.Ordinal);
    }

    private static ParameterModel Parameter(string name, string type) => new() { Name = name, Type = type };

    private static MethodModel Method(string name, string returnType, bool isStatic = false) => new()
    {
        Name = name,
        Signature = $"{name}(...)",
        ReturnType = returnType,
        Accessibility = "public",
        IsStatic = isStatic,
        Parameters = []
    };

    private static async Task<BlueprintDocument> BuildDocument(params TypeModel[] types)
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(CppSkeletonSyntaxTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "cpp-syntax",
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
