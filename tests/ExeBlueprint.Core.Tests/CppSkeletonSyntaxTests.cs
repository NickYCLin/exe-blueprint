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
