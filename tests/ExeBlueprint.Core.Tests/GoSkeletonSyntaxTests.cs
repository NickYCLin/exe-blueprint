using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

// Go 骨架有幾種輸出是必然無法編譯的語法，這裡逐一鎖定。
public sealed class GoSkeletonSyntaxTests
{
    // Go 沒有原始識別字語法，撞到關鍵字只能改名；receiver 叫 r，參數同名會是 duplicate argument。
    [Fact]
    public async Task KeywordAndReceiverClashingNamesAreRenamed()
    {
        var document = await BuildDocument(
            new TypeModel
            {
                FullName = "Tests.Probe",
                Namespace = "Tests",
                Name = "Probe",
                Kind = "class",
                Accessibility = "internal",
                Fields = [new FieldModel { Name = "map", Type = "int", Accessibility = "public" }],
                Methods =
                [
                    Method("select") with
                    {
                        Parameters = [Parameter("func", "int"), Parameter("r", "int"), Parameter("chan", "string")]
                    },
                    Method("go", isStatic: true)
                ]
            },
            new TypeModel
            {
                FullName = "Tests.IRange",
                Namespace = "Tests",
                Name = "IRange",
                Kind = "interface",
                Accessibility = "internal",
                Methods = [Method("range")]
            },
            new TypeModel
            {
                FullName = "Tests.type",
                Namespace = "Tests",
                Name = "type",
                Kind = "class",
                Accessibility = "internal"
            });

        var go = GoSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".go", StringComparison.Ordinal))
            .Content;

        Assert.Contains("    map_ int32", go, StringComparison.Ordinal);
        Assert.Contains("func (r *Probe) select_(func_ int32, r_ int32, chan_ string) {", go, StringComparison.Ordinal);
        Assert.Contains("func Probe_go() {", go, StringComparison.Ordinal);
        Assert.Contains("    range_()", go, StringComparison.Ordinal);
        Assert.Contains("type type_ struct {", go, StringComparison.Ordinal);
    }

    // Go 的欄位與方法共用名稱空間，同名是錯誤；.NET 的多載在這裡也是重複宣告，依序加序號。
    [Fact]
    public async Task OverloadsAndFieldMethodClashesGetUniqueNames()
    {
        var document = await BuildDocument(
            new TypeModel
            {
                FullName = "Tests.Probe",
                Namespace = "Tests",
                Name = "Probe",
                Kind = "class",
                Accessibility = "internal",
                Fields = [new FieldModel { Name = "Run", Type = "int", Accessibility = "public" }],
                Methods =
                [
                    Method("Run"),
                    Method("Run") with { Parameters = [Parameter("x", "int")] },
                    Method("Make", isStatic: true),
                    Method("Make", isStatic: true)
                ]
            },
            new TypeModel
            {
                FullName = "Tests.IDo",
                Namespace = "Tests",
                Name = "IDo",
                Kind = "interface",
                Accessibility = "internal",
                Methods = [Method("Do"), Method("Do")]
            });

        var go = GoSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith(".go", StringComparison.Ordinal))
            .Content;

        Assert.Contains("    Run int32", go, StringComparison.Ordinal);
        Assert.Contains("func (r *Probe) Run_2() {", go, StringComparison.Ordinal);
        Assert.Contains("func (r *Probe) Run_3(x int32) {", go, StringComparison.Ordinal);
        Assert.Contains("func Probe_Make() {", go, StringComparison.Ordinal);
        Assert.Contains("func Probe_Make_2() {", go, StringComparison.Ordinal);
        Assert.Contains("    Do()", go, StringComparison.Ordinal);
        Assert.Contains("    Do_2()", go, StringComparison.Ordinal);
    }

    private static ParameterModel Parameter(string name, string type) => new() { Name = name, Type = type };

    private static MethodModel Method(string name, bool isStatic = false) => new()
    {
        Name = name,
        Signature = $"{name}(...)",
        ReturnType = "void",
        Accessibility = "public",
        IsStatic = isStatic,
        Parameters = []
    };

    private static async Task<BlueprintDocument> BuildDocument(params TypeModel[] types)
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(GoSkeletonSyntaxTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "go-syntax",
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
