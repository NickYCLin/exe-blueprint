using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

// 列舉成員的常數值來自不受信任的組件 metadata。若照字面寫進骨架，型別為 string 的常數就能在
// 四種語言的產出裡注入任意程式碼；只有真正的整數字面才可以出現在 `= 值` 裡。
public sealed class SkeletonEnumSafetyTests
{
    private const string Payload = "0,\n}\n// injected\nenum Z { Q";

    [Fact]
    public async Task EnumMembersOnlyEmitIntegralConstantValues()
    {
        var document = await BuildDocumentWithEnum();

        var csharp = Join(CSharpSkeletonGenerator.Generate(document));
        var cpp = Join(CppSkeletonGenerator.Generate(document));
        var rust = Join(RustSkeletonGenerator.Generate(document));
        var go = Join(GoSkeletonGenerator.Generate(document));

        foreach (var output in new[] { csharp, cpp, rust, go })
        {
            Assert.DoesNotContain("injected", output, StringComparison.Ordinal);
            Assert.DoesNotContain("enum Z", output, StringComparison.Ordinal);
        }

        Assert.Contains("Safe = 7,", csharp, StringComparison.Ordinal);
        Assert.Contains("Negative = -3,", csharp, StringComparison.Ordinal);
        Assert.Contains("Safe = 7", cpp, StringComparison.Ordinal);
        Assert.Contains("Safe = 7,", rust, StringComparison.Ordinal);
        Assert.Contains("ProbeSafe Probe = 7", go, StringComparison.Ordinal);

        // 非整數字面的成員在各語言都不得帶值：C#／C++／Rust 只留名稱，Go 退回 iota。
        Assert.Contains("Evil,", csharp, StringComparison.Ordinal);
        Assert.Contains("Evil,", rust, StringComparison.Ordinal);
        Assert.Contains("ProbeEvil Probe = iota", go, StringComparison.Ordinal);
        Assert.Contains("ProbeTricky Probe = iota", go, StringComparison.Ordinal);
    }

    private static string Join(IReadOnlyList<GeneratedFile> files) =>
        string.Join("\n", files.Select(file => file.Content));

    private static async Task<BlueprintDocument> BuildDocumentWithEnum()
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(SkeletonEnumSafetyTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "enum-probe",
            RelativePath = "Probe.dll",
            FileName = "Probe.dll",
            AssemblyName = "Probe",
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
                        FullName = "Tests.Probe",
                        Namespace = "Tests",
                        Name = "Probe",
                        Kind = "enum",
                        Accessibility = "internal",
                        Fields =
                        [
                            new FieldModel { Name = "value__", Type = "int", Accessibility = "public" },
                            Member("Safe", new ConstantValueModel { Type = "int", Value = "7" }),
                            Member("Negative", new ConstantValueModel { Type = "long", Value = "-3" }),
                            Member("Evil", new ConstantValueModel { Type = "string", Value = Payload }),
                            Member("Tricky", new ConstantValueModel { Type = "int", Value = "1; // injected" })
                        ]
                    }
                ]
            }
        };

        return analyzed with { Files = [artifact] };
    }

    private static FieldModel Member(string name, ConstantValueModel constant) => new()
    {
        Name = name,
        Type = "Tests.Probe",
        Accessibility = "public",
        IsStatic = true,
        IsConstant = true,
        ConstantValue = constant
    };
}
