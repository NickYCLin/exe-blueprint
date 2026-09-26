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

    // 型別、成員、方法、命名空間與型別文字都直接來自不受信任的 metadata。含 ; { } 或換行的名稱會把
    // 任意程式碼寫進骨架；零寬字元會偽裝或製造重複定義；空名稱與開頭數字則無法編譯。
    [Fact]
    public async Task NamesFromMetadataCannotInjectCode()
    {
        const string evilNamespace = "Ev;il\n// injected";
        var document = await BuildDocument(
            new TypeModel
            {
                FullName = $"{evilNamespace}.A",
                Namespace = evilNamespace,
                Name = "A { }\n// injected\nclass B",
                Kind = "class",
                Accessibility = "internal",
                Fields =
                [
                    new FieldModel { Name = "x = 1; public static int y", Type = "int", Accessibility = "public" },
                    new FieldModel { Name = "Pay​ment", Type = "int", Accessibility = "public" },
                    new FieldModel { Name = "1st", Type = "int", Accessibility = "public" },
                    new FieldModel { Name = "", Type = "int", Accessibility = "public" },
                    new FieldModel { Name = "Keep", Type = "System.Collections.Generic.List<int>[]", Accessibility = "public" },
                    new FieldModel { Name = "Bad", Type = "int; // injected", Accessibility = "public" }
                ],
                Methods =
                [
                    new MethodModel
                    {
                        Name = "M() { }\n// injected\nvoid N",
                        Signature = "M(...)",
                        ReturnType = "void",
                        Accessibility = "public",
                        Parameters = []
                    }
                ]
            },
            new TypeModel
            {
                FullName = $"{evilNamespace}.class",
                Namespace = evilNamespace,
                Name = "class",
                Kind = "class",
                Accessibility = "internal"
            });

        var csharp = string.Join(
            "\n",
            CSharpSkeletonGenerator.Generate(document)
                .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.Ordinal))
                .Select(file => file.Content));

        Assert.DoesNotContain("// injected", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("public static int y", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("class B", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("void N", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("​", csharp, StringComparison.Ordinal);
        Assert.Contains("namespace Ev_il", csharp, StringComparison.Ordinal);
        Assert.Contains("class @class", csharp, StringComparison.Ordinal);
        Assert.Contains("Pay_ment", csharp, StringComparison.Ordinal);
        Assert.Contains("int _1st", csharp, StringComparison.Ordinal);
        Assert.Contains("int _ = ", csharp, StringComparison.Ordinal);
        Assert.Contains("System.Collections.Generic.List<int>[] Keep", csharp, StringComparison.Ordinal);
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
