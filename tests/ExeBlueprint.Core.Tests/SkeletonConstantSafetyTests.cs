using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

// C# 骨架裡的常數字面全部來自不受信任的 metadata：字串與 char 要完整跳脫，浮點特殊值要用
// 常數表示，列舉型別的 const 要補轉型，否則產出不是無法編譯就是悄悄變值。
public sealed class SkeletonConstantSafetyTests
{
    [Fact]
    public async Task ConstantFieldsAreEscapedAndTypedSoTheyCompileUnchanged()
    {
        var csharp = await GenerateClassWithConstants();

        // 字串：U+2028 與孤立代理字元、NUL 都要以 \uXXXX 或既有跳脫寫出，不能原樣落地。
        Assert.Contains("Line = \"a\\u2028b\";", csharp, StringComparison.Ordinal);
        Assert.Contains("Lone = \"\\uD800\";", csharp, StringComparison.Ordinal);
        Assert.Contains("Ctrl = \"x\\0y\";", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("\u2028", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("\uD800", csharp, StringComparison.Ordinal);

        // char：單引號與孤立代理字元。
        Assert.Contains("Quote = '\\'';", csharp, StringComparison.Ordinal);
        Assert.Contains("Surrogate = '\\uD800';", csharp, StringComparison.Ordinal);

        // 浮點：NaN／無限大用常數，一般值照舊加後綴。
        Assert.Contains("Nan = float.NaN;", csharp, StringComparison.Ordinal);
        Assert.Contains("Inf = double.NegativeInfinity;", csharp, StringComparison.Ordinal);
        Assert.Contains("Half = 0.5F;", csharp, StringComparison.Ordinal);
        Assert.DoesNotContain("NaNF", csharp, StringComparison.Ordinal);

        // 列舉型別的 const 補上宣告型別轉型；宣告型別就是常數型別時不多加轉型。
        Assert.Contains("BindingFlags)20;", csharp, StringComparison.Ordinal);
        Assert.Contains("Plain = 5;", csharp, StringComparison.Ordinal);
    }

    private static async Task<string> GenerateClassWithConstants()
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(SkeletonConstantSafetyTests).Assembly.Location);
        var artifact = analyzed.Files[0] with
        {
            Id = "constant-probe",
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
                        FullName = "Tests.Constants",
                        Namespace = "Tests",
                        Name = "Constants",
                        Kind = "class",
                        Accessibility = "internal",
                        Fields =
                        [
                            Constant("Line", "string", "string", "a\u2028b"),
                            Constant("Lone", "string", "string", "\uD800"),
                            Constant("Ctrl", "string", "string", "x\0y"),
                            Constant("Quote", "char", "char", "'"),
                            Constant("Surrogate", "char", "char", "\uD800"),
                            Constant("Nan", "float", "float", "NaN"),
                            Constant("Inf", "double", "double", "-Infinity"),
                            Constant("Half", "float", "float", "0.5"),
                            Constant("Flags", "System.Reflection.BindingFlags", "int", "20"),
                            Constant("Plain", "int", "int", "5")
                        ]
                    }
                ]
            }
        };
        var document = analyzed with { Files = [artifact] };

        return CSharpSkeletonGenerator.Generate(document)
            .Single(file => file.RelativePath.EndsWith("/Tests.cs", StringComparison.Ordinal))
            .Content;
    }

    private static FieldModel Constant(string name, string declaredType, string constantType, string value) => new()
    {
        Name = name,
        Type = declaredType,
        Accessibility = "public",
        IsStatic = true,
        IsConstant = true,
        ConstantValue = new ConstantValueModel { Type = constantType, Value = value }
    };
}
