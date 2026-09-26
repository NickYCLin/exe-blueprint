using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;

namespace ExeBlueprint.Core.Tests;

// 簽章裡 by-ref 參數一律是 ref，out 與 in 只反映在 Param 資料列的 Out／In 旗標。先前模型沒有保留，
// C# 骨架把 out 與 in 都寫成 ref，覆寫或實作外部介面的 out 方法（TryParse 這類）會是 CS0115／CS0535。
public sealed class ByReferenceParameterTests
{
    [Fact]
    public async Task ModelAndCSharpSkeletonKeepRefOutAndIn()
    {
        var document = await new BlueprintAnalyzer().AnalyzeAsync(typeof(ByReferenceParameterFixture).Assembly.Location);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == typeof(ByReferenceParameterFixture).FullName);
        var method = Assert.Single(fixture.Methods, candidate => candidate.Name == nameof(ByReferenceParameterFixture.Mix));

        Assert.Equal(
            ["ref", "out", "in", null],
            method.Parameters.Select(parameter => parameter.ByReference));

        var csharp = CSharpSkeletonGenerator.Generate(document)
            .Single(file => file.Content.Contains("class ByReferenceParameterFixture", StringComparison.Ordinal))
            .Content;

        Assert.Contains("Mix(ref int a, out int b, in int c, int d)", csharp, StringComparison.Ordinal);
    }
}

internal static class ByReferenceParameterFixture
{
    public static void Mix(ref int a, out int b, in int c, int d)
    {
        b = a + c + d;
    }
}
