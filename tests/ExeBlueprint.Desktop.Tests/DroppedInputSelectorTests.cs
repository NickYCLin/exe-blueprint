using ExeBlueprint.Desktop;

namespace ExeBlueprint.Desktop.Tests;

public sealed class DroppedInputSelectorTests
{
    [Fact]
    public void SelectReturnsSingleLocalPath()
    {
        var result = DroppedInputSelector.Select([@"C:\Apps\Sample.exe"]);

        Assert.Equal(@"C:\Apps\Sample.exe", result.Path);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void SelectRejectsMultipleItems()
    {
        var result = DroppedInputSelector.Select([@"C:\Apps\One.exe", @"C:\Apps\Two.dll"]);

        Assert.Null(result.Path);
        Assert.Equal("一次只能拖放一個檔案或資料夾。", result.ErrorMessage);
    }

    [Theory]
    [InlineData()]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SelectRejectsMissingLocalPath(params string?[] paths)
    {
        var result = DroppedInputSelector.Select(paths);

        Assert.Null(result.Path);
        Assert.NotNull(result.ErrorMessage);
    }
}
