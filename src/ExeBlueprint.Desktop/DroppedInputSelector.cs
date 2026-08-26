namespace ExeBlueprint.Desktop;

internal readonly record struct DroppedInputSelection(string? Path, string? ErrorMessage);

internal static class DroppedInputSelector
{
    public static DroppedInputSelection Select(IReadOnlyList<string?>? localPaths)
    {
        if (localPaths is null || localPaths.Count == 0)
        {
            return new(null, "拖放內容不是可用的檔案或資料夾。");
        }

        if (localPaths.Count > 1)
        {
            return new(null, "一次只能拖放一個檔案或資料夾。");
        }

        var path = localPaths[0];
        return string.IsNullOrWhiteSpace(path)
            ? new(null, "只能分析這台電腦上的檔案或資料夾。")
            : new(path, null);
    }
}
