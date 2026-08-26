using System.Text.Json;

namespace ExeBlueprint.Desktop;

internal sealed class RecentInputStore
{
    internal const int Capacity = 8;

    private readonly string _filePath;

    public RecentInputStore(string filePath)
    {
        _filePath = filePath;
    }

    public static RecentInputStore CreateDefault()
    {
        var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new RecentInputStore(Path.Combine(localData, "ExeBlueprint", "recent-inputs.json"));
    }

    public IReadOnlyList<string> Load()
    {
        if (!File.Exists(_filePath))
        {
            return [];
        }

        try
        {
            var items = JsonSerializer.Deserialize<string[]>(File.ReadAllText(_filePath));
            return Normalize(items ?? []);
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return [];
        }
    }

    public void Save(IReadOnlyList<string> paths)
    {
        var directory = Path.GetDirectoryName(_filePath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException("最近使用項目的儲存位置無效。");
        }

        Directory.CreateDirectory(directory);
        File.WriteAllText(_filePath, JsonSerializer.Serialize(Normalize(paths)));
    }

    public static IReadOnlyList<string> PutFirst(IReadOnlyList<string> existing, string path) =>
        Normalize([path, .. existing]);

    private static IReadOnlyList<string> Normalize(IEnumerable<string?> paths)
    {
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        return paths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path!)
            .Distinct(comparer)
            .Take(Capacity)
            .ToArray();
    }
}
