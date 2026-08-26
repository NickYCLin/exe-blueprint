using ExeBlueprint.Desktop;

namespace ExeBlueprint.Desktop.Tests;

public sealed class RecentInputStoreTests : IDisposable
{
    private readonly string _temporaryDirectory = Path.Combine(
        Path.GetTempPath(),
        "ExeBlueprint.Desktop.Tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void LoadReturnsEmptyListWhenFileDoesNotExist()
    {
        var store = CreateStore();

        Assert.Empty(store.Load());
    }

    [Fact]
    public void SaveAndLoadPreserveNormalizedPaths()
    {
        var store = CreateStore();
        var paths = Enumerable.Range(0, RecentInputStore.Capacity + 2)
            .Select(index => $"source-{index}")
            .Prepend("source-0")
            .Prepend(" ")
            .ToArray();

        store.Save(paths);
        var loaded = store.Load();

        Assert.Equal(RecentInputStore.Capacity, loaded.Count);
        Assert.Equal("source-0", loaded[0]);
        Assert.Equal(loaded.Count, loaded.Distinct().Count());
    }

    [Fact]
    public void LoadIgnoresMalformedJson()
    {
        var store = CreateStore();
        Directory.CreateDirectory(_temporaryDirectory);
        File.WriteAllText(Path.Combine(_temporaryDirectory, "recent-inputs.json"), "not-json");

        Assert.Empty(store.Load());
    }

    [Fact]
    public void PutFirstMovesExistingPathToFront()
    {
        var result = RecentInputStore.PutFirst(["one", "two", "three"], "two");

        Assert.Equal(["two", "one", "three"], result);
    }

    public void Dispose()
    {
        if (Directory.Exists(_temporaryDirectory))
        {
            Directory.Delete(_temporaryDirectory, recursive: true);
        }
    }

    private RecentInputStore CreateStore() =>
        new(Path.Combine(_temporaryDirectory, "recent-inputs.json"));
}
