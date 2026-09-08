using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using ExeBlueprint.Application;
using ExeBlueprint.Models;

namespace ExeBlueprint.Desktop.Tests;

public sealed class DesktopTestApp
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .WithInterFont()
        .UseSkia()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}

public sealed class DesktopTestSession : IDisposable
{
    public HeadlessUnitTestSession Session { get; } =
        HeadlessUnitTestSession.StartNew(typeof(DesktopTestApp), AvaloniaTestIsolationLevel.PerAssembly);

    public void Dispose() => Session.Dispose();
}

public sealed class MainWindowTests(DesktopTestSession desktopSession) : IDisposable, IClassFixture<DesktopTestSession>
{
    private readonly string _temporaryDirectory = Path.Combine(
        Path.GetTempPath(), "ExeBlueprint.Desktop.Tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task InputChangesUpdateSuggestedOutputAndKeepCustomLocation()
    {
        var session = desktopSession.Session;
        await session.Dispatch(() =>
        {
            var window = CreateWindow();
            try
            {
                Assert.False(Control<Button>(window, "AnalyzeButton").IsEnabled);
                Assert.False(Control<Expander>(window, "AdvancedExpander").IsExpanded);
                Input(window).Text = Path.Combine(_temporaryDirectory, "first.exe");
                Assert.True(Control<Button>(window, "AnalyzeButton").IsEnabled);
                Assert.Contains("first-", Output(window).Text);
                Dispatcher.UIThread.RunJobs();
                Input(window).Text = Path.Combine(_temporaryDirectory, "second.exe");
                Assert.Contains("second-", Output(window).Text);
                var custom = Path.Combine(_temporaryDirectory, "my-results");
                Output(window).Text = custom;
                Input(window).Text = Path.Combine(_temporaryDirectory, "third.exe");
                Assert.Equal(custom, Output(window).Text);
                Input(window).Text = "";
                Assert.False(Control<Button>(window, "AnalyzeButton").IsEnabled);
                Assert.Equal(custom, Output(window).Text);
                Output(window).Text = "";
                Input(window).Text = Path.Combine(_temporaryDirectory, "fourth.exe");
                Assert.Contains("fourth-", Output(window).Text);
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Theory]
    [InlineData(1120, 820)]
    [InlineData(820, 640)]
    public async Task MainActionStaysVisibleWhenSettingsScroll(int width, int height)
    {
        var session = desktopSession.Session;
        await session.Dispatch(() =>
        {
            var window = CreateWindow();
            try
            {
                window.Width = width;
                window.Height = height;
                window.UpdateLayout();
                Capture(window, $"initial-{width}");
                AssertWithinWindow(window, Control<Button>(window, "AnalyzeButton"));
                Control<Expander>(window, "AdvancedExpander").IsExpanded = true;
                var scroll = Control<ScrollViewer>(window, "SetupScroll");
                window.UpdateLayout();
                scroll.ScrollToEnd();
                window.UpdateLayout();
                AssertWithinWindow(window, Control<Button>(window, "AnalyzeButton"));
                AssertWithinWindow(window, Control<TextBlock>(window, "StatusTitleText"));
                Assert.True(scroll.Extent.Height > scroll.Viewport.Height);
                Capture(window, $"advanced-{width}");
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task CompletionShowsWarningsAndChangingSourceClearsOldResult()
    {
        var session = desktopSession.Session;
        await session.Dispatch(() =>
        {
            IProgress<BlueprintExportProgress>? oldProgress = null;
            var window = CreateWindow((request, progress, _) =>
            {
                oldProgress = progress;
                Assert.True(request.EmitCSharp);
                Assert.False(request.JsonOnly);
                return Task.FromResult(Result(request.OutputDirectory!));
            });
            try
            {
                Input(window).Text = Path.Combine(_temporaryDirectory, "example.exe");
                Click(window, "AnalyzeButton");
                Assert.True(Control<Grid>(window, "ResultStats").IsVisible);
                Assert.True(Control<Button>(window, "OpenReportButton").IsVisible);
                Assert.True(Control<Button>(window, "OpenOutputButton").IsVisible);
                Assert.Equal("2", Control<TextBlock>(window, "WarningCountText").Text);
                Assert.Equal(2, Control<ItemsControl>(window, "WarningsList").ItemCount);
                oldProgress!.Report(new BlueprintExportProgress("stale progress"));
                Dispatcher.UIThread.RunJobs();
                Assert.DoesNotContain("stale", Control<TextBlock>(window, "StatusDetailText").Text);
                Capture(window, "complete");
                window.Width = 820;
                window.Height = 640;
                window.UpdateLayout();
                AssertWithinWindow(window, Control<Button>(window, "OpenReportButton"));
                AssertWithinWindow(window, Control<Button>(window, "AnalyzeButton"));
                Capture(window, "complete-820");
                Input(window).Text = Path.Combine(_temporaryDirectory, "another.exe");
                Assert.Contains("another-", Output(window).Text);
                Assert.False(Control<Grid>(window, "ResultStats").IsVisible);
                Assert.False(Control<Button>(window, "OpenOutputButton").IsVisible);
                Assert.False(Control<Button>(window, "OpenReportButton").IsVisible);
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task CancelStopsAnalysisAndRestoresControlsWithoutOldResults()
    {
        var session = desktopSession.Session;
        await session.Dispatch(async () =>
        {
            var cancelled = false;
            var window = CreateWindow(async (_, _, token) =>
            {
                try { await Task.Delay(Timeout.Infinite, token); }
                catch (OperationCanceledException) { cancelled = true; throw; }
                throw new InvalidOperationException("Unreachable");
            });
            try
            {
                Input(window).Text = Path.Combine(_temporaryDirectory, "example.exe");
                Click(window, "AnalyzeButton");
                Assert.False(Input(window).IsEnabled);
                Assert.False(Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.True(Control<Button>(window, "CancelButton").IsVisible);
                Capture(window, "running");
                Click(window, "CancelButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.True(cancelled);
                Assert.True(Input(window).IsEnabled);
                Assert.False(Control<Button>(window, "OpenOutputButton").IsVisible);
                Assert.Equal("已取消", Control<TextBlock>(window, "StatusBadgeText").Text);
                Capture(window, "cancelled");
                return true;
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task RealAnalysisWritesReportAndJsonThenRejectsExplicitOverwrite()
    {
        Directory.CreateDirectory(_temporaryDirectory);
        var input = Path.Combine(_temporaryDirectory, "settings.json");
        await File.WriteAllTextAsync(input, """{"application":{"name":"fixture"}}""");
        var session = desktopSession.Session;
        await session.Dispatch(async () =>
        {
            var window = CreateWindow();
            try
            {
                Input(window).Text = input;
                Output(window).Text = Path.Combine(_temporaryDirectory, "results");
                Click(window, "AnalyzeButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.True(File.Exists(Path.Combine(Output(window).Text!, "blueprint.json")));
                Assert.True(File.Exists(Path.Combine(Output(window).Text!, "REPORT.md")));
                Assert.True(Control<Grid>(window, "ResultStats").IsVisible);
                Click(window, "AnalyzeButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.Contains("已有分析結果", Control<TextBlock>(window, "StatusDetailText").Text);
                Assert.False(Control<Button>(window, "OpenReportButton").IsVisible);
                Assert.True(Input(window).IsEnabled);
                Capture(window, "error");
                Output(window).Text = "";
                Click(window, "AnalyzeButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                var firstAutomaticOutput = Output(window).Text!;
                Assert.True(File.Exists(Path.Combine(firstAutomaticOutput, "REPORT.md")));
                Click(window, "AnalyzeButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.NotEqual(firstAutomaticOutput, Output(window).Text);
                Assert.True(File.Exists(Path.Combine(firstAutomaticOutput, "REPORT.md")));
                Assert.True(File.Exists(Path.Combine(Output(window).Text!, "REPORT.md")));
                return true;
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task JsonOnlyResultDoesNotOfferAnOldReport()
    {
        var session = desktopSession.Session;
        await session.Dispatch(() =>
        {
            var window = CreateWindow((request, _, _) =>
            {
                Assert.True(request.JsonOnly);
                Assert.True(request.EmitRust);
                Assert.False(request.EmitCSharp);
                return Task.FromResult(Result(request.OutputDirectory!));
            });
            try
            {
                Input(window).Text = Path.Combine(_temporaryDirectory, "example.exe");
                Control<CheckBox>(window, "ReportCheckBox").IsChecked = false;
                Control<CheckBox>(window, "CSharpCheckBox").IsChecked = false;
                Control<CheckBox>(window, "RustCheckBox").IsChecked = true;
                Click(window, "AnalyzeButton");
                Assert.False(Control<Button>(window, "OpenReportButton").IsVisible);
                Assert.True(Control<Button>(window, "OpenOutputButton").IsVisible);
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task KeyboardCanStartAnalysisAndLargeWarningListsStayBounded()
    {
        var session = desktopSession.Session;
        await session.Dispatch(() =>
        {
            var window = CreateWindow((request, _, _) =>
            {
                var result = Result(request.OutputDirectory!);
                return Task.FromResult(result with
                {
                    Document = result.Document with { Warnings = Enumerable.Range(1, 150).Select(i => $"注意事項 {i}").ToArray() }
                });
            });
            try
            {
                Input(window).Focus();
                window.KeyTextInput(Path.Combine(_temporaryDirectory, "keyboard.exe"));
                var start = Control<Button>(window, "AnalyzeButton");
                Assert.True(start.Focus());
                window.KeyPressQwerty(PhysicalKey.Space, RawInputModifiers.None);
                window.KeyReleaseQwerty(PhysicalKey.Space, RawInputModifiers.None);
                Assert.True(Control<Grid>(window, "ResultStats").IsVisible);
                Assert.Equal("150", Control<TextBlock>(window, "WarningCountText").Text);
                Assert.Equal(100, Control<ItemsControl>(window, "WarningsList").ItemCount);
                Assert.True(Control<TextBlock>(window, "WarningsMoreText").IsVisible);
                window.SetRenderScaling(1.5);
                AssertWithinWindow(window, start);
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    private MainWindow CreateWindow(
        Func<BlueprintExportRequest, IProgress<BlueprintExportProgress>, CancellationToken, Task<BlueprintExportResult>>? run = null)
    {
        var window = new MainWindow(new RecentInputStore(Path.Combine(_temporaryDirectory, "recent.json")), run, _temporaryDirectory);
        window.Show();
        return window;
    }

    private static BlueprintExportResult Result(string output) => new(new BlueprintDocument
    {
        Input = new InputDescriptor { Name = "Example", Kind = "directory", SourcePath = "Example", FileCount = 24, TotalBytes = 8192 },
        Summary = new BlueprintSummary { TypeCount = 36, MethodCount = 128 },
        Warnings = ["部分相依套件不在來源資料夾中，請確認是否需要補齊。", "原生函式尚未分析。可在進階選項設定 Ghidra 後再次分析。"]
    }, output, [new SkeletonExportResult("C#", Path.Combine(output, "reconstructed-csharp"), 12)]);

    private static T Control<T>(MainWindow window, string name) where T : Control => window.FindControl<T>(name)!;
    private static TextBox Input(MainWindow window) => Control<TextBox>(window, "InputPathBox");
    private static TextBox Output(MainWindow window) => Control<TextBox>(window, "OutputPathBox");
    private static void Click(MainWindow window, string name) =>
        Control<Button>(window, name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

    private static void AssertWithinWindow(MainWindow window, Control control)
    {
        var point = control.TranslatePoint(default, window);
        Assert.NotNull(point);
        Assert.True(control.Bounds.Width > 0 && control.Bounds.Height > 0);
        Assert.InRange(point.Value.X, 0, window.ClientSize.Width - control.Bounds.Width);
        Assert.InRange(point.Value.Y, 0, window.ClientSize.Height - control.Bounds.Height);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var timer = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(timer.Elapsed < TimeSpan.FromSeconds(15), "UI operation timed out");
            await Task.Delay(10);
        }
    }

    private static void Capture(MainWindow window, string name)
    {
        var directory = Environment.GetEnvironmentVariable("EXEBLUEPRINT_UI_SCREENSHOTS");
        if (string.IsNullOrWhiteSpace(directory)) { return; }
        Directory.CreateDirectory(directory);
        using var frame = window.CaptureRenderedFrame();
        Assert.NotNull(frame);
        frame.Save(Path.Combine(directory, name + ".png"), PngBitmapEncoderOptions.Default);
    }

    private static CancellationToken TestContextToken => CancellationToken.None;

    public void Dispose()
    {
        if (Directory.Exists(_temporaryDirectory))
        {
            Directory.Delete(_temporaryDirectory, recursive: true);
        }
    }
}
