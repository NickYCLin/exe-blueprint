using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using ExeBlueprint.Application;
using ExeBlueprint.Models;

namespace ExeBlueprint.Desktop.Tests;

public sealed class DesktopTestApp
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .WithDesktopFonts()
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
    public async Task ChineseLabelsUseEmbeddedFontWhenThePrimaryFontLacksGlyphs()
    {
        await desktopSession.Session.Dispatch(() =>
        {
            var embeddedFamily = new FontFamily(DesktopFonts.ChineseFontFamily);
            var primaryFamily = new FontFamily("fonts:Inter#Inter");
            foreach (var weight in new[] { FontWeight.Normal, FontWeight.SemiBold, FontWeight.Bold })
            {
                foreach (var character in "選擇要分析的程式儲存位置進階選項閱讀報告取消注意事項資料夾（）／，。")
                {
                    var glyphs = new Typeface(embeddedFamily, weight: weight).GlyphTypeface;
                    Assert.NotEqual(0, glyphs.CharacterToGlyphMap.GetGlyph(character));
                    Assert.True(FontManager.Current.TryMatchCharacter(character, FontStyle.Normal,
                        weight, FontStretch.Normal, primaryFamily, null, out var matched));
                    Assert.Equal(embeddedFamily.ToString(), matched.FontFamily.ToString(), ignoreCase: true);
                    Assert.NotEqual(0, matched.GlyphTypeface.CharacterToGlyphMap.GetGlyph(character));
                }
            }
        }, TestContextToken);
    }

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
                Input(window).Text = "\"\"";
                Assert.False(Control<Button>(window, "AnalyzeButton").IsEnabled);
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
        await session.Dispatch(async () =>
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
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
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
                return true;
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
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var window = CreateWindow(async (_, _, token) =>
            {
                entered.SetResult();
                try { await Task.Delay(Timeout.Infinite, token); }
                catch (OperationCanceledException) { cancelled = true; throw; }
                throw new InvalidOperationException("Unreachable");
            });
            try
            {
                Input(window).Text = Path.Combine(_temporaryDirectory, "example.exe");
                Click(window, "AnalyzeButton");
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(15));
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
    public async Task ClosingDuringAnalysisWaitsForCancellationCleanup()
    {
        await desktopSession.Session.Dispatch(async () =>
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var cleanupStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseCleanup = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var cleanupFinished = false;
            var windowClosed = false;
            var window = CreateWindow(async (_, _, token) =>
            {
                entered.SetResult();
                try { await Task.Delay(Timeout.Infinite, token); }
                finally
                {
                    cleanupStarted.SetResult();
                    await releaseCleanup.Task;
                    cleanupFinished = true;
                }

                throw new InvalidOperationException("Unreachable");
            });
            window.Closed += (_, _) => windowClosed = true;
            try
            {
                Input(window).Text = Path.Combine(_temporaryDirectory, "example.exe");
                Click(window, "AnalyzeButton");
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(15));
                window.Close();
                await cleanupStarted.Task.WaitAsync(TimeSpan.FromSeconds(15));
                Assert.True(window.IsVisible);
                Assert.False(windowClosed);
                Assert.False(Control<Button>(window, "CancelButton").IsEnabled);
                Assert.Contains("清理完成後", Control<TextBlock>(window, "StatusDetailText").Text);
                window.Close();
                Assert.False(windowClosed);
                Capture(window, "closing");
                releaseCleanup.SetResult();
                await WaitUntil(() => windowClosed);
                Assert.True(cleanupFinished);
                Assert.False(window.IsVisible);
                return true;
            }
            finally
            {
                releaseCleanup.TrySetResult();
                window.Close();
                await WaitUntil(() => windowClosed);
            }
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
        await session.Dispatch(async () =>
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
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.False(Control<Button>(window, "OpenReportButton").IsVisible);
                Assert.True(Control<Button>(window, "OpenOutputButton").IsVisible);
                return true;
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task KeyboardCanStartAnalysisAndLargeWarningListsStayBounded()
    {
        var session = desktopSession.Session;
        await session.Dispatch(async () =>
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
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.True(Control<Grid>(window, "ResultStats").IsVisible);
                Assert.Equal("150", Control<TextBlock>(window, "WarningCountText").Text);
                Assert.Equal(100, Control<ItemsControl>(window, "WarningsList").ItemCount);
                Assert.True(Control<TextBlock>(window, "WarningsMoreText").IsVisible);
                window.SetRenderScaling(1.5);
                AssertWithinWindow(window, start);
                return true;
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task SynchronousAnalysisWorkDoesNotBlockTheCancelButton()
    {
        var session = desktopSession.Session;
        await session.Dispatch(async () =>
        {
            var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var window = CreateWindow((request, _, token) =>
            {
                entered.SetResult(Dispatcher.UIThread.CheckAccess());
                // 模擬第一個 await 前的同步掃描。若工作仍在 UI 執行緒，取消按鈕就無法回應。
                token.WaitHandle.WaitOne(TimeSpan.FromSeconds(10));
                token.ThrowIfCancellationRequested();
                return Task.FromResult(Result(request.OutputDirectory!));
            });
            try
            {
                Input(window).Text = Path.Combine(_temporaryDirectory, "large-folder");
                Click(window, "AnalyzeButton");
                Assert.False(await entered.Task.WaitAsync(TimeSpan.FromSeconds(15)));
                Assert.True(Control<Button>(window, "CancelButton").IsEnabled);
                Click(window, "CancelButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.Equal("已取消", Control<TextBlock>(window, "StatusBadgeText").Text);
                Assert.True(Input(window).IsEnabled);
                return true;
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task PastedQuotedPathsReachAnalysisWithoutTheirWrapperQuotes()
    {
        var session = desktopSession.Session;
        await session.Dispatch(async () =>
        {
            BlueprintExportRequest? observed = null;
            var source = Path.Combine(_temporaryDirectory, "Example App.exe");
            var output = Path.Combine(_temporaryDirectory, "My Results");
            var ghidra = Path.Combine(_temporaryDirectory, "Ghidra Install");
            var window = CreateWindow((request, _, _) =>
            {
                observed = request;
                return Task.FromResult(Result(request.OutputDirectory!));
            });
            try
            {
                Input(window).Text = $"  \"{source}\"  ";
                Assert.Contains("Example App-", Output(window).Text);
                Output(window).Text = $"\"{output}\"";
                Control<TextBox>(window, "GhidraPathBox").Text = $"\"{ghidra}\"";
                Control<CheckBox>(window, "NativeCheckBox").IsChecked = true;
                Click(window, "AnalyzeButton");
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.NotNull(observed);
                Assert.Equal(source, observed.InputPath);
                Assert.Equal(output, observed.OutputDirectory);
                Assert.Equal(ghidra, observed.GhidraInstallDir);
                Assert.Equal(output, Output(window).Text);
                return true;
            }
            finally { window.Close(); }
        }, TestContextToken);
    }

    [Fact]
    public async Task InventoryModeDisablesDeepAnalysisAndDisplaysFileProgress()
    {
        await desktopSession.Session.Dispatch(async () =>
        {
            BlueprintExportRequest? observed = null;
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var window = CreateWindow(async (request, progress, _) =>
            {
                observed = request;
                progress.Report(new BlueprintExportProgress("正在分析檔案（250/1,000）", 250, 1000));
                entered.SetResult();
                await finish.Task;
                var result = Result(Path.Combine(_temporaryDirectory, "result"));
                return result with { Document = result.Document with { AnalysisMode = "inventory" }, Skeletons = [] };
            });
            try
            {
                Input(window).Text = Path.Combine(Path.GetPathRoot(_temporaryDirectory)!, "ExampleProjects", "LargeSystem", "Large.slnx");
                Output(window).Text = Path.Combine(Path.GetPathRoot(_temporaryDirectory)!, "ExampleResults", "LargeSystem");
                Control<CheckBox>(window, "InventoryCheckBox").IsChecked = true;
                Control<CheckBox>(window, "SourceModeCheckBox").IsChecked = true;
                Assert.False(Control<CheckBox>(window, "CSharpCheckBox").IsEnabled);
                Assert.False(Control<CheckBox>(window, "NativeCheckBox").IsEnabled);
                Capture(window, "inventory-ready");
                Click(window, "AnalyzeButton");
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(15));
                await WaitUntil(() => Control<ProgressBar>(window, "AnalysisProgressBar").Value == 25);
                Assert.False(Control<ProgressBar>(window, "AnalysisProgressBar").IsIndeterminate);
                Assert.True(observed!.InventoryOnly);
                Assert.True(observed.SourceMode);
                Assert.False(observed.EmitCSharp);
                Assert.False(observed.EnableNativeAnalysis);
                Assert.False(Control<CheckBox>(window, "InventoryCheckBox").IsEnabled);
                Capture(window, "inventory-running");
                finish.SetResult();
                await WaitUntil(() => Control<Button>(window, "AnalyzeButton").IsVisible);
                Assert.Equal("—", Control<TextBlock>(window, "TypeCountText").Text);
                Assert.Equal("—", Control<TextBlock>(window, "MethodCountText").Text);
                return true;
            }
            finally { finish.TrySetResult(); window.Close(); }
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
