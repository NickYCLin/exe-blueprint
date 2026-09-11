using System.Diagnostics;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ExeBlueprint.Application;

namespace ExeBlueprint.Desktop;

public sealed partial class MainWindow : Window
{
    private readonly Func<BlueprintExportRequest, IProgress<BlueprintExportProgress>, CancellationToken, Task<BlueprintExportResult>> _runAnalysis;
    private readonly RecentInputStore _recentInputStore;
    private readonly string _outputBaseDirectory;
    private readonly List<string> _recentInputPaths = [];
    private CancellationTokenSource? _analysisCancellation;
    private string? _lastOutputDirectory;
    private string? _lastReportPath;
    private bool _settingSuggestedOutput;
    private bool _outputWasEdited;
    private bool _inputDropZoneActive;
    private bool _closeAfterAnalysis;

    public MainWindow() : this(RecentInputStore.CreateDefault())
    {
    }

    internal MainWindow(
        RecentInputStore recentInputStore,
        Func<BlueprintExportRequest, IProgress<BlueprintExportProgress>, CancellationToken, Task<BlueprintExportResult>>? runAnalysis = null,
        string? outputBaseDirectory = null)
    {
        _recentInputStore = recentInputStore;
        _runAnalysis = runAnalysis ?? new BlueprintExportService().RunAsync;
        _outputBaseDirectory = outputBaseDirectory ?? GetDefaultOutputBaseDirectory();
        InitializeComponent();
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.2.0";
        VersionText.Text = $"桌面版 {version}";
        DragDrop.SetAllowDrop(InputDropZone, true);
        DragDrop.AddDragEnterHandler(InputDropZone, OnInputDragEnter);
        DragDrop.AddDragLeaveHandler(InputDropZone, OnInputDragLeave);
        DragDrop.AddDragOverHandler(InputDropZone, OnInputDragOver);
        DragDrop.AddDropHandler(InputDropZone, OnInputDrop);
        LoadRecentInputs();
        InputPathBox.PropertyChanged += (_, e) =>
        {
            if (e.Property == TextBox.TextProperty)
            {
                OnInputPathChanged();
            }
        };
        OutputPathBox.PropertyChanged += (_, e) =>
        {
            if (e.Property == TextBox.TextProperty && !_settingSuggestedOutput)
            {
                _outputWasEdited = NormalizePathInput(OutputPathBox.Text) is not null;
            }
        };
    }

    private static string GetDefaultOutputBaseDirectory()
    {
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        return string.IsNullOrWhiteSpace(documents)
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : documents;
    }

    private async void OnChooseFile(object? sender, RoutedEventArgs e)
    {
        SetInputPath(await PickFileAsync());
    }

    private async Task<string?> PickFileAsync()
    {
        if (!StorageProvider.CanOpen)
        {
            ShowError("這個桌面環境無法開啟檔案選擇視窗。");
            return null;
        }

        try
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "選擇要分析的程式、專案或壓縮檔",
                AllowMultiple = false,
                FileTypeFilter =
                [
                    new FilePickerFileType("程式、專案與壓縮檔") { Patterns = ["*.exe", "*.dll", "*.zip", "*.asar", "*.sln", "*.slnx", "*.csproj", "*.vbproj", "*.fsproj", "*.vcxproj"] },
                    new FilePickerFileType("方案與專案") { Patterns = ["*.sln", "*.slnx", "*.csproj", "*.vbproj", "*.fsproj", "*.vcxproj"] },
                    new FilePickerFileType("所有檔案") { Patterns = ["*"] }
                ]
            });
            return files.FirstOrDefault()?.TryGetLocalPath();
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            ShowError($"無法開啟檔案選擇視窗：{exception.Message}");
            return null;
        }
    }

    private async void OnChooseFolder(object? sender, RoutedEventArgs e)
    {
        SetInputPath(await PickFolderAsync("選擇要分析的資料夾"));
    }

    private void OnRecentInputSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (RecentInputComboBox.SelectedItem is not string path)
        {
            return;
        }

        SetInputPath(path);
        RecentInputComboBox.SelectedIndex = -1;
    }

    private void OnClearRecentInputs(object? sender, RoutedEventArgs e)
    {
        try
        {
            _recentInputStore.Save([]);
            _recentInputPaths.Clear();
            RefreshRecentInputs();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            ShowError($"無法清除最近使用項目：{exception.Message}");
        }
    }

    private async void OnChooseOutput(object? sender, RoutedEventArgs e)
    {
        var path = await PickFolderAsync("選擇輸出位置");
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        OutputPathBox.Text = path;
        _outputWasEdited = true;
    }

    private async void OnChooseGhidra(object? sender, RoutedEventArgs e)
    {
        var path = await PickFolderAsync("選擇 Ghidra 安裝目錄");
        if (!string.IsNullOrWhiteSpace(path))
        {
            GhidraPathBox.Text = path;
            NativeCheckBox.IsChecked = true;
        }
    }

    private void OnInputDragEnter(object? sender, DragEventArgs e)
    {
        var canAccept = CanAcceptInputDrop(e);
        e.DragEffects = canAccept ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
        SetInputDropZoneActive(canAccept);
    }

    private void OnInputDragLeave(object? sender, DragEventArgs e)
    {
        e.Handled = true;
        SetInputDropZoneActive(false);
    }

    private void OnInputDragOver(object? sender, DragEventArgs e)
    {
        var canAccept = CanAcceptInputDrop(e);
        e.DragEffects = canAccept ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
        SetInputDropZoneActive(canAccept);
    }

    private void OnInputDrop(object? sender, DragEventArgs e)
    {
        SetInputDropZoneActive(false);
        e.Handled = true;

        if (!CanAcceptInputDrop(e))
        {
            e.DragEffects = DragDropEffects.None;
            return;
        }

        var localPaths = e.DataTransfer.TryGetFiles()?
            .Select(item => item.TryGetLocalPath())
            .ToArray() ?? [];
        var selection = DroppedInputSelector.Select(localPaths);
        if (selection.ErrorMessage is not null)
        {
            e.DragEffects = DragDropEffects.None;
            ShowError(selection.ErrorMessage);
            return;
        }

        SetInputPath(selection.Path);
        e.DragEffects = DragDropEffects.Copy;
    }

    private bool CanAcceptInputDrop(DragEventArgs e) =>
        _analysisCancellation is null && e.DataTransfer.Formats.Contains(DataFormat.File);

    private void SetInputDropZoneActive(bool active)
    {
        if (_inputDropZoneActive == active)
        {
            return;
        }

        _inputDropZoneActive = active;
        InputDropZone.Background = new SolidColorBrush(Color.Parse(active ? "#E4EBFF" : "#F3F6FF"));
        InputDropZone.BorderBrush = new SolidColorBrush(Color.Parse(active ? "#3455C5" : "#B9C8EF"));
        InputDropTitleText.Foreground = new SolidColorBrush(Color.Parse(active ? "#1D4ED8" : "#334155"));
        InputDropTitleText.Text = active ? "放開即可選擇這個來源" : "把檔案或資料夾拖到這裡";
    }

    private void OnInputPathChanged()
    {
        ClearResult();
        var hasInput = NormalizePathInput(InputPathBox.Text) is not null;
        AnalyzeButton.IsEnabled = _analysisCancellation is null && hasInput;
        SetStatus(hasInput ? "可以開始" : "尚未開始",
            hasInput ? "準備好了" : "先選擇分析來源",
            hasInput ? "確認儲存位置後，按下「開始分析」。" : "在左側選擇檔案、資料夾，或直接拖曳進來。");
        EmptyResultHint.IsVisible = true;
        if (_outputWasEdited)
        {
            return;
        }

        SuggestOutput();
    }

    private void SuggestOutput()
    {
        try
        {
            _settingSuggestedOutput = true;
            var inputPath = NormalizePathInput(InputPathBox.Text);
            if (inputPath is null)
            {
                OutputPathBox.Text = string.Empty;
                return;
            }

            var suggested = BlueprintExportService.CreateDefaultOutputDirectory(inputPath, _outputBaseDirectory);
            var available = suggested;
            for (var number = 2; Directory.Exists(available) || File.Exists(available); number++)
            {
                available = $"{suggested}-{number}";
            }

            OutputPathBox.Text = available;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            OutputPathBox.Text = string.Empty;
        }
        finally
        {
            _settingSuggestedOutput = false;
        }
    }

    private async void OnAnalyze(object? sender, RoutedEventArgs e)
    {
        if (_analysisCancellation is not null)
        {
            return;
        }

        var inputPath = NormalizePathInput(InputPathBox.Text);
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            ShowError("請先選擇要分析的檔案、資料夾、ZIP 或 ASAR。");
            return;
        }

        if (!_outputWasEdited)
        {
            SuggestOutput();
        }

        ClearResult();
        var cancellation = new CancellationTokenSource();
        _analysisCancellation = cancellation;
        SetBusy(true);
        EmptyResultHint.IsVisible = false;
        SetStatus("分析中", "正在整理程式資料", "檔案較多或啟用 Ghidra 時會需要一些時間。");
        var progress = new Progress<BlueprintExportProgress>(value =>
        {
            if (ReferenceEquals(_analysisCancellation, cancellation) && !cancellation.IsCancellationRequested)
            {
                StatusDetailText.Text = value.Message;
                AnalysisProgressBar.IsIndeterminate = value.TotalFiles is not > 0;
                if (value.TotalFiles is > 0)
                    AnalysisProgressBar.Value = 100.0 * value.CompletedFiles.GetValueOrDefault() / value.TotalFiles.Value;
            }
        });

        try
        {
            var request = new BlueprintExportRequest
            {
                InputPath = inputPath,
                BaseDirectory = _outputBaseDirectory,
                OutputDirectory = NormalizePathInput(OutputPathBox.Text),
                Overwrite = OverwriteCheckBox.IsChecked == true,
                JsonOnly = ReportCheckBox.IsChecked != true,
                InventoryOnly = InventoryCheckBox.IsChecked == true,
                SourceMode = SourceModeCheckBox.IsChecked == true || SourceAnalysisCheckBox.IsChecked == true,
                EnableSourceAnalysis = SourceAnalysisCheckBox.IsChecked == true,
                EmitCSharp = InventoryCheckBox.IsChecked != true && CSharpCheckBox.IsChecked == true,
                EmitCpp = InventoryCheckBox.IsChecked != true && CppCheckBox.IsChecked == true,
                EmitRust = InventoryCheckBox.IsChecked != true && RustCheckBox.IsChecked == true,
                EmitGo = InventoryCheckBox.IsChecked != true && GoCheckBox.IsChecked == true,
                EnableNativeAnalysis = InventoryCheckBox.IsChecked != true && NativeCheckBox.IsChecked == true,
                GhidraInstallDir = NormalizePathInput(GhidraPathBox.Text)
            };
            var result = await Task.Run(
                () => _runAnalysis(request, progress, cancellation.Token),
                cancellation.Token);

            _lastOutputDirectory = result.OutputDirectory;
            _lastReportPath = request.JsonOnly ? null : Path.Combine(result.OutputDirectory, "REPORT.md");
            _settingSuggestedOutput = true;
            try { OutputPathBox.Text = result.OutputDirectory; }
            finally { _settingSuggestedOutput = false; }
            ShowResult(result);
            OpenOutputButton.IsEnabled = true;
            if (!TryRememberRecentInput(inputPath))
            {
                StatusDetailText.Text += "（未能儲存最近使用紀錄）";
            }
        }
        catch (OperationCanceledException)
        {
            SetStatus("已取消", "分析已停止", "可以調整選項後再試一次。已產生的部分檔案可能仍留在儲存位置。");
        }
        catch (Exception exception) when (exception is ArgumentException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            ShowError(exception.Message);
        }
        finally
        {
            cancellation.Dispose();
            _analysisCancellation = null;
            SetBusy(false);
            if (_closeAfterAnalysis)
            {
                Close();
            }
        }
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => RequestCancellation();

    private void RequestCancellation()
    {
        CancelButton.IsEnabled = false;
        SetStatus("停止中", "正在取消分析", "正在停止，請稍候…");
        _analysisCancellation?.Cancel();
    }

    private void OnOpenReport(object? sender, RoutedEventArgs e)
    {
        if (_lastReportPath is null || !File.Exists(_lastReportPath))
        {
            SetStatus("找不到報告", "報告可能已被移動", "請開啟結果資料夾確認，或重新執行分析。", warning: true);
            OpenReportButton.IsEnabled = false;
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo { FileName = _lastReportPath, UseShellExecute = true });
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            SetStatus("無法開啟", "請從結果資料夾查看報告",
                $"可用文字編輯器開啟 REPORT.md。{exception.Message}", warning: true);
        }
    }

    private void OnOpenOutput(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_lastOutputDirectory) || !Directory.Exists(_lastOutputDirectory))
        {
            ShowError("找不到輸出資料夾，可能已被移動或刪除。");
            OpenOutputButton.IsEnabled = false;
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = _lastOutputDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            ShowError($"無法開啟輸出資料夾：{exception.Message}");
        }
    }

    private async Task<string?> PickFolderAsync(string title)
    {
        if (!StorageProvider.CanPickFolder)
        {
            ShowError("這個桌面環境無法開啟資料夾選擇視窗。");
            return null;
        }

        try
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = title,
                AllowMultiple = false
            });
            return folders.FirstOrDefault()?.TryGetLocalPath();
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            ShowError($"無法開啟資料夾選擇視窗：{exception.Message}");
            return null;
        }
    }

    private void SetInputPath(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            InputPathBox.Text = path;
        }
    }

    private void LoadRecentInputs()
    {
        _recentInputPaths.AddRange(_recentInputStore.Load());
        RefreshRecentInputs();
    }

    private bool TryRememberRecentInput(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            var updated = RecentInputStore.PutFirst(_recentInputPaths, fullPath);
            _recentInputStore.Save(updated);
            _recentInputPaths.Clear();
            _recentInputPaths.AddRange(updated);
            RefreshRecentInputs();
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    private void RefreshRecentInputs()
    {
        RecentInputsExpander.IsVisible = _recentInputPaths.Count > 0;
        RecentInputComboBox.ItemsSource = _recentInputPaths.ToArray();
        RecentInputComboBox.IsEnabled = _analysisCancellation is null && _recentInputPaths.Count > 0;
        ClearRecentInputsButton.IsEnabled = _analysisCancellation is null && _recentInputPaths.Count > 0;
    }

    private void SetBusy(bool busy)
    {
        DragDrop.SetAllowDrop(InputDropZone, !busy);
        SetInputDropZoneActive(false);
        InputPathBox.IsEnabled = !busy;
        OutputPathBox.IsEnabled = !busy;
        GhidraPathBox.IsEnabled = !busy;
        ChooseFileButton.IsEnabled = !busy;
        ChooseFolderButton.IsEnabled = !busy;
        RecentInputComboBox.IsEnabled = !busy && _recentInputPaths.Count > 0;
        ClearRecentInputsButton.IsEnabled = !busy && _recentInputPaths.Count > 0;
        ChooseOutputButton.IsEnabled = !busy;
        ChooseGhidraButton.IsEnabled = !busy;
        ReportCheckBox.IsEnabled = !busy;
        InventoryCheckBox.IsEnabled = !busy;
        SourceModeCheckBox.IsEnabled = !busy;
        SourceAnalysisCheckBox.IsEnabled = !busy;
        CSharpCheckBox.IsEnabled = !busy && InventoryCheckBox.IsChecked != true;
        CppCheckBox.IsEnabled = CSharpCheckBox.IsEnabled;
        RustCheckBox.IsEnabled = CSharpCheckBox.IsEnabled;
        GoCheckBox.IsEnabled = CSharpCheckBox.IsEnabled;
        OverwriteCheckBox.IsEnabled = !busy;
        NativeCheckBox.IsEnabled = CSharpCheckBox.IsEnabled;
        AnalyzeButton.IsEnabled = !busy && NormalizePathInput(InputPathBox.Text) is not null;
        AnalyzeButton.IsVisible = !busy;
        OpenOutputButton.IsVisible = !busy && _lastOutputDirectory is not null;
        OpenReportButton.IsVisible = !busy && _lastReportPath is not null;
        OpenReportButton.IsEnabled = true;
        CancelButton.IsVisible = busy;
        CancelButton.IsEnabled = busy;
        AnalysisProgressBar.IsVisible = busy;
        AnalysisProgressBar.IsIndeterminate = true;
    }

    private void OnAnalysisModeChanged(object? sender, RoutedEventArgs e)
    {
        if (CSharpCheckBox is not null) SetBusy(_analysisCancellation is not null);
    }

    private void ShowError(string message)
    {
        ClearResult();
        EmptyResultHint.IsVisible = false;
        SetStatus("需要處理", "這次未完成分析", message, warning: true);
    }

    private void ClearResult()
    {
        _lastOutputDirectory = null;
        _lastReportPath = null;
        ResultStats.IsVisible = false;
        SummaryText.IsVisible = false;
        WarningsExpander.IsVisible = false;
        WarningsList.ItemsSource = null;
        WarningsMoreText.IsVisible = false;
        ResultLocationPanel.IsVisible = false;
        OpenOutputButton.IsVisible = false;
        OpenReportButton.IsVisible = false;
        AnalyzeButton.Content = "開始分析";
    }

    private void ShowResult(BlueprintExportResult result)
    {
        var document = result.Document;
        var hasWarnings = document.Warnings.Count > 0;
        SetStatus(hasWarnings ? "已完成 · 有注意事項" : "已完成", "分析結果已備妥",
            hasWarnings ? "部分內容需要留意，請查看下方說明。"
                : _lastReportPath is null ? "可開啟資料夾查看完整結果。" : "可閱讀報告，或開啟資料夾查看完整結果。",
            warning: hasWarnings, success: !hasWarnings);
        FileCountText.Text = document.Input.FileCount.ToString("N0");
        var structureOnly = document.AnalysisMode == "inventory" ||
            document.Input.Kind == "source-directory" && document.Files.All(file => file.Code is null);
        TypeCountText.Text = structureOnly ? "—" : document.Summary.TypeCount.ToString("N0");
        MethodCountText.Text = structureOnly ? "—" : document.Summary.MethodCount.ToString("N0");
        WarningCountText.Text = document.Warnings.Count.ToString("N0");
        ResultStats.IsVisible = true;
        SummaryText.Text = document.ProjectGraph.Components.Count > 0
            ? $"共 {document.ProjectGraph.Components.Count:N0} 個專案／組件、{document.ProjectGraph.References.Count:N0} 筆參照，請閱讀報告查看總覽。"
            : result.Skeletons.Count > 0
            ? $"已產生 {string.Join("、", result.Skeletons.Select(item => item.Language))} 程式骨架。"
            : "這次未產生程式骨架，可先查看分析資料。";
        SummaryText.IsVisible = true;
        WarningsList.ItemsSource = document.Warnings.Take(100).ToArray();
        WarningsMoreText.IsVisible = document.Warnings.Count > 100;
        WarningsExpander.IsVisible = hasWarnings;
        WarningsExpander.Header = $"查看 {document.Warnings.Count:N0} 項注意事項";
        ResultLocationText.Text = result.OutputDirectory;
        ResultLocationPanel.IsVisible = true;
        AnalyzeButton.Content = "再次分析";
    }

    private void SetStatus(string badge, string title, string detail, bool warning = false, bool success = false)
    {
        StatusBadgeText.Text = badge;
        StatusTitleText.Text = title;
        StatusDetailText.Text = detail;
        StatusBadge.Background = new SolidColorBrush(Color.Parse(warning ? "#FFF0D8" : success ? "#E5F4EC" : "#EEF2FF"));
        StatusBadgeText.Foreground = new SolidColorBrush(Color.Parse(warning ? "#80510D" : success ? "#236444" : "#3455C5"));
    }

    private static string? NormalizePathInput(string? value)
    {
        var path = value?.Trim();
        if (path is { Length: >= 2 } && path[0] == '"' && path[^1] == '"')
        {
            path = path[1..^1];
        }

        return string.IsNullOrWhiteSpace(path) ? null : path;
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        base.OnClosing(e);
        if (e.Cancel || _analysisCancellation is null)
        {
            return;
        }

        e.Cancel = true;
        _closeAfterAnalysis = true;
        RequestCancellation();
        StatusDetailText.Text = "正在停止分析，清理完成後會自動關閉視窗。";
    }
}
