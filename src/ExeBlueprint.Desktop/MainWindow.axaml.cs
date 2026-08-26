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
    private readonly BlueprintExportService _exportService = new();
    private readonly RecentInputStore _recentInputStore = RecentInputStore.CreateDefault();
    private readonly List<string> _recentInputPaths = [];
    private CancellationTokenSource? _analysisCancellation;
    private string? _lastOutputDirectory;
    private bool _settingSuggestedOutput;
    private bool _outputWasEdited;
    private bool _inputDropZoneActive;

    public MainWindow()
    {
        InitializeComponent();
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.2.0";
        VersionText.Text = $"桌面版 {version}";
        DragDrop.SetAllowDrop(InputDropZone, true);
        DragDrop.AddDragEnterHandler(InputDropZone, OnInputDragEnter);
        DragDrop.AddDragLeaveHandler(InputDropZone, OnInputDragLeave);
        DragDrop.AddDragOverHandler(InputDropZone, OnInputDragOver);
        DragDrop.AddDropHandler(InputDropZone, OnInputDrop);
        LoadRecentInputs();
        OutputPathBox.TextChanged += (_, _) =>
        {
            if (!_settingSuggestedOutput)
            {
                _outputWasEdited = !string.IsNullOrWhiteSpace(OutputPathBox.Text);
            }
        };
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
                Title = "選擇要分析的程式或壓縮檔",
                AllowMultiple = false,
                FileTypeFilter =
                [
                    new FilePickerFileType("程式與壓縮檔") { Patterns = ["*.exe", "*.dll", "*.zip"] },
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
        StatusTitleText.Text = "已選擇最近使用項目";
        StatusDetailText.Text = path;
        SummaryText.IsVisible = false;
        RecentInputComboBox.SelectedIndex = -1;
    }

    private void OnClearRecentInputs(object? sender, RoutedEventArgs e)
    {
        try
        {
            _recentInputStore.Save([]);
            _recentInputPaths.Clear();
            RefreshRecentInputs();
            StatusTitleText.Text = "已清除最近使用項目";
            StatusDetailText.Text = "之後完成分析的來源會重新出現在這裡。";
            SummaryText.IsVisible = false;
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
        StatusTitleText.Text = "已選擇分析來源";
        StatusDetailText.Text = selection.Path;
        SummaryText.IsVisible = false;
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
        InputDropZone.Background = new SolidColorBrush(Color.Parse(active ? "#EFF6FF" : "#F8FAFC"));
        InputDropZone.BorderBrush = new SolidColorBrush(Color.Parse(active ? "#2563EB" : "#CBD5E1"));
        InputDropTitleText.Foreground = new SolidColorBrush(Color.Parse(active ? "#1D4ED8" : "#334155"));
        InputDropTitleText.Text = active ? "放開即可選擇這個來源" : "把檔案或資料夾拖到這裡";
    }

    private void OnInputPathChanged(object? sender, TextChangedEventArgs e)
    {
        if (_outputWasEdited || string.IsNullOrWhiteSpace(InputPathBox.Text))
        {
            return;
        }

        try
        {
            _settingSuggestedOutput = true;
            OutputPathBox.Text = BlueprintExportService.CreateDefaultOutputDirectory(
                InputPathBox.Text,
                Environment.CurrentDirectory);
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

        var inputPath = InputPathBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            ShowError("請先選擇要分析的檔案、資料夾或 ZIP。");
            return;
        }

        _analysisCancellation = new CancellationTokenSource();
        SetBusy(true);
        StatusTitleText.Text = "正在分析";
        StatusDetailText.Text = "正在準備分析流程…";
        SummaryText.IsVisible = false;
        var progress = new Progress<BlueprintExportProgress>(value => StatusDetailText.Text = value.Message);

        try
        {
            var result = await _exportService.RunAsync(
                new BlueprintExportRequest
                {
                    InputPath = inputPath,
                    OutputDirectory = NullIfWhiteSpace(OutputPathBox.Text),
                    Overwrite = OverwriteCheckBox.IsChecked == true,
                    JsonOnly = ReportCheckBox.IsChecked != true,
                    EmitCSharp = CSharpCheckBox.IsChecked == true,
                    EmitCpp = CppCheckBox.IsChecked == true,
                    EmitRust = RustCheckBox.IsChecked == true,
                    EmitGo = GoCheckBox.IsChecked == true,
                    EnableNativeAnalysis = NativeCheckBox.IsChecked == true,
                    GhidraInstallDir = NullIfWhiteSpace(GhidraPathBox.Text)
                },
                progress,
                _analysisCancellation.Token);

            _lastOutputDirectory = result.OutputDirectory;
            OutputPathBox.Text = result.OutputDirectory;
            StatusTitleText.Text = "分析完成";
            StatusDetailText.Text = result.OutputDirectory;
            SummaryText.Text = BuildSummary(result);
            SummaryText.IsVisible = true;
            OpenOutputButton.IsEnabled = true;
            if (!TryRememberRecentInput(inputPath))
            {
                StatusDetailText.Text += "（未能儲存最近使用紀錄）";
            }
        }
        catch (OperationCanceledException)
        {
            StatusTitleText.Text = "已取消分析";
            StatusDetailText.Text = "已停止目前工作，先前完成的部分檔案可能仍留在輸出目錄。";
        }
        catch (Exception exception) when (exception is ArgumentException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            ShowError(exception.Message);
        }
        finally
        {
            _analysisCancellation.Dispose();
            _analysisCancellation = null;
            SetBusy(false);
        }
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        StatusDetailText.Text = "正在停止，請稍候…";
        _analysisCancellation?.Cancel();
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
        CSharpCheckBox.IsEnabled = !busy;
        CppCheckBox.IsEnabled = !busy;
        RustCheckBox.IsEnabled = !busy;
        GoCheckBox.IsEnabled = !busy;
        OverwriteCheckBox.IsEnabled = !busy;
        NativeCheckBox.IsEnabled = !busy;
        AnalyzeButton.IsEnabled = !busy;
        AnalyzeButton.IsVisible = !busy;
        OpenOutputButton.IsVisible = !busy;
        CancelButton.IsVisible = busy;
        AnalysisProgressBar.IsVisible = busy;
    }

    private void ShowError(string message)
    {
        StatusTitleText.Text = "無法完成分析";
        StatusDetailText.Text = message;
        SummaryText.IsVisible = false;
    }

    private static string BuildSummary(BlueprintExportResult result)
    {
        var document = result.Document;
        var values = new List<string>
        {
            $"檔案 {document.Input.FileCount:N0}",
            $"PE 執行檔 {document.Summary.ExecutableCount:N0}",
            $"程式庫 {document.Summary.LibraryCount:N0}",
            $"型別／方法 {document.Summary.TypeCount:N0}／{document.Summary.MethodCount:N0}"
        };
        if (result.Skeletons.Count > 0)
        {
            values.Add($"骨架 {string.Join("、", result.Skeletons.Select(item => item.Language))}");
        }

        if (document.Warnings.Count > 0)
        {
            values.Add($"警告 {document.Warnings.Count:N0}（請查看報告）");
        }

        return string.Join("　｜　", values);
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        _analysisCancellation?.Cancel();
        base.OnClosing(e);
    }
}
