using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

internal static class TechnologyDetector
{
    public static IReadOnlyList<TechnologyDetection> DetectFile(
        string relativePath,
        PeAnalysis? pe,
        BinarySignalReader signals)
    {
        var detections = new List<TechnologyDetection>();
        var imports = pe?.ImportedModules ?? [];
        var references = pe?.ManagedReferences ?? [];
        var sections = pe?.Sections ?? [];
        var extension = Path.GetExtension(relativePath);
        var isNativePe = pe is { IsManaged: false };
        var isDotNetBundle = isNativePe && signals.IsDotNetSingleFileBundle();
        var inspectNativeToolchainSignals = isNativePe && !isDotNetBundle;

        if (isDotNetBundle)
        {
            Add(detections, "dotnet-single-file", ".NET single-file", "runtime", 1.00, "找到 .NET bundle marker 與有效 header offset");
        }

        if (pe?.IsManaged == true)
        {
            Add(detections, "dotnet", ".NET", "runtime", 1.00, $"{relativePath} 含有 CLR metadata");

            if (references.Contains("PresentationFramework", StringComparer.OrdinalIgnoreCase))
            {
                Add(detections, "wpf", "WPF", "framework", 0.99, "參考 PresentationFramework");
            }

            if (references.Contains("System.Windows.Forms", StringComparer.OrdinalIgnoreCase))
            {
                Add(detections, "winforms", "Windows Forms", "framework", 0.99, "參考 System.Windows.Forms");
            }

            if (references.Any(reference => reference.StartsWith("Avalonia", StringComparison.OrdinalIgnoreCase)))
            {
                Add(detections, "avalonia", "Avalonia", "framework", 0.98, "含有 Avalonia assembly reference");
            }

            if (references.Any(reference => reference.StartsWith("UnityEngine", StringComparison.OrdinalIgnoreCase)))
            {
                Add(detections, "unity-mono", "Unity Mono", "framework", 0.97, "含有 UnityEngine assembly reference");
            }
        }

        if (imports.Contains("msvbvm60.dll", StringComparer.OrdinalIgnoreCase))
        {
            Add(detections, "vb6", "Visual Basic 6", "language", 0.99, "匯入 MSVBVM60.DLL");
        }

        if (imports.Any(name => name.StartsWith("python", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
        {
            Add(detections, "python", "Python runtime", "runtime", 0.97, "匯入 Python runtime DLL");
        }

        if (inspectNativeToolchainSignals && (signals.Contains("PyInstaller") || signals.Contains("pyi-windows-manifest-filename")))
        {
            Add(detections, "pyinstaller", "PyInstaller", "packager", 0.94, "找到 PyInstaller bootloader 特徵");
        }

        if (inspectNativeToolchainSignals && (signals.Contains("Go build ID:") || sections.Contains(".gopclntab", StringComparer.OrdinalIgnoreCase)))
        {
            Add(detections, "go", "Go", "language", 0.96, "找到 Go build metadata");
        }

        if (inspectNativeToolchainSignals && (signals.Contains("rust_begin_unwind") || signals.Contains("rust_eh_personality")))
        {
            Add(detections, "rust", "Rust", "language", 0.82, "找到 Rust runtime symbol");
        }

        if (inspectNativeToolchainSignals && imports.Any(IsQtModule))
        {
            Add(detections, "qt", "Qt", "framework", 0.98, "匯入 Qt runtime module");
        }

        if (inspectNativeToolchainSignals && imports.Any(name => name.Equals("WebView2Loader.dll", StringComparison.OrdinalIgnoreCase)) &&
            signals.Contains("__TAURI__"))
        {
            Add(detections, "tauri", "Tauri", "framework", 0.85, "同時找到 WebView2 與 Tauri 特徵");
        }

        if (inspectNativeToolchainSignals && (imports.Any(name =>
                name.StartsWith("vcl", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("rtl", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".bpl", StringComparison.OrdinalIgnoreCase)) ||
            signals.Contains("Embarcadero Delphi") ||
            extension.Equals(".dfm", StringComparison.OrdinalIgnoreCase)))
        {
            Add(detections, "delphi", "Delphi／C++Builder", "toolchain", 0.86, "找到 VCL、BPL 或 Embarcadero 特徵");
        }

        if (inspectNativeToolchainSignals && imports.Any(name =>
                name.StartsWith("vcruntime", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("msvcp", StringComparison.OrdinalIgnoreCase)))
        {
            Add(detections, "msvc", "Microsoft Visual C++", "toolchain", 0.90, "匯入 MSVC runtime");
        }

        if (inspectNativeToolchainSignals && (imports.Any(name => name.Equals("krnln.fnr", StringComparison.OrdinalIgnoreCase)) ||
            signals.Contains("krnln.fnr")))
        {
            Add(detections, "easy-language", "易語言", "language", 0.99, "找到 krnln.fnr runtime 特徵");
        }
        else if (inspectNativeToolchainSignals && signals.Contains("lpEWindow"))
        {
            Add(detections, "easy-language", "易語言", "language", 0.74, "找到易語言視窗資料特徵");
        }

        if (inspectNativeToolchainSignals && pe?.IsExecutable == true &&
            (signals.Contains("Inno Setup Setup Data") || signals.Contains("Inno Setup")))
        {
            Add(detections, "inno-setup", "Inno Setup", "installer", 0.97, "找到 Inno Setup 資料特徵");
        }

        if (inspectNativeToolchainSignals && pe?.IsExecutable == true &&
            (signals.Contains("Nullsoft.NSIS") || signals.Contains("Nullsoft Install System")))
        {
            Add(detections, "nsis", "NSIS", "installer", 0.97, "找到 NSIS 資料特徵");
        }

        return Merge(detections);
    }

    public static IReadOnlyList<TechnologyDetection> DetectPackage(IReadOnlyList<FileArtifact> files)
    {
        var detections = files.SelectMany(file => file.Technologies).ToList();
        var paths = files.Select(file => file.RelativePath).ToArray();
        var names = files.Select(file => file.FileName).ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (files.Any(file => file.Format == "ASAR archive") ||
            paths.Any(path => path.EndsWith("resources/app.asar", StringComparison.OrdinalIgnoreCase)) ||
            names.Contains("electron.exe"))
        {
            Add(detections, "electron", "Electron", "framework", 0.99, "應用程式套件含有 Electron 的 app.asar 或 electron.exe");
        }

        if (names.Contains("UnityPlayer.dll") && paths.Any(path => path.Contains("_Data/", StringComparison.OrdinalIgnoreCase)))
        {
            Add(detections, "unity", "Unity", "framework", 0.99, "同時找到 UnityPlayer.dll 與 Unity Data 目錄");
        }

        if (names.Any(name => name.StartsWith("python", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) ||
            names.Contains("base_library.zip"))
        {
            Add(detections, "python", "Python runtime", "runtime", 0.96, "套件含有 Python runtime 或 base_library.zip");
        }

        if (names.Contains("jvm.dll") || files.Any(file => file.Format == "Java archive"))
        {
            Add(detections, "jvm", "Java／JVM", "runtime", 0.92, "套件含有 JVM 或 JAR");
        }

        if (names.Contains("krnln.fnr") || files.Any(file => IsEasyLanguageExtension(Path.GetExtension(file.FileName))))
        {
            Add(detections, "easy-language", "易語言", "language", 0.99, "套件含有易語言工程或支持庫檔案");
        }

        if (names.Any(name => name.Equals("WebView2Loader.dll", StringComparison.OrdinalIgnoreCase)) &&
            files.Any(file => file.Technologies.Any(item => item.Id == "tauri")))
        {
            Add(detections, "tauri", "Tauri", "framework", 0.92, "套件與執行檔特徵均符合 Tauri");
        }

        return Merge(detections);
    }

    private static bool IsQtModule(string name) =>
        name.StartsWith("Qt5", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Qt6", StringComparison.OrdinalIgnoreCase);

    private static bool IsEasyLanguageExtension(string extension) =>
        extension.Equals(".fne", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".fnr", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".fnl", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".ec", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".e", StringComparison.OrdinalIgnoreCase);

    private static void Add(
        ICollection<TechnologyDetection> detections,
        string id,
        string name,
        string category,
        double confidence,
        string evidence)
    {
        detections.Add(new TechnologyDetection
        {
            Id = id,
            Name = name,
            Category = category,
            Confidence = confidence,
            Evidence = [evidence]
        });
    }

    private static IReadOnlyList<TechnologyDetection> Merge(IEnumerable<TechnologyDetection> detections) =>
        detections
            .GroupBy(item => item.Id, StringComparer.OrdinalIgnoreCase)
            .Select(group => new TechnologyDetection
            {
                Id = group.Key,
                Name = group.OrderByDescending(item => item.Confidence).First().Name,
                Category = group.OrderByDescending(item => item.Confidence).First().Category,
                Confidence = group.Max(item => item.Confidence),
                Evidence = group.SelectMany(item => item.Evidence)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase)
                    .ToArray()
            })
            .OrderByDescending(item => item.Confidence)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
}
