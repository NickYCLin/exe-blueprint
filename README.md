# ExeBlueprint

[繁體中文](README.md)｜[English](README.en.md)

[![CI](https://github.com/NickYCLin/exe-blueprint/actions/workflows/ci.yml/badge.svg)](https://github.com/NickYCLin/exe-blueprint/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/NickYCLin/exe-blueprint)](https://github.com/NickYCLin/exe-blueprint/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ExeBlueprint 是跨平台的 Windows EXE、DLL 與應用程式套件靜態分析工具。它會整理 PE、.NET metadata、IL、相依關係與內嵌資源，產生可供盤點、重建或後續自動化處理的 `blueprint.json`，另外附上一份方便閱讀的 `REPORT.md`。

現在有圖形介面可直接選擇或拖放檔案與資料夾，也能指定輸出位置並重選最近分析成功的來源；桌面版支援 Windows、macOS 與 Linux，原本的命令列工具也會繼續提供。

目前版本只做靜態分析，不會執行輸入程式。

## 適合什麼情境

- 想先盤點陌生或老舊的 Windows 應用程式，不希望直接執行來源不明的 EXE
- 要查 PE imports、.NET assembly references、框架、資源與套件內相依關係
- 在系統移轉或軟體考古前，先整理 .NET 型別、IL、呼叫圖與 WPF BAML 結構
- 要把分析結果交給腳本、CI 或大型語言模型接著比對、分類與規劃重建工作
- 需要 JSON 資料做後續工具鏈輸入，也需要 Markdown 報告供工程師快速閱讀

ExeBlueprint 不是動態沙箱，也不是能完整還原所有原始碼的反編譯器。原生程式的函式分析可選配 Ghidra；目前較完整的程式結構還原集中在 .NET assembly。

## 下載

不想安裝 .NET SDK，可以直接到 [GitHub Releases](https://github.com/NickYCLin/exe-blueprint/releases/latest) 下載自包含版本：

- `ExeBlueprint-v0.2.1-win-x64.zip`：Windows 10／11 64 位元，解壓縮後雙擊 `ExeBlueprint.exe`。
- `ExeBlueprint-v0.2.1-macos-arm64.zip`：Apple Silicon Mac。
- `ExeBlueprint-v0.2.1-macos-x64.zip`：Intel Mac。
- `ExeBlueprint-v0.2.1-linux-x64.tar.gz`：Intel／AMD 64 位元 Linux 桌面版。
- `SHA256SUMS.txt`：用來核對下載檔是否完整。

每個套件也附上 `exe-blueprint-cli` 命令列版本。Windows 及 macOS 產物目前尚未做商業程式碼簽章，macOS 也未經 Apple 公證；第一次開啟的方式與 Linux 相依套件都寫在壓縮檔內的 `README.txt`。請只從本專案 Releases 下載，並核對 SHA-256。

## 目前能做什麼

- 分析單一檔案、完整資料夾或 ZIP
- 計算每個檔案的 SHA-256
- 讀取 PE 架構、子系統、section 與簽章資料
- 分辨 .NET assembly 與原生 PE
- 讀取 PE imports 與 .NET assembly references
- 讀出 .NET assembly 的命名空間、型別、巢狀宣告關係、ref-like 旗標、欄位、屬性、事件、方法簽章、virtual／override／sealed dispatch 旗標、enum 常值與繼承關係
- 列出 .NET assembly 的內嵌 manifest 資源（.resources、WPF BAML、內嵌設定檔或組件），標出用途、位置與大小；`.resources` 會再列出鍵名、型別及可安全解碼的標準值，`.baml` 會整理檔頭版本、record 類型數量、element／property 使用次數，以及檔案內宣告與 WPF 內建的型別／屬性 ID 對照
- 掃描 IL 建立方法層級呼叫圖，看得出程式流程怎麼串
- 把每個方法的 IL 反組譯成可讀指令（呼叫、字串、分支目標都解析出來）
- 用堆疊模擬把方法 IL 還原成 C# 陳述式，把條件分支還原成 if／if-else，迴圈還原成 while／do-while（可巢狀），並還原標準 try/catch、含混合巢狀 `&&`／`||` 短路條件的 catch filter、try/finally、fault 與複合 try/catch/finally，也支援保護區直接拋出例外的 terminal try
- 能把標準 IL 跳表還原成 switch，支援 case 直接 return／throw，或指派區域變數後回到共用流程
- 把 .NET 型別轉出一份 C# 骨架，能還原的方法直接給程式碼，其餘附上原始 IL
- 另外可轉出 C++／Rust／Go 的型別與方法簽章骨架（結構為主，方法體留空）
- 選配用 Ghidra headless 分析原生 PE，列出函式（沒裝 Ghidra 會自動略過並加註記）
- 找出套件內可以對上的 EXE／DLL 相依關係
- 依檔案內容辨識常見語言、runtime、框架與安裝器
- 輸出 JSON 與繁體中文 Markdown 報告
- 安全解開 ZIP，阻擋路徑穿越和符號連結

目前已有以下辨識規則：

- .NET、WPF、Windows Forms、Avalonia
- Visual Basic 6、Delphi／C++Builder、Microsoft Visual C++
- Go、Rust、Python、PyInstaller、Java／JVM
- 易語言 runtime 與支持庫檔案
- Qt、Tauri、Electron、Unity
- Inno Setup、NSIS

辨識結果會附上依據與可信度。看到某個語言名稱，不代表已經證明原始碼就是用該語言撰寫。

## 從原始碼執行

需要 [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)。

啟動桌面版：

```powershell
dotnet run --project .\src\ExeBlueprint.Desktop
```

命令列版本：

```powershell
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\MyApplication
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\MyApplication.zip
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\App.exe -o .\report
```

不指定輸出目錄時，結果會放在：

```text
exe-blueprint-output/<輸入名稱>-<時間>/
├─ blueprint.json
└─ REPORT.md
```

如果只需要 JSON：

```powershell
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\App.exe --json-only
```

要順便把 .NET 型別轉出骨架，加上對應的 `--emit-*`（可同時多個）：

```powershell
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\App.exe --emit-csharp --emit-rust --emit-go --emit-cpp
```

各語言會分別放在輸出目錄的 `reconstructed-csharp/`、`reconstructed-cpp/`、`reconstructed-rust/`、`reconstructed-go/`。
C# 會還原方法體：能結構化的方法用堆疊模擬還原成 C# 陳述式（含 if／if-else、while／do-while、switch、try/catch、含混合巢狀短路條件的 catch filter、try/finally、fault、複合 try/catch/finally 與 terminal try），
還原不了的把原始 IL 放進註解、方法體先用 `NotImplementedException`。
C++／Rust／Go 目前只還原型別與方法簽章（結構），方法體留空。全部僅供對照或轉語言起點，不保證能直接編譯。

要分析原生 PE（C/C++、Delphi、Go、Rust 等沒有 .NET metadata 的程式）的函式，加上 `--native`
（需先安裝 [Ghidra](https://ghidra-sre.org/) 並設定 `GHIDRA_INSTALL_DIR`，或用 `--ghidra <目錄>` 指定）：

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.0"
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\Native.exe --native
```

沒偵測到 Ghidra 時不會失敗，只會在報告與警告裡註記略過了原生分析。

輸出目錄已有報告時，程式預設不會覆寫。確定要覆寫可加上 `--force`。

## 自行發佈

```powershell
dotnet publish .\src\ExeBlueprint.Desktop -c Release -r win-x64 --self-contained true
dotnet publish .\src\ExeBlueprint.Cli -c Release -r win-x64 --self-contained true
```

`-r` 可改成 `linux-x64`、`osx-x64` 或 `osx-arm64`。正式 Release 會另外把 macOS 產物整理成 `.app`。

```text
src/ExeBlueprint.Desktop/bin/Release/net10.0/win-x64/publish/ExeBlueprint.exe
```

## 報告內容

`blueprint.json` 是後續專案重建和轉語言要共用的資料格式，內容包含：

- 輸入套件摘要
- 每個檔案的格式與雜湊
- PE 與 .NET metadata
- .NET 型別、欄位、屬性、事件、方法簽章、方法層級呼叫圖與各方法反組譯出的 IL
- 語言、框架和工具鏈判斷
- 套件內與外部相依關係
- 分析警告

`REPORT.md` 適合直接閱讀，用來快速確認入口程式、架構、相依套件、程式碼結構和辨識結果。

## 接下來要做的功能

- 解開 Inno Setup、NSIS、MSI、PyInstaller 與 Electron 套件
- 深化原生 PE 分析：把 Ghidra 的函式進一步還原成呼叫圖與程式碼（目前先列出函式清單）
- 擴充中介模型，補上 UI 與設定（函式、型別、欄位、屬性、事件、呼叫圖、內嵌 manifest 資源清單、`.resources` 標準鍵值，以及 WPF BAML record、檔內與內建型別／屬性 ID 對照已完成 .NET 部分；接著要解析 BAML 屬性值與自訂資源型別）
- 補齊例外處理與型別引用，讓骨架能直接編譯成多專案 solution（目前會產生 `.slnx` 與套件內的 `ProjectReference`，class 與具 instance constructor 的 struct skeleton 成員會有 `default!` initializer，已保留完整命名空間、泛型巢狀型別、ref struct、方法與運算式的 nullable 語意及欄位／屬性／事件修飾詞，能區分 virtual、override、sealed override 與 final 介面實作，並還原 if／if-else、while／do-while、標準 switch、try/catch、含混合巢狀短路條件的 catch filter、try/finally、以 catch/rethrow 等價表示的 fault、複合 try/catch/finally、terminal try、indexer、參考型別 null 分支、bool／char／enum 呼叫常值、enum 位元運算與 switch case、enum 成員常值與區域變數型別）
- 優先支援易語言、VB6、Delphi 到 C# 的轉換
- 讓 C++／Rust／Go 產生器也還原方法體、支援易語言（目前這三個語言只還原結構）
- 比較原程式與重建版本的輸入、輸出和副作用
- 補上桌面版安裝程式（拖放輸入與最近使用項目已完成）

這些項目尚未完成，詳細分層可看 [架構說明](docs/architecture.md)。

## 安全與公開資料

- 只分析自己擁有或已獲授權的程式。
- 輸入檔預設放在 repo 外，`inputs/` 和常見 Windows binary 已加入 `.gitignore`。
- 不要提交客戶程式、反編譯結果、帳密、token、私有網址、資料庫或內部設定。
- 未來如需動態分析，會放在隔離環境，不會直接在日常工作環境執行不明程式。

## 開發

```powershell
dotnet restore .\ExeBlueprint.slnx
dotnet build .\ExeBlueprint.slnx -c Release
dotnet test .\ExeBlueprint.slnx -c Release
```

Commit message 採用：

```text
<type>(<scope>): <繁體中文主旨>
```

主旨不超過 50 個字，內文說明異動原因與內容。完整規則請看 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 授權

本專案採用 [MIT License](LICENSE)。
