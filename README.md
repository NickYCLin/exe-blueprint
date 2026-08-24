# ExeBlueprint

ExeBlueprint 用來整理 Windows 應用程式套件。它會掃描 EXE、DLL、設定檔和資源，產生可供後續重建使用的 `blueprint.json`，另外附上一份方便閱讀的 `REPORT.md`。

目前版本只做靜態分析，不會執行輸入程式。

## 目前能做什麼

- 分析單一檔案、完整資料夾或 ZIP
- 計算每個檔案的 SHA-256
- 讀取 PE 架構、子系統、section 與簽章資料
- 分辨 .NET assembly 與原生 PE
- 讀取 PE imports 與 .NET assembly references
- 讀出 .NET assembly 的命名空間、型別、欄位、屬性、方法簽章與繼承關係
- 掃描 IL 建立方法層級呼叫圖，看得出程式流程怎麼串
- 把 .NET 型別轉出一份 C# 骨架，當接手改寫或轉語言的起點
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

## 使用方式

需要 [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)。

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

要順便把 .NET 型別轉出一份 C# 骨架，加上 `--emit-csharp`：

```powershell
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\App.exe --emit-csharp
```

骨架會放在輸出目錄的 `reconstructed-csharp/`，方法體是 `NotImplementedException`，
用來對照結構或當轉語言的起點，不保證能直接編譯。

輸出目錄已有報告時，程式預設不會覆寫。確定要覆寫可加上 `--force`。

## 編譯成 Windows EXE

```powershell
dotnet publish .\src\ExeBlueprint.Cli -c Release -r win-x64 --self-contained true
```

輸出位置：

```text
src/ExeBlueprint.Cli/bin/Release/net10.0/win-x64/publish/exe-blueprint.exe
```

## 報告內容

`blueprint.json` 是後續專案重建和轉語言要共用的資料格式，內容包含：

- 輸入套件摘要
- 每個檔案的格式與雜湊
- PE 與 .NET metadata
- .NET 型別、方法、簽章與方法層級呼叫圖
- 語言、框架和工具鏈判斷
- 套件內與外部相依關係
- 分析警告

`REPORT.md` 適合直接閱讀，用來快速確認入口程式、架構、相依套件、程式碼結構和辨識結果。

## 接下來要做的功能

- 解開 Inno Setup、NSIS、MSI、PyInstaller 與 Electron 套件
- 串接 ILSpy、Ghidra 等分析後端（讓原生 PE 也能還原函式與流程）
- 擴充中介模型，補上 UI、資源和設定（函式、型別、欄位、屬性、呼叫圖已完成 .NET 部分）
- 讓產出的 C# 骨架能還原方法體、直接編譯成多專案 solution
- 優先支援易語言、VB6、Delphi 到 C# 的轉換
- 加入 C++、Rust、Go 和易語言程式碼產生器（C# 骨架已有第一版）
- 比較原程式與重建版本的輸入、輸出和副作用
- 製作可拖放檔案與資料夾的 Windows 桌面介面

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

目前尚未指定開源授權。在授權檔加入 repository 前，請勿把程式碼當成可任意再散布或商用的開源套件。
