# ExeBlueprint

ExeBlueprint 用來整理 Windows 應用程式套件。它會掃描 EXE、DLL、設定檔和資源，產生可供後續重建使用的 `blueprint.json`，另外附上一份方便閱讀的 `REPORT.md`。

目前版本只做靜態分析，不會執行輸入程式。

## 下載

不想安裝 .NET SDK，可以直接到 [GitHub Releases](https://github.com/NickYCLin/exe-blueprint/releases/latest) 下載 Windows 64 位元自包含版本：

- `exe-blueprint-v0.1.0-win-x64.exe`：可直接執行的單檔版。
- `exe-blueprint-v0.1.0-win-x64.zip`：方便下載與保存的壓縮版。
- `SHA256SUMS.txt`：用來核對下載檔是否完整。

目前執行檔尚未做程式碼簽章，Windows 可能顯示 SmartScreen 提醒。請只從本專案的 Releases 下載，並核對 SHA-256。

## 目前能做什麼

- 分析單一檔案、完整資料夾或 ZIP
- 計算每個檔案的 SHA-256
- 讀取 PE 架構、子系統、section 與簽章資料
- 分辨 .NET assembly 與原生 PE
- 讀取 PE imports 與 .NET assembly references
- 讀出 .NET assembly 的命名空間、型別、巢狀宣告關係、ref-like 旗標、欄位、屬性、事件、方法簽章、virtual／override／sealed dispatch 旗標、enum 常值與繼承關係
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

## 下載現成版本（不用裝 SDK）

到 [Releases](https://github.com/NickYCLin/exe-blueprint/releases) 下載 `...-win-x64.zip`，
全部解壓縮到同一個資料夾後，**雙擊 `run.bat`**，或把要分析的 EXE／DLL／資料夾／ZIP **拖到 `run.bat` 上**。

這是命令列工具、不是安裝程式，**不要直接雙擊 exe**（會閃一下就關）。想自己打指令就用 PowerShell：

```powershell
.\exe-blueprint.exe analyze .\你的程式.exe -o .\report
```

從網路下載的未簽章 exe 若被 Windows 擋（SmartScreen／封鎖／防毒隔離），
解法都寫在 zip 內的 `README.txt`。

## 從原始碼執行

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
- .NET 型別、欄位、屬性、事件、方法簽章、方法層級呼叫圖與各方法反組譯出的 IL
- 語言、框架和工具鏈判斷
- 套件內與外部相依關係
- 分析警告

`REPORT.md` 適合直接閱讀，用來快速確認入口程式、架構、相依套件、程式碼結構和辨識結果。

## 接下來要做的功能

- 解開 Inno Setup、NSIS、MSI、PyInstaller 與 Electron 套件
- 深化原生 PE 分析：把 Ghidra 的函式進一步還原成呼叫圖與程式碼（目前先列出函式清單）
- 擴充中介模型，補上 UI、資源和設定（函式、型別、欄位、屬性、事件、呼叫圖已完成 .NET 部分）
- 補齊例外處理與型別引用，讓骨架能直接編譯成多專案 solution（目前會產生 `.slnx` 與套件內的 `ProjectReference`，已保留完整命名空間、泛型巢狀型別、ref struct 及欄位／屬性／事件修飾詞，能區分 virtual、override、sealed override 與 final 介面實作，並還原 if／if-else、while／do-while、標準 switch、try/catch、含混合巢狀短路條件的 catch filter、try/finally、以 catch/rethrow 等價表示的 fault、複合 try/catch/finally、terminal try、indexer、參考型別 null 分支、bool／char／enum 呼叫常值、enum 位元運算與 switch case、enum 成員常值與區域變數型別）
- 優先支援易語言、VB6、Delphi 到 C# 的轉換
- 讓 C++／Rust／Go 產生器也還原方法體、支援易語言（目前這三個語言只還原結構）
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
