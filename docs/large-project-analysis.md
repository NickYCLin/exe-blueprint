# 大型系統與原始碼專案分析

大型系統可先做結構盤點，再挑選組件深入分析。盤點最多同時處理四個檔案，結果仍依路徑排序；深入 IL 分析維持逐檔執行。原始碼與編譯後的系統共用 `projectGraph` 總覽，但各自保留證據來源：專案描述檔的宣告、PE／.NET 組件的 metadata，兩者不會只憑檔名就認定是同一份程式。

## 開始盤點

```powershell
# 多專案原始碼目錄：略過 bin、obj、版本控制與已安裝套件
dotnet run --project ./src/ExeBlueprint.Cli -- analyze D:/code/MySystem --source --inventory -o ./artifacts/source-overview

# 另外用 Roslyn 建立 C# 宣告與跨專案呼叫索引；--source-code 會自動啟用 --source
dotnet run --project ./src/ExeBlueprint.Cli -- analyze D:/code/MySystem/MySystem.slnx --inventory --source-code -o ./artifacts/source-code-overview

# 也可選擇 .sln、.slnx、.csproj、.vbproj、.fsproj 或 .vcxproj
dotnet run --project ./src/ExeBlueprint.Cli -- analyze D:/code/MySystem/MySystem.slnx --inventory -o ./artifacts/solution-overview

# 編譯後的系統：保留 bin 等目錄，盤點所有組件
dotnet run --project ./src/ExeBlueprint.Cli -- analyze D:/deploy/MySystem --inventory -o ./artifacts/binary-overview

# 看完總覽後，深入分析選定的 .NET 組件
dotnet run --project ./src/ExeBlueprint.Cli -- analyze D:/deploy/MySystem/App.dll --emit-csharp -o ./artifacts/app-detail
```

桌面版可勾選「先盤點大型系統的專案與組件」；需要 C# 宣告與呼叫時另勾選「建立 C# 宣告與跨專案呼叫索引」。選擇方案／專案描述檔會自動以原始碼模式掃描其所在資料夾，包括該資料夾內的其他專案，不會追讀根目錄之外的參照。

![桌面版的大型專案盤點選項](images/large-project-inventory.png)

原始碼目錄會略過 `.git`、`.svn`、`.hg`、`.vs`、`.idea`、`bin`、`obj`、`node_modules`、`.venv`、`venv`、`artifacts` 與 `exe-blueprint-output`，報告會記錄略過路徑。一般編譯後目錄不套用此清單；本次輸出子目錄則一律略過，避免把上次報告當成輸入。

## 會得到什麼

- 方案與子專案清單，以及專案或最近一層 `Directory.Build.props` 宣告的目標框架、輸出類型及 assembly 名稱。
- 方案包含的專案、`ProjectReference` 及 `PackageReference` 宣告；若能證明中央套件管理已啟用，會從最近一層 `Directory.Packages.props` 補上無條件的純文字版本與來源。
- 編譯後的 managed assembly／native binary 節點，以及原有組件與 PE import 相依關係。
- 掃描完成後的檔案總數、分析中的已完成檔數與目前檔案；掃描與分析均可取消。
- 摘要報告與完整 JSON；報告會限制顯示筆數，避免數千檔案淹沒總覽。

`analysisMode=inventory` 表示未讀取 IL、內嵌資源或啟動 Ghidra，也不產生骨架。此時型別與方法計數不代表實際規模；桌面會顯示「—」，JSON 消費端應先看分析模式。

## 如何判斷參照

schema `0.22` 的 `projectGraph.components` 保存節點，`references` 保存帶有來源與類型的參照；中央套件版本另以 `versionSource` 指出來源 props 檔：

| status | 意義 |
| --- | --- |
| `resolved` | 已在輸入內找到對應項目；原始碼路徑只是宣告連結，不代表 MSBuild 已求值 |
| `missing` | 可讀取的相對專案路徑，在輸入內找不到 |
| `ambiguous` | 路徑大小寫等條件有多個候選，沒有擅自挑選 |
| `conditional` | 有 Condition、Choose 或 Target 等條件，未判定是否生效 |
| `unevaluated` | 有變數、萬用字元、中央版本、根目錄外路徑等未求值資訊 |
| `external` | 套件或組件相依不在輸入內；不代表已安裝或已還原 |

解析不執行 MSBuild、`Target`、NuGet restore 或輸入程式，不載入外部 XML entity。`Directory.Build.props` 與 `Directory.Packages.props` 只會在目前工作區內向上尋找最近一份，採用無條件、無變數、無萬用字元的純文字宣告；專案本身的宣告優先。SDK、自訂 `Import`、`Choose`、條件、運算式與 props 的遞迴匯入仍不展開，也尚未精確比對原始碼與建置產物。

## C# 宣告與呼叫索引

`--source-code` 是選配的 Roslyn 分析，可和 `--inventory` 一起使用；啟用時也會自動使用原始碼目錄模式。它目前只處理能靜態確認來源歸屬的 SDK-style `.csproj`：預設 Compile 項目歸給最近一層專案目錄，並套用無條件、純文字的 `Compile Include`／`Remove`。同目錄多專案、自訂 `Import`、`Choose`、`Target`、條件式 Compile、Exclude、變數或萬用字元會把該專案標成不完整，不會猜測實際建置輸入。

`sourceCode.declarations` 保存型別與方法的專案、檔案、行號及 Roslyn 符號 ID；`sourceCode.calls` 保存 invocation、物件建立與 constructor initializer，狀態分成 `resolved-source`、`external`、`ambiguous`、`unresolved`。跨專案只沿 `projectGraph` 中已解析的 `ProjectReference` 建立 compilation reference。分析器不讀取工作區外的 NuGet cache、不執行 restore，外部套件型別可能因此無法解析；framework 符號則使用執行分析器的 .NET shared framework，不保證與目標 TFM 完全一致。每個專案的 `complete`、`errorCount`、`errorCodes` 和 `notes` 用來判斷結果可信範圍。

若專案或最近一層 `Directory.Build.props` 的 Compile 規則無法靜態確認，或工作區內存在會套用到專案的 `Directory.Build.targets`，該專案會標成不完整並略過語意索引，不會猜測實際參與建置的來源檔。遇到 `#if` 等條件式編譯指示也會標成不完整，因為目前不求值 `DefineConstants`，索引只反映預設符號分支。非基礎 `Microsoft.NET.Sdk` 的 SDK 特有來源、`Using` 項目、Analyzer 與 source generator 也不會執行，結果會保留相應註記。

語意索引最多處理 256 個 C# 專案、10,000 個來源檔、合計 32 MiB 來源檔、2,000,000 個語法節點／token、100,000 筆宣告、100,000 筆呼叫與 32 Mi 個符號字元；單一專案檔與來源檔各以 1 MiB 為上限。達限時會設定 `sourceCode.truncated=true`。

## 上限與驗收範圍

輸入仍受 25,000 個檔案、總計 20 GiB、單檔 4 GiB 等既有限制保護，不會為了大型輸入移除防護。單一專案描述檔最多 1 MiB／4,096 個 XML 節點；專案圖最多解析 4,096 個原始碼描述檔，保留 100,000 筆參照及 8,388,608 個 UTF-16 參照文字單位。達到專案圖總量限制會標示 `projectGraph.truncated=true`，單檔限制或格式問題保留在節點 `notes`。

測試涵蓋多專案方案、跨資料夾參照、舊版 MSBuild namespace、條件與缺失參照、DTD／路徑邊界、取消、原始碼目錄排除、編譯後組件盤點及輸出目錄排除。規模測試與實際客戶大型系統的驗收需分開看；結構盤點通過不代表所有組件的完整 IL 還原都可在同樣記憶體與時間內完成。

Windows 可用下列腳本建立 1,000 個串接參照的專案、11,001 個來源檔案，並以自行產生的 DLL 複製出 1,000 個部署組件。腳本驗證檔案數與參照圖，記錄 CLI 耗時、取樣取得的記憶體峰值與輸出大小；測試資料及結果只寫入指定的新目錄，不清除現有資料。

```powershell
dotnet build ExeBlueprint.slnx -c Release
./scripts/Test-LargeProjectAnalysis.ps1 -OutputDirectory ./artifacts/large-project-run -FixtureAssembly ./path/to/owned-fixture.dll
```

這是合成資料的規模驗收：原始碼沒有做語意分析，編譯後案例是同一個測試 DLL 的多份部署副本，不等同 1,000 個不同且複雜的實際組件。

2026-09-09 在 Windows、20 個邏輯處理器的開發環境量測到以下結果。時間含 CLI 啟動、掃描、分析與報告輸出，不含測試資料建立；記憶體是程序的取樣峰值 working set，不是只計 .NET heap。這是單次觀察，不是效能保證。

| 案例 | 檔案數 | 圖節點／參照 | 耗時 | 記憶體峰值 | 報告／JSON |
| --- | ---: | --- | ---: | ---: | --- |
| 1,000 個串接專案 | 11,001 | 1,001／1,999 | 24.5 秒 | 92.4 MiB | 96.6 KiB／10.2 MiB |
| 1,000 份測試 DLL 部署 | 1,000 | 1,000／2,000 | 3.5 秒 | 69.2 MiB | 161.6 KiB／2.3 MiB |
