# 架構說明

ExeBlueprint 把輸入端、分析流程和輸出端分開。新增一種語言時，不需要改寫整個工具。

```text
檔案／資料夾／ZIP
        ↓
安全匯入與檔案盤點
        ↓
格式、語言與框架辨識
        ↓
PE／.NET／專用分析器
        ↓
Blueprint 中介資料
        ↓
專案重建器
        ↓
目標語言產生器
        ↓
編譯與行為比對
```

## 目前完成

`ExeBlueprint.Core` 已包含輸入盤點、ZIP 安全解壓、檔案分類、PE／.NET 讀取、.NET 型別／欄位／屬性／事件／方法與 enum 常值抽取、方法層級呼叫圖、技術辨識、相依關係、報告產生，以及 .NET 型別的 C# 骨架產生。

`ExeBlueprint.Cli` 提供命令列入口，後續桌面版也會呼叫同一套核心。

## Blueprint 資料

目前 schema 版本是 `0.2`，主要欄位包括：

- `input`：輸入類型、檔案數與總大小
- `summary`：PE、assembly、型別、方法、資源和相依關係數量
- `files`：每個檔案的格式、雜湊和分析資料，受管組件另含 `code`
- `files[].code`：.NET 型別、欄位、屬性、事件、方法簽章、入口點、方法層級呼叫圖與各方法反組譯出的 IL
- `dependencies`：PE imports 與 assembly references
- `technologies`：語言、runtime、框架和工具鏈判斷
- `warnings`：略過或無法分析的項目

後續加入 UI、資源和更細的控制流程時會再提升 schema 版本，舊欄位維持相容。

## 分析器分層

每種輸入會依序經過：

1. 通用檔案格式辨識
2. PE／managed metadata 分析
3. 語言或框架專用分析
4. 套件層級相依關係整理

不認得的 EXE 仍會保留通用 PE 結果，不會因缺少專用分析器而完全失敗。

## 原生 PE 分析（Ghidra）

開啟 `--native` 時，`NativeAnalyzer` 會對原生 PE 呼叫 Ghidra headless（`analyzeHeadless`），
用內建的 `ExportFunctions.py` 後置腳本把函式匯出成 JSON，再由 `GhidraOutputParser` 解析進 `FileArtifact.NativeCode`。
Ghidra 安裝目錄來自 `--ghidra` 或環境變數 `GHIDRA_INSTALL_DIR`。找不到 Ghidra、逾時或執行失敗時不會讓整體分析失敗，
只會把 `Backend` 記成 `none` 並附上註記，同時列入報告警告。原生函式與受管 `code` 分開存放，
所以 C#／C++／Rust／Go 產生器不會誤把原生函式當成 .NET 型別輸出。

## 易語言

易語言分析預計分成動態編譯和靜態編譯兩條路徑：

- 動態編譯：從 `krnln.fnr`、支持庫和 dispatcher 關係整理命令呼叫。
- 靜態編譯：以自建特徵資料辨識支持庫函式、視窗、控件和事件。

現階段只完成 runtime 與套件特徵辨識，還沒有還原 `.e` 工程。

## 專案重建與轉語言

重建器不會直接翻譯零碎的反編譯文字。它會先把函式、型別、呼叫、UI、資源和外部副作用整理成中介資料，再由目標語言產生器輸出專案。

目前已有第一個產生器 `CSharpSkeletonGenerator`，吃 `CodeModel` 輸出 C# 骨架：
還原命名空間、型別、欄位、屬性、事件、方法簽章與繼承，並保留完整型別名稱及成員的可見性、static／virtual 與 readonly 修飾詞。
多個輸入 assembly 會輸出 `Reconstructed.slnx`，套件內可對上的 assembly reference 會轉成 `ProjectReference`。方法體由 `ManagedSymbolReader` 的 IL 還原器重建：
先把 IL 解碼成指令陣列，用區間遞迴結構化把條件分支還原成 if／if-else，比對 Roslyn 的
while／for 形狀（先跳條件、主體、條件、往回跳）還原成 while，並把底測式（往回跳收尾）還原成 do-while（皆可巢狀）；
區塊內以堆疊模擬還原載入、算式、欄位、屬性、方法呼叫、`new`、運算子、`return`、`throw`；
auto-property 的隱藏欄位會還原成屬性名稱，運算子方法還原成運算子語法。
呼叫時若參數型別是 char，整數常值會還原成 char 常值；區域變數會依方法的 local signature 用實際型別宣告。
IL `switch` 跳表可還原直接 return／throw 的分支，也能處理各 case 指派區域變數後回到共同 join 的形狀；這類區域變數會提升到 switch 外並依 IL locals init 語意先設成 default。
標準 `try/catch` 與 `try/finally` 會依 exception region metadata 的保護區域與 handler 邊界還原，不靠跳轉位置猜測；
`catch` 支援多個 handler、未命名 catch-all、具名例外變數與重新拋出。跨區塊的區域變數會提升到 `try` 外並依 IL locals init 語意先設成 default。
filter、fault、catch 與 finally 的複合排列，或非標準例外區域目前仍會退回反組譯 IL 註解加 `NotImplementedException`。
重建採全有或全無：遇到無法結構化的跳轉、參照編譯器產生的名稱或任何不支援的指令，就整個方法放棄，
寧可不還原也不產出語意錯誤的程式碼。enum 會保留底層整數型別與各成員原始數值；
型別引用已保留完整命名空間，但套件外依賴、泛型限制與巢狀型別仍可能需要手動補齊，因此不保證可直接編譯。

另外也有 `CppSkeletonGenerator`、`RustSkeletonGenerator`、`GoSkeletonGenerator`，
共用 `SkeletonSupport` 挑型別與 `LanguageTypeMap` 做基本型別對應，各自輸出該語言的型別與方法簽章骨架
（struct／class／trait／interface／enum），方法體留空。這三個語言目前只還原結構，不翻譯方法內容。

第一批預定的輸出方向：

- .NET assembly → C# project
- 易語言／VB6／Delphi → C# Windows desktop project
- 原生 C／C++ → C-like project skeleton
- Blueprint → C#、C++、Rust

每個輸出項目都會標示 `confirmed`、`inferred` 或 `unknown`，並保留來源證據。
