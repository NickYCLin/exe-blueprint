# 架構說明

ExeBlueprint 把輸入端、分析流程和輸出端分開。新增一種語言時，不需要改寫整個工具。

```text
檔案／資料夾／ZIP／ASAR
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

`ExeBlueprint.Core` 已包含輸入盤點、ZIP 安全解壓、Electron ASAR 與有上限的巢狀 ASAR 展開、檔案分類、PE／.NET 讀取、.NET 型別／欄位／屬性／事件／方法與 enum 常值抽取、方法層級呼叫圖、技術辨識、相依關係、報告產生，以及 .NET 型別的 C# 骨架產生。

`ExeBlueprint.Application.BlueprintExportService` 負責串接分析、JSON、Markdown 與各語言骨架輸出。
`ExeBlueprint.Cli` 和 Avalonia 製作的 `ExeBlueprint.Desktop` 都呼叫這個服務，所以兩種入口的分析結果與覆寫保護一致。

桌面版只放檔案／資料夾選擇與拖放、最近使用項目、選項、進度與狀態，不在 UI 專案裡重做分析器。拖放操作只接受一個本機檔案或資料夾，並沿用既有輸入與輸出路徑邏輯。最近使用項目只在分析成功後記錄，最多保留八筆本機路徑，資料放在作業系統的 Local Application Data。Avalonia 使用同一份 XAML 在 Windows、macOS 與 Linux 顯示，平台差異集中在檔案選擇器與 Release 包裝。

## Blueprint 資料

目前 schema 版本是 `0.8`，主要欄位包括：

- `input`：輸入類型、檔案數與總大小
- `summary`：PE、assembly、型別、方法、資源和相依關係數量
- `files`：每個檔案的格式、雜湊、來源資訊（provenance）和分析資料，受管組件另含 `code`
- `files[].origin`：`direct`、`directory`、`zip` 或 `asar` 來源；需要時保存直接容器、容器內項目與展開深度，讓 staging 實體路徑不會外洩或取代邏輯路徑
- `files[].code`：.NET 型別、巢狀宣告與 ref-like 關係、欄位、含 index parameters 的屬性、事件、方法簽章與 dispatch 旗標、入口點、方法層級呼叫圖、manifest 資源與各方法反組譯出的 IL
- `archives`：每次 ASAR 展開的容器路徑、深度、header 大小、節點與 packed／unpacked／link 數量，以及 `complete`／`error` 狀態
- `dependencies`：PE imports 與 assembly references
- `technologies`：語言、runtime、框架和工具鏈判斷
- `warnings`：略過或無法分析的項目

`.resources` 內的鍵值會放在 manifest 資源的 `entries`。字串、數字、布林、字元、日期與時間可轉成文字；一般位元組陣列和 stream 只記大小，檔名為 `.baml` 時會另外整理 MSBAML 檔頭版本、record 總數、各類型數量、element／property 使用次數，並用 BAML 檔案自行宣告的 assembly、type、attribute、string 對照表解析使用中的 ID。負值 ID 會依 [dotnet/wpf v10.0.11 的官方內建表](https://github.com/dotnet/wpf/tree/v10.0.11/src/Microsoft.DotNet.Wpf/src/PresentationFramework/System/Windows/Markup/Baml2006) 解析，保留號或超出已知範圍的 ID 則維持數字。BAML element 以有上限的 flat node 清單保存 node ID、parent ID、depth、record start/end byte offset、content/complex parent property、child count 與 property value count，避免惡意深度造成遞迴序列化風險，也為 deferred value 定位保留依據；property value 也帶 element ID，可直接與節點對接。不平衡的 element 或 property scope 不會假裝成完整 tree，而會設定 `elementTreeComplete` 與錯誤原因。直接字串、字串表與型別參照、MarkupExtension argument、converter 輸入字串、custom binary 大小及 deferred StaticResource ID 會放在 `propertyValues`；simple deferred ResourceDictionary 另會保存 string/type key、相對與絕對 value 範圍、shared flags、對應 element，以及每個 key 自己的 optimized StaticResource 表。record 56 只用所在 value 的 key-local ID 解參照，不會誤查全域 string/type 表。complex key、verbose StaticResource、nested StaticResource indirection 目前會設定 `deferredResourcesComplete=false` 和明確原因，不會猜測關係。解析器不載入 WPF assembly、不執行 converter／serializer，也不建立 UI 物件。自訂資源型別不會反序列化，只保留完整型別名稱與原始資料大小。單一 assembly 最多保留 5,000 筆鍵值、單一文字值最多保留 4,096 字元；BAML 最多掃描 100,000 筆 record、每類最多保留 2,000 個 symbol、每檔最多保留 2,000 個 element、2,000 筆 property value、2,000 筆 deferred resource 與 2,000 筆 deferred StaticResource，每個 metadata 字串最多讀取 8,192 bytes，property value 最多保留 4,096 個字元，截斷狀態和解析錯誤都會明確記錄。

後續加入 complex deferred key、原生呼叫圖或更細的控制流程時會再提升 schema 版本，舊欄位維持相容。

## ZIP／ASAR 安全匯入

ZIP 只會把通過 portable path、重複／檔案目錄衝突、重新解析點與大小檢查的普通檔案寫進私人暫存目錄。ASAR 會先嚴格解析 8-byte 外層 Chromium Pickle、bounded header Pickle 與 strict UTF-8 JSON tree，再驗證每個項目的 portable path、十進位 offset、size、資料範圍和非完全相同的重疊範圍。實體 staging 檔名是 opaque 名稱；分類、報告和相依解析一律使用保留下來的邏輯路徑。

分析器會保留 ASAR 容器本身，並把 packed 項目以 streaming copy 寫入隨機私人暫存目錄；Unix-like 系統會把目錄權限縮到 mode `0700`。`.asar.unpacked` 只接受索引指定、大小相符且路徑中沒有重新解析點的檔案，讀取時仍會複製到私人 staging，避免把外部路徑直接當成展開結果。ASAR link 會驗證 target、循環與 hop 上限，但不建立作業系統 symlink；有 link、遺失 sidecar、無效 nested ASAR 或達到深度上限時，容器仍會留在 `files`，相對應的 `archives[].complete` 會是 `false` 並附上原因。

預設工作區最多保留 25,000 個檔案、20 GiB 邏輯總大小、單檔 4 GiB，archive depth 最多 8；另外會限制 ASAR 嘗試數、單一與累計 header、累計節點和保留路徑字元總量。所有 nested ASAR 共用同一組工作區 budget，不會在每一層重新歸零。取消或失敗時會清除私人暫存資料；Markdown 只列出 bounded archive 狀態，JSON 則保留完整的 archive 統計與 complete/error 契約。

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
所以 C#／C++／Rust／Go 產生器不會誤把原生函式當成 .NET 型別輸出。headless process 的 stdout/stderr 會同步清空並只保留 bounded diagnostic tail；逾時或取消會終止整個 process tree 並等待退出。匯出 JSON 最多 32 MiB、保留 100,000 筆函式及每欄 16,384 字元，超限會透過 `functionsTruncated` 明示，非零 exit code 或 schema 錯誤不會被當成成功結果。Windows 的 Ghidra launcher 是 batch；為避免 `%NAME%` 或 `!NAME!` 被 `cmd.exe` 多層展開成另一段路徑，launcher、輸入或暫存路徑若含 literal `%` 或 `!` 會安全略過並附上原因。

## 易語言

易語言分析預計分成動態編譯和靜態編譯兩條路徑：

- 動態編譯：從 `krnln.fnr`、支持庫和 dispatcher 關係整理命令呼叫。
- 靜態編譯：以自建特徵資料辨識支持庫函式、視窗、控件和事件。

現階段只完成 runtime 與套件特徵辨識，還沒有還原 `.e` 工程。

## 專案重建與轉語言

重建器不會直接翻譯零碎的反編譯文字。它會先把函式、型別、呼叫、UI、資源和外部副作用整理成中介資料，再由目標語言產生器輸出專案。

目前已有第一個產生器 `CSharpSkeletonGenerator`，吃 `CodeModel` 輸出 C# 骨架：
還原命名空間、型別、泛型巢狀宣告、ref struct、欄位、屬性、事件、方法簽章與繼承，並保留完整型別名稱及成員的可見性、static／abstract／virtual／override／sealed override 與 readonly 修飾詞；metadata 中標為 final new-slot 的隱含介面實作會輸出成一般非 virtual 成員，避免 sealed 類別產生無效 C#。ref-like 屬性不會輸出成需要 backing field 的 auto-property，而是使用無儲存欄位的 accessor stub。
多個輸入 assembly 會輸出 `Reconstructed.slnx`，套件內可對上的 assembly reference 會轉成 `ProjectReference`。方法體由 `ManagedSymbolReader` 的 IL 還原器重建：
先把 IL 解碼成指令陣列，用區間遞迴結構化把條件分支還原成 if／if-else，比對 Roslyn 的
while／for 形狀（先跳條件、主體、條件、往回跳）還原成 while，並把底測式（往回跳收尾）還原成 do-while（皆可巢狀）；
區塊內以堆疊模擬還原載入、算式、欄位、屬性、方法呼叫、`new`、運算子、`return`、`throw`；
auto-property 的隱藏欄位會還原成屬性名稱，運算子方法還原成運算子語法。
一般 property accessor 會輸出成成員存取，帶索引參數的 instance accessor 則會還原成 `target[index]` getter 或 setter，避免顯式呼叫 C# 禁止的 `get_*`／`set_*` 方法。
具現化 class 與原本就有 instance constructor 的 struct，其非 constant field 與 auto-property 會加上 `default!` skeleton initializer，明確表達尚未還原 constructor 初始化流程的佔位值；interface、abstract property、沒有 instance constructor 的 struct 與 ref-like computed property 不會套用。
方法簽章會讀取 parameter 與 return parameter 的 `NullableAttribute`，並依 method／declaring type 的 `NullableContextAttribute` 還原最外層 `?`；若 compiler-generated `Equals(object)` 使用 oblivious metadata，則依 `System.Object.Equals(object?)` override contract 補回 nullable 標記。
控制流程合併前必須預先宣告的 reference local 會使用 `default!` skeleton 佔位值；compiler-generated record 對 nullable value 呼叫 `EqualityComparer<T>.GetHashCode` 時也會保留 null-forgiving 語意，避免產生與原始程式無關的 nullable warning。
呼叫時會依正式參數型別，把 IL 整數常值還原成 bool、char 或具明確轉型的 enum 引數；區域變數會依方法的 local signature 用實際型別宣告。
重建 context 也會追蹤參數、區域變數、欄位、運算式與呼叫回傳型別；`brtrue`／`brfalse` 遇到參考型別時會輸出 `is null`／`is not null`，避免把物件直接當成 C# bool 條件。
IL enum 位元運算的整數常值會轉回另一側的 enum 型別，enum selector 的 `switch` case 常值也會套用相同型別，避免輸出無法編譯的 enum／int 混合運算。
IL `switch` 跳表可還原直接 return／throw 的分支，也能處理各 case 指派區域變數後回到共同 join 的形狀；這類區域變數會提升到 switch 外並依 IL locals init 語意先設成 default。
標準 `try/catch`、`try/finally`、`fault` 與複合 `try/catch/finally` 會依 exception region metadata 的保護區域與 handler 邊界還原，不靠跳轉位置猜測；保護區可用 `leave` 正常離開，也可由 `throw` 或合法巢狀 `rethrow` 直接終止。C# 沒有 `fault` 語法，因此會輸出語意等價的 `catch` 並在 handler 尾端重新拋出。
`catch` 支援多個 handler、未命名 catch-all、具名例外變數、重新拋出，以及 Roslyn 產生的直線運算式與可混合巢狀的 `&&`／`||` 短路 `when` filter；filter 後接一般 catch 或與 finally 複合也能還原。跨區塊的區域變數會提升到 `try` 外並依 IL locals init 語意先設成 default。
含回跳、會產生陳述式或不規則控制分支的 filter，以及非標準例外區域目前仍會退回反組譯 IL 註解加 `NotImplementedException`。
重建採全有或全無：遇到無法結構化的跳轉、參照編譯器產生的名稱或任何不支援的指令，就整個方法放棄，
寧可不還原也不產出語意錯誤的程式碼。enum 會保留底層整數型別與各成員原始數值；
型別引用已保留完整命名空間，但套件外依賴與泛型限制仍可能需要手動補齊，因此不保證可直接編譯。資源解析不會具現化或反序列化自訂型別，以免分析不可信檔案時執行非預期程式碼。

另外也有 `CppSkeletonGenerator`、`RustSkeletonGenerator`、`GoSkeletonGenerator`，
共用 `SkeletonSupport` 挑型別與 `LanguageTypeMap` 做基本型別對應，各自輸出該語言的型別與方法簽章骨架
（struct／class／trait／interface／enum），方法體留空。這三個語言目前只還原結構，不翻譯方法內容。

第一批預定的輸出方向：

- .NET assembly → C# project
- 易語言／VB6／Delphi → C# Windows desktop project
- 原生 C／C++ → C-like project skeleton
- Blueprint → C#、C++、Rust

每個輸出項目都會標示 `confirmed`、`inferred` 或 `unknown`，並保留來源證據。
