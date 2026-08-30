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

目前 schema 版本是 `0.9`，主要欄位包括：

- `input`：輸入類型、檔案數與總大小
- `summary`：PE、assembly、型別、方法、資源和相依關係數量
- `files`：每個檔案的格式、雜湊、來源資訊（provenance）和分析資料，受管組件另含 `code`
- `files[].origin`：`direct`、`directory`、`zip` 或 `asar` 來源；需要時保存直接容器、容器內項目與展開深度，讓 staging 實體路徑不會外洩或取代邏輯路徑
- `files[].code`：.NET 型別、巢狀宣告與 ref-like 關係、泛型名稱與 additive constraint 明細、欄位、含 index parameters 的屬性、事件、方法簽章、dispatch 與已還原 body 的 `requiresUnsafeContext` 旗標、入口點、方法層級呼叫圖、manifest 資源與各方法反組譯出的 IL
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
還原命名空間、型別、泛型巢狀宣告、ref struct、欄位、屬性、事件、方法簽章與繼承，並保留完整型別名稱及成員的可見性、static／abstract／virtual／override／sealed override 與 readonly 修飾詞；metadata 中標為 final new-slot 的隱含介面實作會輸出成一般非 virtual 成員，避免 sealed 類別產生無效 C#。ref-like 屬性不會輸出成需要 backing field 的 auto-property，而是使用無儲存欄位的 accessor stub；具體型別的唯寫屬性也會保留 property 形狀並使用區塊 setter，避免 C# 禁止的 setter-only auto-property 與虛構 getter。沒有任何 accessor，或同時帶 setter 與 by-ref return 的 PropertyDef 無法安全表示成 C# property，會保守略過。
多個輸入 assembly 會輸出 `Reconstructed.slnx`，套件內可對上的 assembly reference 會轉成 `ProjectReference`。方法體由 `ManagedSymbolReader` 的 IL 還原器重建：
先把 IL 解碼成指令陣列，用區間遞迴結構化把條件分支還原成 if／if-else，比對 Roslyn 的
while／for 形狀（先跳條件、主體、條件、往回跳）還原成 while，並把底測式（往回跳收尾）還原成 do-while（皆可巢狀）；
區塊內以堆疊模擬還原載入、算式、欄位、屬性、方法呼叫、`new`、運算子、`return`、`throw`；
區間內的 terminal `void ret` 會保留為明確 `return;`，避免 if／switch／exception 分支誤穿透到 join 後繼續產生副作用；只有方法最外層的最後一個 `return;` 會略去。ECMA-335 禁止出現在 try／filter／handler 保護範圍內的 `ret` 會整體 fail closed，不會被誤轉成無法編譯的 C# `return`。
auto-property 的隱藏欄位會還原成屬性名稱，運算子方法還原成運算子語法。
一般 property accessor 會輸出成成員存取，帶索引參數的 instance accessor 則會還原成 `target[index]` getter 或 setter，避免顯式呼叫 C# 禁止的 `get_*`／`set_*` 方法。
instance call 會保留 IL 的 dispatch 種類：`callvirt` 維持一般 receiver／interface dispatch；`call` 只有在 receiver 可證實為 `ldarg.0`，且 owner 是精確等於目前 TypeDef direct `BaseType` 的同模組 TypeDef／MethodDef 時才輸出 `base`。同型別 direct call 僅接受已知 nonabstract nonvirtual 或 nonabstract virtual-final MethodDef；非 `this` receiver、TypeRef／TypeSpec base、未知 MemberRef、非直接祖先、同名不同 handle 與 generic MethodSpec 都 fail closed，避免把 nonvirtual call 誤寫成遞迴或虛擬 dispatch。
具現化 class 與原本就有 instance constructor 的 struct，其非 constant field 與 auto-property 會加上 `default!` skeleton initializer，作為尚未完整證實所有 constructor 路徑時的佔位值；interface、abstract property、沒有 instance constructor 的 struct 與 ref-like computed property 不會套用。
instance class constructor 另有獨立的 fail-closed prologue 還原：caller 與所有本地 MethodDef callee 都必須是 default calling convention、非 generic／varargs、具正式 constructor flags 的 `.ctor`；metadata 無法提供 flags 的外部 MemberRef callee 則驗證 `.ctor` 名稱、default instance signature 與精確 owner handle。第一個副作用只能是 `ldarg.0`、最多 32 個直接 argument／primitive literal load，再以 `call` 指向目前 TypeDef 的另一個 MethodDef 或精確的 direct-base handle。引數僅接受具 primitive provenance 的 CLI primitive、exact nominal identity、bool `0/1`，或已驗 enum／integral 的同 CLI stack family；`this(...)` handle graph 以迭代方式驗證，必須無循環並最終抵達 `base(...)`。generic definition chain、constructed base、同名不同 handle、祖先／無關 owner、`callvirt`、prefix EH、越界／非指令邊界 branch target 或跳回 prefix 都拒絕。已證實的 initializer 以結構化 `constructorInitializer.kind/arguments` 保存；call 後若只是寫入目前 TypeDef instance FieldDef 的 `this.field = argument/literal` 直線序列才同時輸出 body，其餘 tail 保留 initializer 但維持空 constructor skeleton。
方法簽章會讀取 parameter 與 return parameter 的 `NullableAttribute`，並依 method／declaring type 的 `NullableContextAttribute` 還原最外層 `?`；若 compiler-generated `Equals(object)` 使用 oblivious metadata，則依 `System.Object.Equals(object?)` override contract 補回 nullable 標記。
CLI function-pointer signature 會還原成 C# `delegate* managed<...>` 或 `delegate* unmanaged[...]<...>`，並保留 Cdecl、Stdcall、Thiscall、Fastcall、SuppressGCTransition 等可表示的 calling convention 順序與重複項目。varargs、generic／instance header、無法表示的 required modifier、未知 calling convention、巢狀 modifier 或 function pointer generic argument 會保守退回 `nint`，避免輸出語意錯誤或無法編譯的型別。C# generator 會只把直接輸出 pointer／function-pointer 成員，或成功還原 body 確實使用 pointer local、field、call／newobj signature 的 owner type／delegate 標成 `unsafe`；同一 project 確實可達這些輸出時才加入 `AllowUnsafeBlocks`，不會因被過濾的 orphan nested type 或安全 parent 誤擴大範圍。
type 與 method generic parameter 會另外保存 position、raw flags、variance、special constraints、`allows ref struct`、完整 nullable flag vector、constraint rows 與 `modreq`／`modopt`。`notnull` 只採用 generic parameter 本身的 `NullableAttribute(1)` 作為 Roslyn convention 證據，不會把 owner context fallback 猜成 constraint；`unmanaged` 只有在 `IsUnmanagedAttribute`、`ValueType modreq(UnmanagedType)` 與 special flags 一致時才視為完整。外部 TypeRef 無法在不載入 dependency 的前提下證明 class/interface、metadata 衝突或資料超限時，會保留原始型別並標示 `complete=false` 與原因。舊的 `genericParameters` 名稱陣列仍保留相容性；C# generator 只在 owner、parameter 與所有 constraints 都完整且 modifier／nullable shape 可表示時，依 primary、base／type parameter／interface、`new()`、`allows ref struct` 的合法順序輸出 `where`，否則整個 owner 保守略過 constraints；constructed class/interface constraint 在 schema 尚未保存 generic definition contract 前也採 fail-closed，避免產生不符合其型別參數限制的程式碼。override 與 explicit interface implementation 則沿用原宣告的 constraints，不重複輸出。
泛型讀取另有 assembly 與 owner 共用的 parameter row、constraint row、保留字元預算；單一 TypeSpec 的 bytes／節點／深度／arity、qualified-name bytes、modifier 數量與 modifier 輸出也各自受限。達到任一上限時會停止保留後續資料，透過 owner 的 `genericParametersComplete=false`／`genericParametersError` 與 `code.truncated` 明示不完整；因此極端情況下該 owner 的明細陣列可以是空的，不會把缺資料誤報為完整，並避免少量惡意 metadata 放大成巨量記憶體或 JSON。
控制流程合併前必須預先宣告的 reference local 會使用 `default!` skeleton 佔位值；compiler-generated record 對 nullable value 呼叫 `EqualityComparer<T>.GetHashCode` 時也會保留 null-forgiving 語意，避免產生與原始程式無關的 nullable warning。
呼叫時會依正式參數型別，把 IL 整數常值還原成 bool、char 或具明確轉型的 enum 引數；區域變數會依方法的 local signature 用實際型別宣告。
重建 context 也會追蹤參數、區域變數、欄位、運算式與呼叫回傳型別；`brtrue`／`brfalse` 遇到參考型別時會輸出 `is null`／`is not null`，避免把物件直接當成 C# bool 條件。
IL enum 位元運算的整數常值會轉回另一側的 enum 型別，enum selector 的 `switch` case 常值也會套用相同型別，避免輸出無法編譯的 enum／int 混合運算。
`div.un`／`rem.un`／`cgt.un`／`clt.un` 只在兩側型別都能確認屬於同一個 int32、int64 或 native-int stack family 時還原；運算元會先明確轉成 `uint`、`ulong` 或 `nuint`，算術結果寫回同 family 的 signed／窄型別時再使用 `unchecked` 轉型。`cgt.un` 的既有 reference/null 正規化仍保留；型別未知、跨 family 或具 unordered 語意的浮點輸入則讓整個方法 fail closed。

`bge.un`／`bgt.un`／`ble.un`／`blt.un`（含 short form）沿用同一個型別閘門；前向 `if` 會輸出 unsigned fall-through 補集，迴圈與 filter 所需的 taken 分支則輸出原始關係運算。浮點 `.un` 分支包含 NaN unordered 語意，尚未能無損表示時不會退化成一般 signed C# 比較。
寫入 argument、local、field 與 return 的 typed target 會依 CLI integral stack family 正規化：`int` 常值 `0/1` 寫入 bool 時還原成 `false/true`，其餘值拒絕；需要在 enum 與 integral 之間轉型時，enum 只接受目前 assembly 中 non-generic definition chain、可唯一驗證為 sealed `System.Enum`、具唯一 `value__` instance field 與型別／常值一致之 static literal 的 TypeDef，並要求 signature 以 `VALUETYPE` 指向該 handle，再於同 stack family 內補上 `unchecked` 明確轉型。其 `System.Enum` base 必須直接來自 neutral framework AssemblyRef 與正式 public-key token；同 assembly 重複 full name 的 TypeDef，以及需要轉型之外部、generic 或 malformed enum、偽造的本地 `System.Enum` base 與跨 family 寫入，都會讓該 method fail closed，不靠具名型別外觀猜測。
`shl`／`shr`／`shr.un` 會先把左值正規化成該 CLI stack family 的 signed carrier（`int`／`long`／`nint`），再分別輸出 `<<`／`>>`／`>>>`，因此經 metadata 驗證的 enum 與無號整數不會被 C# enum 運算子或 signedness 改寫語意。shift count 僅接受已知 int32 或 native-int family，必要時以 `unchecked((int)...)` 取得 C# 所需的 count；int64、浮點、bool、reference、未知與未驗證具名型別一律 fail closed。
IL `switch` 跳表可還原直接 return／throw 的分支，也能處理各 case 指派區域變數後回到共同 join 的形狀；這類區域變數會提升到 switch 外並依 IL locals init 語意先設成 default。
標準 `try/catch`、`try/finally`、`fault` 與複合 `try/catch/finally` 會依 exception region metadata 的保護區域與 handler 邊界還原，不靠跳轉位置猜測；保護區可用 `leave` 正常離開，也可由 `throw` 或合法巢狀 `rethrow` 直接終止。C# 沒有 `fault` 語法，因此會輸出語意等價的 `catch` 並在 handler 尾端重新拋出。
`catch` 支援多個 handler、未命名 catch-all、具名例外變數、重新拋出，以及 Roslyn 產生的直線運算式與可混合巢狀的 `&&`／`||` 短路 `when` filter；filter 後接一般 catch 或與 finally 複合也能還原。跨區塊的區域變數會提升到 `try` 外並依 IL locals init 語意先設成 default。
含回跳、會產生陳述式或不規則控制分支的 filter，以及非標準例外區域目前仍會退回反組譯 IL 註解加 `NotImplementedException`。
重建採全有或全無：遇到無法結構化的跳轉、參照編譯器產生的名稱或任何不支援的指令，就整個方法放棄，
寧可不還原也不產出語意錯誤的程式碼。enum 會保留底層整數型別與各成員原始數值；
型別引用已保留完整命名空間，但套件外依賴與無法安全表示的 metadata 仍可能需要手動補齊，因此不保證可直接編譯。資源解析不會具現化或反序列化自訂型別，以免分析不可信檔案時執行非預期程式碼。

另外也有 `CppSkeletonGenerator`、`RustSkeletonGenerator`、`GoSkeletonGenerator`，
共用 `SkeletonSupport` 挑型別與 `LanguageTypeMap` 做基本型別對應，各自輸出該語言的型別與方法簽章骨架
（struct／class／trait／interface／enum），方法體留空。這三個語言目前只還原結構，不翻譯方法內容。

第一批預定的輸出方向：

- .NET assembly → C# project
- 易語言／VB6／Delphi → C# Windows desktop project
- 原生 C／C++ → C-like project skeleton
- Blueprint → C#、C++、Rust

每個輸出項目都會標示 `confirmed`、`inferred` 或 `unknown`，並保留來源證據。
