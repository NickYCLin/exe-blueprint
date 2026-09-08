# 功能詳解與開發方向

[回產品首頁](../README.md) · [English overview](../README.en.md) · [結構化產品資料](product.json)

本頁依目前 main 原始碼整理，保留較完整的支援範圍與限制。下載版的功能請以對應 Release 說明為準。

## 目前能做什麼

- 桌面版依選來源、設定結果、分析與查看結果分成三步；進度與結果固定顯示，支援拖放、最近來源、取消、直接查看注意事項與開啟報告。詳細操作見[桌面版說明](desktop-guide.md)。

- 分析單一檔案、完整資料夾、ZIP 或 Electron ASAR；資料夾與 ZIP 內的 ASAR、以及有上限的巢狀 ASAR 也會展開；若直接輸入 .NET apphost，偵測到同名 DLL 與 `.runtimeconfig.json` 時會一併分析該受管 DLL
- 計算每個檔案的 SHA-256
- 讀取 PE 架構、子系統、section 與簽章資料
- 分辨 .NET assembly 與原生 PE
- 讀取 PE imports 與 .NET assembly references
- 讀出 .NET assembly 的命名空間、型別、巢狀宣告關係、ref-like 旗標、欄位、屬性、事件、方法簽章、virtual／override／sealed dispatch 旗標、enum 常值與繼承關係
- 列出 .NET assembly 的內嵌 manifest 資源（.resources、WPF BAML、內嵌設定檔或組件），標出用途、位置與大小；`.resources` 會再列出鍵名、型別及可安全解碼的標準值；對 System.Resources.Extensions 預序列化的自訂型別，會讀出封裝格式、payload 大小／magic 與 TypeConverterString 的原始文字，不載入型別或執行轉換器；內嵌 `.json`、`.xml` 與 `.config` 設定檔只會列出元素、屬性與欄位結構，不會輸出設定值；`.baml` 會整理檔頭版本、record 類型數量、element／property 使用次數、可重建 parent/child 與 content/complex property 關係的 flat element tree、檔案內宣告與 WPF 內建的型別／屬性 ID 對照、安全的 property 值，以及 deferred ResourceDictionary 的 string/type/complex key、value 範圍和 key-local optimized／verbose StaticResource 關係
- 掃描 IL 建立方法層級呼叫圖，看得出程式流程怎麼串
- 把每個方法的 IL 反組譯成可讀指令（呼叫、字串、分支目標都解析出來）
- 用堆疊模擬把方法 IL 還原成 C# 陳述式，把條件分支還原成 if／if-else，迴圈還原成 while／do-while（可巢狀），並還原標準 try/catch、含混合巢狀 `&&`／`||` 短路條件的 catch filter、try/finally、fault 與複合 try/catch/finally，也支援保護區直接拋出例外的 terminal try
- 能把標準 IL 跳表還原成 switch，支援 case 直接 return／throw，或指派區域變數後回到共用流程
- 把 .NET 型別轉出一份 C# 骨架，能還原的方法直接給程式碼，其餘附上原始 IL
- 另外可轉出 C++／Rust／Go 的型別與方法簽章骨架（結構為主，方法體留空）
- 選配用 Ghidra headless 分析原生 PE，列出函式、靜態 CALL 與無條件直接跳躍的 tail call，保留呼叫位置、直接／間接類型和未解析 CALL 目標（沒裝 Ghidra 會自動略過並加註記）
- 找出套件內可以對上的 EXE／DLL 相依關係
- 依檔案內容辨識常見語言、runtime、框架與安裝器
- 輸出 JSON 與繁體中文 Markdown 報告
- 安全解開 ZIP，阻擋路徑穿越、跨平台路徑衝突和符號連結
- 嚴格解析 ASAR 的 Chromium Pickle header 與 JSON 索引，驗證路徑、offset、size 和範圍後才把內容複製到私人暫存目錄；外置 `.asar.unpacked` 項目會驗證大小與重新解析點，ASAR link 不會落成作業系統連結
- ASAR 展開受到檔案數、總大小、單檔大小、巢狀深度、封存數、header、節點和路徑總量限制；無效或只完成一部分的封存會保留容器並在 JSON／報告明示原因

目前已有以下辨識規則：

- .NET、WPF、Windows Forms、Avalonia
- Visual Basic 6、Delphi／C++Builder、Microsoft Visual C++
- Go、Rust、Python、PyInstaller、Java／JVM
- 易語言 runtime 與支持庫檔案
- Qt、Tauri、Electron、Unity
- Inno Setup、NSIS

辨識結果會附上依據與可信度。看到某個語言名稱，不代表已經證明原始碼就是用該語言撰寫。

## 報告內容

`blueprint.json` 目前使用 schema `0.18`，是後續專案重建和轉語言要共用的資料格式，內容包含：

- 輸入套件摘要
- 每個檔案的格式、雜湊與來源資訊（provenance；直接輸入、資料夾、ZIP 或 ASAR，以及直接容器、項目和深度）
- ASAR 封存的 header／節點／packed／unpacked／link 數量，以及完整或不完整狀態與原因
- PE 與 .NET metadata
- .NET 型別、同一 artifact 內的 TypeDef／declaring TypeDef identity、泛型參數與 constraint metadata（含獨立的 owner domain／primary constraint 證據）、欄位、屬性、事件、方法簽章、方法層級呼叫圖與各方法反組譯出的 IL
- `.resources` 的標準鍵值，以及預序列化自訂型別的 `serialization` 格式、payload 大小、辨識出的資料種類與完整性；只會保留原始 TypeConverterString 文字
- 原生 `nativeCode.callGraph` 的呼叫來源、位置、目標位址、直接／間接類型與 `isTailCall`；`tailCallsAnalyzed` 區分後端是否支援直接 tail call 分析，無法確認 CALL 目標時保留 `null`，超限時標示 `truncated`
- 內嵌 JSON 與 XML／`.config` 設定檔的 `configuration` 結構摘要（根類型、結構節點數和欄位路徑），不保存任何設定值
- 語言、框架和工具鏈判斷
- 套件內與外部相依關係
- 分析警告

`REPORT.md` 適合直接閱讀，用來快速確認入口程式、架構、相依套件、程式碼結構和辨識結果。

## 接下來要做的功能

- 解開 Inno Setup、NSIS、MSI、PyInstaller 與 Electron 外層安裝封裝（Electron ASAR 已支援）
- 深化原生 PE 分析：補上條件／間接 tail call 與程式碼還原（目前已有函式清單、靜態 CALL 及無條件直接 tail call；間接呼叫的執行期目標仍可能不完整）
- 擴充中介模型，補上 UI 與設定（函式、型別、欄位、屬性、事件、呼叫圖、內嵌 manifest 資源清單、`.resources` 標準鍵值與預序列化自訂型別的安全 envelope 摘要、內嵌 JSON／XML 設定的安全欄位結構，以及 WPF BAML record、flat element tree、檔內與內建型別／屬性 ID、可安全讀取的 property 值、deferred complex key 與 verbose StaticResource 關係已完成 .NET 部分；接著可深化型別專屬的靜態摘要）
- 補齊例外處理與型別引用，讓骨架能直接編譯成多專案 solution（目前會產生 `.slnx` 與套件內的 `ProjectReference`，class 與具 instance constructor 的 struct skeleton 成員會有 `default!` initializer，已保留完整命名空間、泛型巢狀型別、interface／delegate variance、可安全表示的 type／method／delegate `where` constraints、ref struct、managed／unmanaged 函式指標簽章、pointer 成員與已還原方法體所需的 scoped `unsafe` context、方法與運算式的 nullable 語意及欄位／屬性／事件修飾詞，能區分 virtual、override、sealed override 與 final 介面實作，並還原 canonical `base(...)`／`this(...)` constructor initializer、直線欄位初始化、exact direct-base nonvirtual dispatch、terminal void return、if／if-else、while／do-while、標準 switch、try/catch、含混合巢狀短路條件的 catch filter、try/finally、以 catch/rethrow 等價表示的 fault、複合 try/catch/finally、terminal try、indexer、具區塊 setter 的唯寫屬性、參考型別 null 分支、bool／char／enum 呼叫常值、enum 位元運算、位移與 switch case、enum 成員常值、區域變數型別、bool／enum typed target 的 CLI stack-family 轉型，以及具已知整數 stack family 的 `div.un`／`rem.un`／`cgt.un`／`clt.un` 與四種 `.un` 關係分支）
- 優先支援易語言、VB6、Delphi 到 C# 的轉換
- 讓 C++／Rust／Go 產生器也還原方法體、支援易語言（目前這三個語言只還原結構）
- 比較原程式與重建版本的輸入、輸出和副作用
- 補上 macOS／Linux 桌面版安裝整合（Windows 安裝程式已加入建置與驗收流程，從下一次版本發布起提供；拖放輸入與最近使用項目已完成）

這些項目尚未完成，詳細分層可看 [架構說明](architecture.md)。
