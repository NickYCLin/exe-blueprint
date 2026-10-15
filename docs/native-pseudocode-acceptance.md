# 原生偽碼與名稱映射驗收

## 啟用與證據

CLI 使用 `--native-pseudocode`，預設關閉；此選項同時啟用原生分析。Core 呼叫端設定 `EnableNativeAnalysis=true` 與 `AnalysisOptions.NativeDecompilation`，匯出服務則使用 `BlueprintExportRequest.NativeDecompilation` 並啟用原生分析。五項預算均可調整：最多函式 1–4096、每函式字元 1–262144、全局字元 1–8388608、每函式秒數 1–60、全局秒數 1–600。CLI 使用預設值，不提供個別預算旗標。

`nativeCode.decompilation` 為可選欄位，Ghidra script 的原有 schemaVersion 3、函式清單與 callGraph 不變；v1/v2/v3 舊輸出不要求偽碼。證據記錄輸入 SHA256、Ghidra analyzerVersion、limits、candidateCount、complete、truncated、limitReason，以及各函式的 address/status/code/diagnostic/elapsedMilliseconds。SHA 同時核對原始輸入、Ghidra 匯入程式和匯出紀錄，函式位址必須連到已保留的非外部函式。parser 拒絕重複欄位、未知位址、缺少必要紀錄、損壞 JSON、錯誤狀態與超量輸出。

status 為 success、failed、timeout 或 truncated。`complete` 表示所有候選函式都已嘗試且 inventory 未截斷，不代表全部成功；每函式仍須查看 status。截斷字元以 UTF-16 code unit 計算，不在非 BMP 字元中間截斷。逐函式與全局時間從 DecompInterface 初始化前起算，傳給 decompileFunction 的秒數不超過剩餘全局預算；低於一秒不再啟動下一個函式。這不是硬即時保證，初始化、Ghidra 自動分析及不回應的後端仍受既有 headless 程序逾時和程序樹清理機制保護。

opt-in 匯出在第一次基礎圖 checkpoint 前，先核對 Ghidra 實際匯入 SHA256 與請求；不符時不寫出 checkpoint。所有 opt-in checkpoint（包含尚無 decompilation 的基礎圖）都在根層保留實際匯入 inputSha256，Analyzer 必須先確認該欄位唯一、為字串且與請求相符，才可保留函式與 CALL 圖。缺少、重複、錯型別或不匹配時明確失敗，不以 stderr 文字推斷，也不把請求 hash 補到未驗證的圖上。程序非零退出或 headless 逾時時，只有通過這項 SHA 核對及有效 JSON／偽碼限制核對的 checkpoint 才保留，並標示 backend_partial/process_timeout。尚未開始或未完成的函式不虛構成功／逾時紀錄；已驗證的基礎圖沒有偽碼 checkpoint 時版本標 unavailable。使用者取消仍拋出取消例外，不假裝成功。未啟用偽碼的舊 JSON 仍相容。JSON 共用 24 MiB 預算；圖接近上限時，opt-in 額外保留證據空間可能使圖提早截斷。

## 真 Ghidra 驗證

準備官方 Ghidra、適用 JDK 和隨附 Jython extension。與既有原生驗收相同，Ghidra 12 的 Jython ZIP 須安裝到該版本的 Ghidra/Extensions，不混用不同版本。工具不由驗收腳本自動下載或安裝。

在 Linux 的 mingw-w64 環境，只編譯 repository 自有 fixture：

```bash
x86_64-w64-mingw32-gcc -shared -O0 -nostdlib -Wl,--entry,0 \
  -o /tmp/native_pseudocode.dll tests/ghidra/fixtures/native_pseudocode.c
JAVA_HOME=/path/to/jdk-21 python3 -B scripts/ghidra/verify_pseudocode_fixture.py \
  --ghidra /path/to/ghidra --fixture /tmp/native_pseudocode.dll \
  --output /tmp/pseudocode-acceptance
```

output 必須是新目錄。腳本只呼叫 Ghidra 做靜態分析，不執行 DLL，也不編譯／執行偽碼。它依序驗證關閉、啟用和縮小預算的輸出，保留三份 JSON/log 與 acceptance.json；檢查 if、loop、switch、caller 的直接呼叫、位址對應、根層與偽碼 SHA 和原有圖相等。縮小預算保留兩函式、80/40 個字元且完整性為 false。另以不同的請求 SHA 做第四次真 Ghidra 分析，保留 mismatch.config.json/log，確認匯入核對失敗且沒有產生任何 mismatch.json checkpoint。

2026-10-14 在 Linux x64，Ghidra 12.1.4、隨附 Jython、JDK 21.0.12.1、mingw-w64 GCC 13 `-O0`，自有 DLL SHA256：

`05cc8b40387588798585018f0469d5022a40e3f2262be48e56925f26e14e0bfe`

branch `1dbf81000`、loop `1dbf8101c`、choice `1dbf81050`、caller `1dbf810c5` 均 success，四函式、五筆直接 CALL。啟用與關閉的函式/CALL 圖一致。另以 Release CLI 的 `analyze ... --native-pseudocode --json-only` 驗證同一 SHA、版本與偽碼保存到 blueprint.json。建置工具鏈或時間戳不同可能改變 DLL SHA／位址，以每次 acceptance.json 為準。

## Managed 與安全界線

.NET 重建方法體與骨架宣告共用名稱清理，參數亦共用重名後綴；方法、欄位、accessor、名義型別、泛型及陣列依 metadata 結構映射。原始型別 identity 與呼叫圖名稱保留，安全判定不使用清理後的文字，避免 primitive alias spoofing。文字常值不做全方法取代。超深／過長輸出仍 fail closed，名稱映射不保證重建結果可編譯或可還原原始來源。

一般 CI 執行 .NET 與 Python mock/API fixture 測試，不安裝真 Ghidra。取消、缺後端、損壞、超量、partial、函式逾時與全局時間限制由 fixture 測試覆蓋；函式 timeout/failed 和強制程序中止並非這次真 Ghidra 成功 fixture 的實測結論。沒有執行未知 EXE 或未知重建結果，沒有動態攻擊、解鎖、AI 命名或 MCP 查詢。REA 僅作概念參考，沒有複製其程式碼；影片只取得過 metadata／說明／章節，沒有字幕，也未據此聲稱看完。

## 獨立驗收回饋回歸

2026-10-14 後續修正加入直接 parser 及完整 Analyzer 的 null／錯型別測試，functions:[null] 明確拋 InvalidDataException，Analyzer 安全回傳失敗而非崩潰。三位元組自有輸入搭配 fake processRunner，驗證 exit=0/1 的不匹配 hash，以及缺少、錯型別、重複 hash 的有效基礎圖都不會保留；只有 hash 已驗證的基礎圖能轉成 backend_partial。測試亦刻意讓已驗證基礎圖帶有 mismatch stderr，確認 Analyzer 的信任判斷依 JSON hash 而非診斷字串。

另建立 40 層 TypeDefinition／TypeReference 合成 metadata，10 秒測試期限內解析，核對完整 raw 名稱、清理後名稱及原始 nominal handle，防止同一父層重複遞迴回歸。Release build 為 0 warnings/errors，全套 Core 944、Desktop 23、Python 17 項通過。

## 缺後端的請求證據

2026-10-15 使用同一自有 DLL，執行 `analyze ... --ghidra /不存在的目錄 --native-pseudocode --json-only`，重現 `Backend=none` 但 decompilation 為 null，無法從該欄位區分未請求與已請求但缺後端。修正後，只有 opt-in 且輸入可讀時保留主機實際讀取的輸入 SHA256、原請求 limits、analyzerVersion=unavailable、limitReason=backend_unavailable、complete=false，函式清單為空且沒有 CALL 圖；沒有輸出被裁切，因此 truncated=false。這是請求失敗證據，不是已通過 Ghidra 匯入核對的 checkpoint，零筆函式不表示已完成掃描或輸入沒有函式。

未啟用偽碼時仍不產生 decompilation；輸入無法讀取時安全失敗，不虛構 hash。取消與不匹配 checkpoint 的拒絕行為維持不變。本次只補缺後端路徑，其他無 checkpoint 的程序失敗仍由 Backend=none 與 Note 說明，未宣稱所有失敗路徑都有偽碼證據。

新增測試先重現 opt-in 的 Assert.NotNull 失敗，修正後 NativeDecompilationTests 35 項通過；`dotnet build ExeBlueprint.slnx -c Release` 為 0 warnings/errors，`dotnet test ExeBlueprint.slnx -c Release --no-build` 的 Core 946、Desktop 23 項與 `python3 -B -m unittest discover -s tests/ghidra -v` 的 17 項全數通過。最終 Release CLI 分別以不存在的後端路徑及既有 Ghidra 12.1.4 靜態分析自有 DLL：前者保留 backend_unavailable 證據且無圖，後者仍為 4 個成功函式、5 個 CALL，if／loop／switch／call 偽碼及 SHA256 核對通過，函式清單與 CALL 圖和先前驗收結果相同。未執行 DLL 或重建產物。
