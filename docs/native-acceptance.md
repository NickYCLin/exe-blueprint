# 原生呼叫圖驗收

`tests/ghidra/test_export_functions.py` 使用 API fixture 檢查匯出規則與安全上限。以下流程另外用真實 Ghidra、MSVC 編譯出的 Windows x64 DLL，以及 CLI 的 JSON／Markdown 輸出做整合驗收。

## 準備工具

- Windows x64、Python 3 與 .NET 10 SDK
- Visual Studio 或 Build Tools 的 MSVC x64 工具；腳本會用 `vswhere` 尋找，也可指定 `--compiler`
- [官方 Ghidra 發行套件](https://github.com/NationalSecurityAgency/ghidra/releases)與其要求的 [JDK](https://github.com/NationalSecurityAgency/ghidra#install)

匯出腳本使用 Jython runtime。Ghidra 12.1.3 將 Jython 放在隨附的擴充套件中，使用前需在 Ghidra 的 `File → Install Extensions` 安裝 Jython；若只使用 headless，可依套件內 `GettingStarted.html` 的說明，把 `Extensions/Ghidra/*_Jython.zip` 解壓縮到同一份安裝目錄的 `Ghidra/Extensions`。不要混用不同 Ghidra 版本的擴充。

在 repository 根目錄執行，將工具路徑換成實際位置：

```powershell
python -B scripts/ghidra/verify_native_fixture.py `
  --ghidra C:\tools\ghidra_12.1.3_PUBLIC `
  --java-home C:\tools\jdk-21
```

腳本不會下載或安裝工具。它會在 `artifacts/native-acceptance-*` 建立獨立目錄，以 `/O2` 編譯 `tests/ghidra/fixtures/native_calls.c`，再建置 Release CLI 並呼叫真正的 Ghidra headless。DLL 只接受靜態分析，整個流程不會執行它；`JAVA_HOME` 與編譯器路徑也只傳給子程序。

## 檢查內容

- `tail` 必須透過直接 tail call 連到 `target`，保留呼叫位置與函式位址。
- `ordinary` 必須保留一般 CALL，不能誤標為 tail call。
- `loop` 的函式內回邊與 `indirect` 的 computed jump 不能被標成直接 tail call。
- 函式與呼叫圖不得截斷，`tailCallsAnalyzed` 必須為 true。
- `REPORT.md` 必須顯示 tail call 分類。

通過後會寫出 `acceptance.json`，記錄 Ghidra／schema 版本、DLL 的 SHA-256、函式和呼叫數量；同目錄保留編譯、建置、分析 log 與報告。失敗會以非零 exit code 結束，並保留資料供檢查。

這份驗收只涵蓋上述 Windows x64 fixture，其他平台、條件／間接 tail call、ABI 與堆疊語意仍需各自驗證。一般 CI 持續執行不需要 Java 的 API fixture 測試；本流程需備妥工具後另外執行。

## 已驗證結果

2026-09-08 在 Windows x64，使用 Ghidra 12.1.3、隨附 Jython 擴充、JDK 21 與 MSVC x64 `/O2` 通過上述驗收：5 個函式、2 筆呼叫、1 筆直接 tail call、0 筆未解析目標，函式與呼叫圖均未截斷。JSON 與 Markdown 均保留分類，函式內迴圈及 computed jump 沒有誤判。

首次載入 Jython 擴充時，這台測試機曾超過原生分析預設的 180 秒期限；完成首次載入後重跑成功。逾時結果會標示後端不可用，不會當成空呼叫圖。這項實測不代表所有 Ghidra 版本與平台皆已驗收。
