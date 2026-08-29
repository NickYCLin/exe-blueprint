ExeBlueprint（命令列工具）
============================

這不是安裝程式，是一個「命令列工具」，不需要安裝，解壓縮後就能用。

最快的用法
----------
1. 把這個 zip 全部解壓縮到一個資料夾（三個檔案要放在一起）。
2. 雙擊 run.bat，照畫面提示做；
   或直接把要分析的 EXE / DLL / 資料夾 / ZIP / ASAR 拖到 run.bat 上。

想自己打指令（PowerShell）
--------------------------
在解壓縮後的資料夾按住 Shift + 右鍵 → 「在此處開啟 PowerShell」，然後：

    .\exe-blueprint.exe --help
    .\exe-blueprint.exe analyze .\你的程式.exe -o .\report

分析結果會放在 exe-blueprint-output\ 資料夾底下的 blueprint.json 與 REPORT.md。

如果打不開 / 被 Windows 擋住
----------------------------
這支程式沒有做程式碼簽章，從網路下載的執行檔常被 Windows 擋，處理方式：

* 出現「Windows 已保護您的電腦」(SmartScreen)：
  點「其他資訊」→「仍要執行」。

* 檔案被封鎖（Mark of the Web）：
  對 exe-blueprint.exe 按右鍵 →「內容」→ 最下面若有「解除封鎖」勾起來 → 套用。

* 防毒/Defender 把它隔離了（自包含單檔 .NET 程式常被誤判）：
  到 Windows 安全性 →「病毒與威脅防護」→「保護歷程記錄」，把它允許/還原。

* 出現「這個應用程式無法在您的電腦上執行」：
  代表你的 Windows 不是 64 位元 x64。目前只提供 win-x64 版本。

注意事項
--------
* 只做靜態分析，不會執行你丟進去的程式。
* ZIP 與 ASAR 會在檔案數、大小和巢狀深度限制內安全展開；ASAR link 不會建立成系統連結，不完整的封存會在報告註明原因。
* 產生的 C# / C++ / Rust / Go 是「重建起點」，不保證能直接編譯或和原程式行為完全相同。
* 只有加上 --native 分析原生程式時才需要另外安裝 Ghidra。

專案首頁：https://github.com/NickYCLin/exe-blueprint
