ExeBlueprint 桌面版
===================

這個套件同時放了圖形介面與命令列版本，不需要另外安裝 .NET。

Windows
-------
雙擊 ExeBlueprint.exe 開啟圖形介面。
命令列版本是 exe-blueprint-cli.exe。

macOS
-----
雙擊 ExeBlueprint.app 開啟圖形介面。
這一版尚未經 Apple Developer 簽章與公證。第一次開啟若被擋住，請在 Finder 對
ExeBlueprint.app 按右鍵，選「打開」，再確認一次。
命令列版本是 exe-blueprint-cli。

Linux
-----
在桌面環境執行 ExeBlueprint；命令列版本是 exe-blueprint-cli。
若系統沒有保留執行權限，可執行：

  chmod +x ExeBlueprint exe-blueprint-cli

Ubuntu／Debian 若缺少圖形介面函式庫，可安裝：

  sudo apt install libx11-6 libice6 libsm6 libfontconfig1

使用提醒
--------
- 程式只做靜態分析，不會執行你選擇的程式或封存內容。
- 目前分析對象是 Windows EXE、DLL、資料夾、ZIP 與 Electron ASAR；圖形介面本身可在三種桌面系統執行。
- ZIP 與 ASAR 會在檔案數、大小和巢狀深度限制內安全展開；ASAR link 不會建立成系統連結，不完整的封存會在報告註明原因。
- Windows 與 macOS 版本目前都沒有商業程式碼簽章，請只從本專案 GitHub Releases 下載。
- SHA256SUMS.txt 可用來確認下載檔案是否完整。
- 只分析自己擁有或已獲授權的程式。

命令列範例
----------
Windows：

  .\exe-blueprint-cli.exe analyze .\MyApplication.exe -o .\report

macOS／Linux：

  ./exe-blueprint-cli analyze ./MyApplication.exe -o ./report
