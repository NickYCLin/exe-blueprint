# Windows 安裝程式

Windows x64 桌面版可打包成 `ExeBlueprint-v<版本>-win-x64-setup.exe`。ZIP 免安裝版仍會保留，安裝程式從下一次版本發布起加入 Release。

安裝精靈提供繁體中文與英文，預設安裝到目前使用者的 `%LOCALAPPDATA%\Programs\ExeBlueprint`，不需要系統管理員權限。開始功能表會加入 ExeBlueprint；桌面捷徑可自行勾選。桌面版與 CLI 都已包含 .NET runtime。

執行新版安裝程式會更新同一份安裝。可由 Windows「已安裝的應用程式」移除；移除只處理安裝程式放入的檔案，使用者自行放入的檔案和其他位置的分析結果會保留。

目前沒有 Windows 程式碼簽章。安裝版與 ZIP 版的簽章狀態相同，請依 Release 的 SHA-256 核對下載檔案。

## 建置

在 Windows 準備 .NET 10 SDK 與 Inno Setup 6.3 以上，再執行：

```powershell
./scripts/packaging/Build-WindowsInstaller.ps1 -OutputDirectory ./artifacts/windows-setup
```

腳本會 publish Windows x64 桌面版與 CLI、檢查必要檔案，再編譯安裝程式。若編譯器不在預設位置，可用 `-CompilerPath` 指定 `ISCC.exe`；已備妥 Release 檔案時可用 `-StageDirectory` 指定目錄。輸出檔案已存在時會停止，請改用新的輸出目錄。

繁體中文語系取自 Inno Setup 官方 repository 的固定版本，下載後會核對 SHA-256。語系和中間產物不會加入 Release 附件。

## 自動驗收

`Windows installer` workflow 使用 GitHub Windows runner 既有的 Inno Setup。每次相關 PR 與 main 更新會建置安裝程式，再於 runner 的暫存目錄驗證：

1. 初次安裝：版本登錄與開始功能表捷徑存在。
2. 升級：以同一份程式檔案、`0.0.0` 安裝版本模擬既有安裝，確認新版更新版本登錄與被改動的檔案；逐一比對安裝檔案 SHA-256。
3. CLI：執行安裝後的 `--version`，核對實際輸出。
4. 移除：登錄、捷徑和安裝檔案都移除；自行加入的測試檔案仍存在。

這項測試驗證安裝流程，不代表舊版應用程式資料遷移或所有 Windows 環境均已驗收。測試腳本只允許在 GitHub Actions runner 執行，避免影響開發者的既有安裝。安裝程式、三份操作 log 與 `acceptance.json` 會保留在 workflow artifact；Release workflow 也會先通過相同驗收才發布附件。
