# macOS DMG

v0.3.0 起，Release 提供 macOS Intel（`macos-x64.dmg`）與 Apple Silicon（`macos-arm64.dmg`）兩種磁碟映像，也保留 ZIP 版。套件包含 .NET runtime，不需要另外安裝。

## 安裝與更新

1. 依 Release 的 `SHA256SUMS.txt` 核對下載檔案，再開啟 DMG。
2. 將 `ExeBlueprint.app` 拖到映像內的 `Applications` 連結。
3. 退出磁碟映像，從「應用程式」開啟 ExeBlueprint。

更新前先結束程式，再用新版 `.app` 取代舊版。移除時將「應用程式」內的 `.app` 移到垃圾桶；儲存在其他位置的分析結果會保留。命令列版 `exe-blueprint-cli` 放在磁碟映像根目錄，可另外複製到自己的工具目錄。

目前沒有 Apple Developer 簽章與公證。DMG 格式本身不會改變 Gatekeeper 的判斷；首次開啟提示請參考 [Apple 的說明](https://support.apple.com/zh-tw/102445)。

## 建置

先在 macOS 準備與 Release 相同的 staging 目錄：

```text
stage/
  ExeBlueprint.app/Contents/Info.plist
  ExeBlueprint.app/Contents/MacOS/ExeBlueprint
  ExeBlueprint.app/Contents/MacOS/...
  exe-blueprint-cli
  README.txt
```

再執行以下命令，版本必須與 `Info.plist` 一致，架構可選 `x64` 或 `arm64`：

```bash
bash scripts/packaging/build-macos-dmg.sh stage artifacts/packages 0.3.0 arm64
```

腳本會檢查 bundle 版本及主程式／CLI 架構，用 `ditto` 保留 app bundle 內容，加入指向 `/Applications` 的連結，再以 `hdiutil` 建立壓縮唯讀映像。輸出檔已存在時會停止，不會覆寫。格式與複製方式依照 [Apple 的發佈封裝說明](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)。

## 自動驗收

`macOS installer` workflow 在 Intel 與 Apple Silicon runner 各自建置對應版本，驗證：

- `hdiutil verify` 成功，映像能唯讀掛載。
- `Applications` 是指向 `/Applications` 的連結。
- App 的 plist、版本、CPU 架構與執行權限正確；掛載後 CLI 的 `--version` 輸出符合版本。
- 掛載內容與原始 staging 檔案的 SHA-256、連結及執行權限一致。
- 用 `ditto` 複製到 runner 暫存目錄後，app bundle 的檔案仍逐一相符。

驗收不改動 runner 的 `/Applications`。DMG、`acceptance.json` 與操作 log 保留在 workflow artifact；Release workflow 也會執行相同驗收。

這些檢查涵蓋磁碟映像與複製流程，尚未驗證實際 Finder 拖曳、下載隔離標記、Gatekeeper 首次開啟或桌面程式啟動。`acceptance.json` 會以 `guiLaunchVerified: false` 明確記錄此範圍。
