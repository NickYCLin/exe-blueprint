# 發佈新版本

GitHub Release 由版本 tag 觸發，產物會在 GitHub Actions 的乾淨 Windows 環境重新建置，不使用開發電腦上的既有檔案。

## 發佈前

1. 更新 `src/ExeBlueprint.Cli/ExeBlueprint.Cli.csproj` 的 `<Version>`。
2. 新增 `docs/releases/v<版本>.md`，用繁體中文寫這一版的功能、限制和使用提醒。
3. 執行完整驗證：

   ```powershell
   dotnet restore .\ExeBlueprint.slnx
   dotnet build .\ExeBlueprint.slnx -c Release --no-restore
   dotnet test .\ExeBlueprint.slnx -c Release --no-build
   ```

4. 提交並推送版本異動，確認 `main` 的 CI 通過。

## 建立 Release

版本號、tag 與版本說明檔名必須一致。例如 `0.2.0`：

```powershell
git tag -a v0.2.0 -m "chore(release): 發佈 v0.2.0"
git push origin v0.2.0
```

`.github/workflows/release.yml` 會依序：

- 確認 tag、專案版本與版本說明檔一致。
- 執行完整測試。
- 發佈 Windows x64 自包含單檔程式。
- 建立 EXE、ZIP 與 `SHA256SUMS.txt`。
- 建立或更新同名 GitHub Release。

若只是暫時性的網路或 GitHub 服務錯誤，可以重新執行原本的 workflow。若必須修改程式或 workflow，請提高修訂版號後建立新 tag；不要移動或刪掉已推送的版本 tag。
