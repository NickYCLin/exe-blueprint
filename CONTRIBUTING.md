# 參與開發

## 開始前

```powershell
dotnet restore .\ExeBlueprint.slnx
dotnet test .\ExeBlueprint.slnx -c Release
```

不要把待分析的 EXE、DLL、客戶資料或反編譯結果提交到 repository。

## Commit message

格式依照 [Git Commit Message 這樣寫會更好](https://ithelp.ithome.com.tw/articles/10228738)：

```text
<type>(<scope>): <subject>

<body>

<footer>
```

規則：

- `type` 必填，可用 `feat`、`fix`、`docs`、`style`、`refactor`、`perf`、`test`、`chore`、`revert`
- `scope` 選填，用來標示影響範圍
- `subject` 使用繁體中文，不超過 50 個字，結尾不加句號
- 標題和內文之間留一行空白
- 內文每行盡量不超過 72 個字元
- 內文交代為什麼要改，以及實際改了什麼
- 有 issue 時在 footer 加上編號

範例：

```text
feat(analyzer): 新增易語言套件辨識

需要先分辨動態與靜態編譯結果，才能選擇後續分析器。

調整內容：
- 辨識 krnln.fnr 與常見支持庫副檔名
- 在報告中附上判斷依據與可信度

issue #12
```

可以把 repository 內的 `.gitmessage.txt` 設為本機模板：

```powershell
git config commit.template .gitmessage.txt
```
