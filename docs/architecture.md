# 架構說明

ExeBlueprint 把輸入端、分析流程和輸出端分開。新增一種語言時，不需要改寫整個工具。

```text
檔案／資料夾／ZIP
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

`ExeBlueprint.Core` 已包含輸入盤點、ZIP 安全解壓、檔案分類、PE／.NET 讀取、.NET 型別／欄位／屬性／方法抽取、方法層級呼叫圖、技術辨識、相依關係、報告產生，以及 .NET 型別的 C# 骨架產生。

`ExeBlueprint.Cli` 提供命令列入口，後續桌面版也會呼叫同一套核心。

## Blueprint 資料

目前 schema 版本是 `0.2`，主要欄位包括：

- `input`：輸入類型、檔案數與總大小
- `summary`：PE、assembly、型別、方法、資源和相依關係數量
- `files`：每個檔案的格式、雜湊和分析資料，受管組件另含 `code`
- `files[].code`：.NET 型別、欄位、屬性、方法簽章、入口點、方法層級呼叫圖與各方法反組譯出的 IL
- `dependencies`：PE imports 與 assembly references
- `technologies`：語言、runtime、框架和工具鏈判斷
- `warnings`：略過或無法分析的項目

後續加入 UI、資源和更細的控制流程時會再提升 schema 版本，舊欄位維持相容。

## 分析器分層

每種輸入會依序經過：

1. 通用檔案格式辨識
2. PE／managed metadata 分析
3. 語言或框架專用分析
4. 套件層級相依關係整理

不認得的 EXE 仍會保留通用 PE 結果，不會因缺少專用分析器而完全失敗。

## 易語言

易語言分析預計分成動態編譯和靜態編譯兩條路徑：

- 動態編譯：從 `krnln.fnr`、支持庫和 dispatcher 關係整理命令呼叫。
- 靜態編譯：以自建特徵資料辨識支持庫函式、視窗、控件和事件。

現階段只完成 runtime 與套件特徵辨識，還沒有還原 `.e` 工程。

## 專案重建與轉語言

重建器不會直接翻譯零碎的反編譯文字。它會先把函式、型別、呼叫、UI、資源和外部副作用整理成中介資料，再由目標語言產生器輸出專案。

目前已有第一個產生器 `CSharpSkeletonGenerator`，吃 `CodeModel` 輸出 C# 骨架：
還原命名空間、型別、欄位、屬性、方法簽章與繼承。方法體的部分，空方法與回傳常數／字串／null
這類簡單模式會直接還原成 C#，其餘方法把反組譯出的 IL 放進註解，方法體先用 `NotImplementedException`。
它證明了「中介模型 → 目標語言」這條路走得通，但複雜方法體、巢狀型別、事件與泛型限制都還沒處理，所以不保證可直接編譯。

第一批預定的輸出方向：

- .NET assembly → C# project
- 易語言／VB6／Delphi → C# Windows desktop project
- 原生 C／C++ → C-like project skeleton
- Blueprint → C#、C++、Rust

每個輸出項目都會標示 `confirmed`、`inferred` 或 `unknown`，並保留來源證據。
