# 內嵌圖片的檔頭摘要

從 schema `0.19` 起，支援的 `.resources` 項目可附上 `imageHeader`，列出 PNG 或 GIF 的格式、尺寸及檔頭錯誤。這些資訊可協助盤點重建介面所需的素材。

適用來源：

- 標準 `ResourceTypeCode.ByteArray` 與 `ResourceTypeCode.Stream`。
- 預序列化資源的 TypeConverter byte array 與 Activator stream payload。

解析依實際位元組判斷，不依資源名稱或宣告型別猜測。BinaryFormatter 物件不會進入圖片解析；一般獨立 manifest 圖片與其他圖片格式尚未納入。

| 欄位 | 說明 |
| --- | --- |
| `format` | `png` 或 `gif` |
| `status` | `parsed` 表示已讀取並檢查支援的檔頭欄位；`invalid` 表示檔頭不完整或欄位無效 |
| `width`、`height` | 像素尺寸。GIF 是 logical screen 的畫布大小，不是個別動畫影格 |
| `error` | 檔頭失敗原因；失敗時不提供寬高 |

沒有 `imageHeader` 只代表沒有可辨識的 PNG／GIF 檔頭，不代表資源不是圖片。

PNG 只讀取 33 bytes，檢查完整 signature、第一個 IHDR 的類型與長度、IHDR CRC、寬高、色彩與位元深度的有效組合，以及壓縮、filter 和交錯欄位。格式依據為 [W3C PNG 規格](https://www.w3.org/TR/png-3/#11IHDR)。

GIF 只讀取 13 bytes，辨識 GIF87a／GIF89a 與非零畫布尺寸；欄位依據為 [GIF89a 規格](https://www.w3.org/Graphics/GIF/spec-gif89a.txt)。

解析器不解壓像素、不讀取 EXIF 或文字中繼資料，不使用影像解碼器，也不建立 TypeConverter、Activator 或資源物件。檔頭尺寸即使很大，也不會依尺寸配置記憶體。讀出檔頭不代表完整圖片、像素或動畫影格已通過驗證；Markdown 報告會直接註明這項限制。

資源項目原本的 `status` 與 `serialization.complete` 保留原意。例如，完整的預序列化 envelope 可以包含損壞的圖片檔頭，此時 envelope 仍完整，但 `imageHeader.status` 會是 `invalid`。
