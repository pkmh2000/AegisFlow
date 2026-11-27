# Changelog

## [1.0.0-beta.1] - 2026-11-26

### Beta Release Highlights
- **即時威脅偵測與 ML 流量分析**：6 維度網址特徵萃取與自動攔截判定，搭配伺服器端 Gemini AI 主動式修補建議。
- **Web3 加密貨幣錢包防護**：預檢 `Permit2`、`setApprovalForAll`、`approve` 無上限授權與 `eth_sign` 盲簽風險。
- **視覺化儀表板**：新增 Recharts 過去 7 天威脅攔截頻率趨勢折線圖、威脅地理分佈熱力圖、可自訂模組版面與新手防禦預設。
- **自動告警與警示音**：支援瀏覽器推播、多平台 Webhook 派送與 Web Audio API 嚴重威脅 (`critical`) 警報音效與試聽控制。
- **零信任控管與抗勒索備份**：HMAC-SHA256 記憶體工作階段驗證、Web Crypto AES-256-GCM + SHA-256 `.aegisvault` 離線加密備份還原。
- **PWA 與 GitHub Pages 靜態部署就緒**：支援 `VITE_BASE_PATH` 子路徑建置、自動產生 `404.html` 與 `.nojekyll`，並於無後端環境下切換本機端 ML 分析引擎。
