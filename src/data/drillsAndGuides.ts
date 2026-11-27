import type { SecurityDrillScenario } from '../types/security';

export const SECURITY_DRILLS: SecurityDrillScenario[] = [
  {
    id: 'drill-sms-phish',
    title: '金融機構異常登入簡訊釣魚連結辨識',
    category: 'phishing',
    difficulty: '基礎',
    prompt: '您收到一則簡訊通知：「您的帳戶因異常跨境交易將於 2 小時內凍結，請立即點擊以下連結驗證身分。」請判斷應該採取何種處置？',
    artifactLabel: '簡訊內附連結',
    artifactContent: 'https://cathaybk-tw-verify.top/auth/session?token=9941a',
    options: [
      {
        id: 'a',
        label: '點擊連結並輸入網路銀行帳號密碼解除凍結',
        isCorrect: false,
        explanation: '該網域使用 .top 頂級網域且非銀行官方主網域 (cathaybk.com.tw)，屬於典型釣魚詐騙。',
      },
      {
        id: 'b',
        label: '立即攔截並封鎖該連結，改由官方 App 或手動輸入正確網址查核',
        isCorrect: true,
        explanation: '正確！AegisFlow ML 特徵分析也會偵測到非官方網域與緊急威嚇關鍵字而自動阻擋。',
      },
      {
        id: 'c',
        label: '將連結轉寄給同事請對方幫忙測試',
        isCorrect: false,
        explanation: '轉發未經隔離的惡意連結可能讓其他使用者暴露於釣魚或瀏覽器漏洞風險。',
      },
    ],
    remediationTip: '遇到任何要求緊急驗證帳密的簡訊或電子郵件，務必透過 AegisFlow 連結掃描器檢驗，並由官方書籤進入服務。',
  },
  {
    id: 'drill-web3-permit',
    title: '惡意 NFT 空投與 Permit2 簽名陷阱',
    category: 'wallet_drainer',
    difficulty: '進階',
    prompt: '一個標榜「限時領取 2,500 USDC 空投」的網站要求您連接錢包，並跳出以下簽名視窗，您應如何處置？',
    artifactLabel: '錢包簽名請求摘要',
    artifactContent: 'dApp: https://uniswap-claim-bonus.xyz | Method: Permit2.permitBatch | Spender: 0x9fE4...8821 | Amount: Unlimited (2^256-1)',
    options: [
      {
        id: 'a',
        label: '因為沒有顯示 Gas 費用，代表只是免費登入驗證，直接簽署',
        isCorrect: false,
        explanation: 'Permit2 離線簽章不需要當場支付 Gas，但一旦簽署即允許惡意合約於背景直接轉走所有授權代幣。',
      },
      {
        id: 'b',
        label: '拒絕簽署並透過 Web3 錢包防護將該網域加入黑名單',
        isCorrect: true,
        explanation: '正確！無上限額度 (2^256-1) 搭配仿冒 .xyz 網域是典型的 Wallet Drainer 抽乾手法。',
      },
      {
        id: 'c',
        label: '切換到測試鏈網路後再簽署領取',
        isCorrect: false,
        explanation: '部分惡意網頁會透過 RPC 切換回主網或誘騙盲簽 eth_sign，應直接拒絕並關閉分頁。',
      },
    ],
    remediationTip: '啟用 AegisFlow「Web3 錢包無上限授權攔截」零信任原則，所有 Permit2 與 setApprovalForAll 簽章都應經過人類可讀審計。',
  },
  {
    id: 'drill-trojan-update',
    title: '偽裝瀏覽器緊急安全更新木馬載荷',
    category: 'trojan',
    difficulty: '進階',
    prompt: '瀏覽外部論壇時突然跳出全螢幕提示「Chrome 憑證過期，請下載更新檔」，自動開始下載以下檔案，應如何應對？',
    artifactLabel: '攔截到的下載來源',
    artifactContent: 'http://198.51.100.77:8443/patch/BrowserSecurityUpdate.exe (未經數位簽章)',
    options: [
      {
        id: 'a',
        label: '直接執行安裝檔以確保瀏覽器安全',
        isCorrect: false,
        explanation: '真正的瀏覽器更新不會透過外部網頁以裸 IP 與 .exe 執行檔方式分發，這是典型的木馬滲透手法。',
      },
      {
        id: 'b',
        label: '中止下載、刪除暫存檔，並於日誌溯源中心封鎖來源 IP 與通訊埠',
        isCorrect: true,
        explanation: '正確！採用未加密 HTTP 裸 IP 與非常規埠 :8443 下載可執行檔，屬於極高風險木馬行為。',
      },
      {
        id: 'c',
        label: '先上傳到雲端硬碟備份，晚點再執行',
        isCorrect: false,
        explanation: '保留惡意可執行檔於同步雲端硬碟可能導致其他跨平台裝置誤觸執行。',
      },
    ],
    remediationTip: '在零信任原則中啟用「未知可執行檔隔離」，僅允許透過作業系統官方商店或已驗證簽章的管道更新軟體。',
  },
  {
    id: 'drill-ransomware-containment',
    title: '疑似勒索軟體異常加密行為緊急應變',
    category: 'ransomware_c2',
    difficulty: '專家',
    prompt: '端點監控系統告警：工作站背景程序在 10 秒內連續修改 300 份文件副檔名為 .locked，並嘗試連線未知 C2 位址。第一步應做什麼？',
    artifactLabel: '端點行為告警',
    artifactContent: 'Host: WS-FIN-04 | Process: svchost_tmp.exe | Outbound: 45.142.122.91:4444 | Disk I/O: 410 MB/s',
    options: [
      {
        id: 'a',
        label: '立即中斷網路連線防止橫向擴散與金鑰回傳，並保留現場與離線加密備份還原',
        isCorrect: true,
        explanation: '正確！斷網可阻斷 C2 通訊與內網 SMB 橫向感染，並確保 AegisFlow AES-256 離線加密快照可用於乾淨還原。',
      },
      {
        id: 'b',
        label: '重新開機看檔案是否會恢復正常',
        isCorrect: false,
        explanation: '重新開機可能觸發開機磁區鎖定或清除記憶體中的鑑識線索。',
      },
      {
        id: 'c',
        label: '將還原用的外接備份硬碟直接插上受感染電腦檢查檔案',
        isCorrect: false,
        explanation: '將備份媒體直接連接受感染主機，會導致勒索軟體連同備份一起加密銷毀！',
      },
    ],
    remediationTip: '定期將重要設定與日誌匯出為離線不可變 `.aegisvault` 加密快照，並保存於氣隙 (Air-gapped) 儲存空間。',
  },
];

export const OFFLINE_RISK_GUIDES = [
  {
    id: 'guide-phishing',
    title: '釣魚連結與雙重混淆網域評估指南',
    severity: 'high' as const,
    summary: '識別偽造登入頁面、Punycode 國際化網域仿冒與開放式轉址攻擊鏈。',
    indicators: [
      '網域包含異常連字號、數字序列或 .xyz / .top / .icu 等高風險免費頂級網域',
      'URL 含有 @ 符號或 redirect=http 參數，企圖繞過視覺檢查',
      '缺乏有效 HTTPS TLS 憑證或使用自簽憑證',
    ],
    actions: [
      '立即透過 AegisFlow 阻斷該主機名稱並清除受影響瀏覽器的工作階段 Cookie',
      '若已不慎輸入憑證，優先於獨立乾淨裝置更換密碼並撤銷既有登入工作階段',
      '將事件雜湊與來源 IP 透過開源 API 同步至組織防禦清單',
    ],
  },
  {
    id: 'guide-web3',
    title: 'Web3 錢包授權保護與合約撤銷程序',
    severity: 'critical' as const,
    summary: '防範假空投網站誘導簽署 Unlimited Approve、setApprovalForAll 與 Permit2 盲簽。',
    indicators: [
      '簽名彈窗出現 eth_sign 警告或十六進位不可讀雜湊',
      '授權額度為 Unlimited / 2^256-1，且 Spender 地址未通過區塊鏈瀏覽器驗證',
      '網域模仿知名 DeFi/NFT 品牌並要求「緊急同步節點」或輸入助記詞',
    ],
    actions: [
      '任何正常 dApp 永遠不會要求輸入助記詞 (Seed Phrase)，遇見即為 100% 詐騙',
      '立即中斷該 dApp 錢包連線並撤銷異常合約的代幣授權額度',
      '將主要資產轉移至未曾互動過不明合約的硬體隔離錢包',
    ],
  },
  {
    id: 'guide-ransomware',
    title: '木馬與勒索軟體中斷隔離及快照復原',
    severity: 'critical' as const,
    summary: '遭遇惡意執行檔滲透或檔案異常加密時的零信任隔離與離線還原作業。',
    indicators: [
      '不明來源可執行檔 (.exe / .ps1 / .scr / .apk) 嘗試自裸 IP 或非常規埠下載',
      '短時間內出現大量檔案重新命名、高磁碟寫入與對外可疑 C2 連線',
      '防毒軟體或系統還原點服務遭異常停用',
    ],
    actions: [
      '立即關閉 Wi-Fi 與拔除網路線，阻斷惡意程式橫向移動與資料外洩',
      '切勿將離線加密備份隨身碟直接插入尚未重灌確認乾淨的裝置',
      '於乾淨系統重新匯入 AegisFlow `.aegisvault` 離線快照並驗證 SHA-256 校驗碼',
    ],
  },
];
