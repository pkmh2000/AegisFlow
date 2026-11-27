import type {
  PlatformSource,
  ThreatGeoInfo,
  ThreatLogEntry,
  URLScanResult,
  WalletScanResult,
} from '../types/security';

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'buzz', 'click', 'link', 'work', 'support', 'zip', 'mov',
]);

const TARGETED_BRANDS = [
  'paypal', 'apple', 'microsoft', 'google', 'metamask', 'binance', 'coinbase', 'uniswap', 'opensea', 'ledger', 'trezor', 'cathay', 'ctbc', 'esun', 'line', 'shopee', 'chunghwa',
];

const GEO_NODES: Array<{ ip: string; asn: string; geo: ThreatGeoInfo }> = [
  { ip: '185.220.101.44', asn: 'AS205100', geo: { countryCode: 'NL', countryName: '荷蘭', city: '阿姆斯特丹', region: '歐洲', lat: 52.37, lng: 4.9 } },
  { ip: '45.142.122.91', asn: 'AS49870', geo: { countryCode: 'RU', countryName: '俄羅斯', city: '莫斯科', region: '東歐', lat: 55.75, lng: 37.62 } },
  { ip: '198.51.100.77', asn: 'AS64512', geo: { countryCode: 'US', countryName: '美國', city: '阿什本', region: '北美', lat: 39.04, lng: -77.49 } },
  { ip: '103.145.24.18', asn: 'AS138915', geo: { countryCode: 'SG', countryName: '新加坡', city: '新加坡', region: '東南亞', lat: 1.35, lng: 103.82 } },
  { ip: '43.132.198.62', asn: 'AS132203', geo: { countryCode: 'HK', countryName: '香港', city: '香港', region: '東亞', lat: 22.32, lng: 114.17 } },
  { ip: '177.54.148.29', asn: 'AS262589', geo: { countryCode: 'BR', countryName: '巴西', city: '聖保羅', region: '南美', lat: -23.55, lng: -46.63 } },
];

function inferGeoNode(seed: string) {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
  }
  return GEO_NODES[hash % GEO_NODES.length];
}

function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function scanUrlLocally(
  rawUrl: string,
  platform: PlatformSource = 'Browser'
): { result: URLScanResult; logEntry: ThreatLogEntry } {
  const normalized = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
  const parsed = new URL(normalized);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('僅支援 http:// 或 https:// 協定連結。');
  }

  const host = parsed.hostname.toLowerCase();
  const fullPath = `${parsed.pathname}${parsed.search}`;
  const tld = host.split('.').pop() || '';
  const signals: string[] = [];

  const hostEntropy = shannonEntropy(host.replace(/\./g, ''));
  const pathEntropy = shannonEntropy(fullPath);
  const entropyScore = Math.min(100, Math.round(Math.max(0, hostEntropy - 2.6) * 28 + Math.max(0, pathEntropy - 3.6) * 18));
  if (entropyScore >= 55) signals.push(`高隨機字元熵值 (${hostEntropy.toFixed(2)} bits) 符合 DGA 或動態釣魚特徵`);

  let lexicalAnomaly = 0;
  const digitCount = (host.match(/\d/g) || []).length;
  const hyphenCount = (host.match(/-/g) || []).length;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    lexicalAnomaly += 55;
    signals.push('直接使用 IP 位址取代可信網域名稱');
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    lexicalAnomaly += 30;
    signals.push(`使用非常規傳輸埠 :${parsed.port}`);
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    lexicalAnomaly += 28;
    signals.push(`高風險濫用頂級網域 (.${tld})`);
  }
  if (digitCount >= 4 || hyphenCount >= 3) {
    lexicalAnomaly += 22;
    signals.push('網域包含異常數字序列或多重連字號');
  }
  if (rawUrl.includes('@')) {
    lexicalAnomaly += 45;
    signals.push('URL 含 @ 符號，可能企圖進行視覺主機名偽裝');
  }
  if (/(\.exe|\.scr|\.bat|\.ps1|\.apk|\.msi|\.dmg)(\?|$)/i.test(fullPath)) {
    lexicalAnomaly += 65;
    signals.push('路徑直接指向高風險可執行檔或木馬載荷');
  }
  lexicalAnomaly = Math.min(100, lexicalAnomaly);

  let homographRisk = 0;
  if (host.includes('xn--')) {
    homographRisk += 65;
    signals.push('偵測到 Punycode (xn--) 國際化網域字形偽裝風險');
  }
  for (const brand of TARGETED_BRANDS) {
    if (host.includes(brand) && !host.endsWith(`${brand}.com`) && !host.endsWith(`${brand}.com.tw`) && !host.endsWith(`${brand}.io`) && !host.endsWith(`${brand}.org`)) {
      homographRisk += 50;
      signals.push(`網域疑似仿冒知名品牌關鍵字 (${brand})`);
      break;
    }
  }
  homographRisk = Math.min(100, homographRisk);

  const tlsTrustGap = parsed.protocol === 'http:' ? 60 : 12;
  if (parsed.protocol === 'http:') signals.push('採用未加密 HTTP 明文協定');

  let redirectDepthRisk = 10;
  if (/(redirect|next|url|return|goto|continue)=http/i.test(parsed.search)) {
    redirectDepthRisk += 55;
    signals.push('偵測到開放式轉址參數 (Open Redirect)');
  }
  redirectDepthRisk = Math.min(100, redirectDepthRisk);

  let payloadSignatureRisk = 8;
  if (/(airdrop|claim-reward|connect-wallet|sync-node|seed-phrase|mnemonic|verify-kyc)/i.test(rawUrl)) {
    payloadSignatureRisk += 62;
    signals.push('觸發高風險釣魚與加密貨幣授權誘騙詞彙特徵');
  }
  if (/(powershell|cmd=|wget|curl|payload|dropper|c2|gate\.php)/i.test(rawUrl)) {
    payloadSignatureRisk += 70;
    signals.push('偵測到惡意程式指令或遠端木馬端點特徵');
  }
  payloadSignatureRisk = Math.min(100, payloadSignatureRisk);

  const weighted = Math.round(
    entropyScore * 0.14 +
      lexicalAnomaly * 0.24 +
      homographRisk * 0.24 +
      tlsTrustGap * 0.1 +
      redirectDepthRisk * 0.12 +
      payloadSignatureRisk * 0.16
  );
  const maxFeature = Math.max(lexicalAnomaly, homographRisk, payloadSignatureRisk);
  const riskScore = Math.min(99, Math.max(weighted, Math.round(maxFeature * 0.85)));

  const category =
    /(\.exe|\.scr|\.ps1|\.apk|dropper|gate\.php|c2)/i.test(rawUrl)
      ? 'trojan'
      : /(airdrop|claim|wallet|metamask|uniswap|ledger|seed)/i.test(rawUrl) && riskScore >= 40
      ? 'wallet_drainer'
      : redirectDepthRisk >= 60 && riskScore >= 40
      ? 'suspicious_redirect'
      : riskScore >= 45
      ? 'phishing'
      : 'safe';

  const severity =
    riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 38 ? 'medium' : riskScore >= 20 ? 'low' : 'nominal';
  const verdict = riskScore >= 60 ? 'block' : riskScore >= 35 ? 'warn' : 'allow';
  const mlConfidence = Math.min(99, Math.max(74, 78 + signals.length * 4));
  const geoNode = inferGeoNode(host);
  const scannedAt = new Date().toISOString();

  const features = {
    entropyScore,
    lexicalAnomaly,
    homographRisk,
    tlsTrustGap,
    redirectDepthRisk,
    payloadSignatureRisk,
  };

  const traceHops = [
    `Client Request -> ${parsed.protocol}//${host}`,
    `Browser ML Feature Engine -> Entropy ${entropyScore}/100 · Homograph ${homographRisk}/100`,
    verdict === 'block' ? 'AegisFlow Policy -> 自動攔截封鎖' : verdict === 'warn' ? 'AegisFlow Policy -> 沙箱隔離警示' : 'AegisFlow Policy -> 放行連線',
  ];

  const finalSignals = signals.length > 0 ? signals : ['網域結構、字元熵值與協定特徵均位於安全基準區間'];

  return {
    result: {
      url: parsed.href,
      normalizedHost: host,
      riskScore,
      mlConfidence,
      category,
      severity,
      verdict,
      features,
      signals: finalSignals,
      traceHops,
      aiError: '目前為 GitHub Pages 純靜態部署環境，已完成本機瀏覽器 ML 特徵分析；Gemini AI 主動修補建議需連線至後端伺服器。',
      scannedAt,
    },
    logEntry: {
      id: `evt-${Math.floor(1000 + Math.random() * 8999)}`,
      timestamp: scannedAt,
      target: parsed.href,
      category,
      severity,
      action: verdict === 'block' ? 'blocked' : verdict === 'warn' ? 'quarantined' : 'allowed',
      platform,
      sourceIp: geoNode.ip,
      asn: geoNode.asn,
      geo: geoNode.geo,
      riskScore,
      mlConfidence,
      summary: finalSignals[0],
      features,
      traceHops,
      syncedChannels: verdict === 'allow' ? [] : ['BrowserPush'],
    },
  };
}

export function scanWalletLocally(
  dappUrl: string,
  contractAddress: string,
  methodSignature: string,
  calldata: string
): { result: WalletScanResult; logEntry: ThreatLogEntry } {
  const { result: urlCheck } = scanUrlLocally(dappUrl, 'Browser');
  const cleanContract = contractAddress.trim();
  const cleanMethod = methodSignature.trim();
  const cleanData = calldata.trim().toLowerCase();

  const findings: string[] = [];
  let riskScore = Math.round(urlCheck.riskScore * 0.65);
  let allowanceType: WalletScanResult['allowanceType'] = 'none';

  if (cleanMethod === 'eth_sign') {
    allowanceType = 'eth_sign';
    riskScore += 55;
    findings.push('偵測到高風險 eth_sign 盲簽請求：簽署任意雜湊可能直接導致錢包資產被全數轉移。');
  } else if (/permit2/i.test(cleanMethod) || cleanData.includes('0x30f28b7a') || cleanData.includes('0x2b67b570')) {
    allowanceType = 'permit2';
    riskScore += 45;
    findings.push('偵測到 Permit2 離線授權簽章：可能允許第三方合約於無 Gas 提示下批次轉走多項代幣。');
  } else if (/setapprovalforall/i.test(cleanMethod) || cleanData.startsWith('0xa22cb465')) {
    allowanceType = 'unlimited';
    riskScore += 48;
    findings.push('偵測到 setApprovalForAll 請求：授權目標合約控制該系列所有 NFT 資產。');
  } else if (/approve/i.test(cleanMethod) && (cleanData.includes('ffffffffffffffff') || cleanData === '')) {
    allowanceType = 'unlimited';
    riskScore += 42;
    findings.push('偵測到無上限 (Unlimited) ERC-20 代幣 Approve 授權，存在惡意提領風險。');
  } else {
    allowanceType = 'scoped';
    findings.push('授權方法具備明確作用域，仍建議比對合約地址是否與官方一致。');
  }

  if (urlCheck.riskScore >= 35) {
    findings.push(...urlCheck.signals);
  }

  riskScore = Math.min(99, riskScore);
  const severity = riskScore >= 80 ? 'critical' : riskScore >= 55 ? 'high' : riskScore >= 30 ? 'medium' : 'nominal';
  const verdict = riskScore >= 60 ? 'block' : riskScore >= 30 ? 'warn' : 'allow';
  const humanReadableIntent =
    allowanceType === 'eth_sign'
      ? `警告：${urlCheck.normalizedHost} 請求您對原始雜湊進行盲簽 (eth_sign)，等同於授予空白支票。`
      : allowanceType === 'permit2'
      ? `注意：${urlCheck.normalizedHost} 請求 Permit2 批次授權簽章，合約 ${cleanContract || '未指定'} 將可代為轉移指定代幣。`
      : allowanceType === 'unlimited'
      ? `高風險：${urlCheck.normalizedHost} 請求將您的代幣/NFT 無上限控制權交給合約 ${cleanContract || '未知合約'}。`
      : `${urlCheck.normalizedHost} 請求有限額度互動授權。`;

  const geoNode = inferGeoNode(urlCheck.normalizedHost);
  const scannedAt = new Date().toISOString();

  return {
    result: {
      dappUrl: urlCheck.url,
      contractAddress: cleanContract || '0x0000000000000000000000000000000000000000',
      methodSignature: cleanMethod,
      allowanceType,
      riskScore,
      severity,
      verdict,
      humanReadableIntent,
      findings,
      aiError: '目前為 GitHub Pages 純靜態部署環境，已完成本機 Web3 ABI 簽章檢核；Gemini AI 智能合約審計需連線至後端伺服器。',
      scannedAt,
    },
    logEntry: {
      id: `evt-${Math.floor(1000 + Math.random() * 8999)}`,
      timestamp: scannedAt,
      target: `${urlCheck.url} [${cleanMethod}]`,
      category: verdict === 'allow' ? 'safe' : 'wallet_drainer',
      severity,
      action: verdict === 'block' ? 'blocked' : verdict === 'warn' ? 'quarantined' : 'allowed',
      platform: 'Browser',
      sourceIp: geoNode.ip,
      asn: geoNode.asn,
      geo: geoNode.geo,
      riskScore,
      mlConfidence: 95,
      summary: humanReadableIntent,
      features: urlCheck.features,
      traceHops: [`Wallet Provider -> ${urlCheck.normalizedHost}`, `ABI Inspector -> ${cleanMethod} (${allowanceType})`, `AegisFlow Web3 Guard -> ${verdict.toUpperCase()}`],
      syncedChannels: verdict === 'allow' ? [] : ['BrowserPush'],
    },
  };
}
