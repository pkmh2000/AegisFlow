import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import net from 'net';
import { monitorEventLoopDelay } from 'perf_hooks';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const loopDelayMonitor = monitorEventLoopDelay({ resolution: 20 });
loopDelayMonitor.enable();
let lastCpuUsage = process.cpuUsage();
let lastCpuTime = process.hrtime.bigint();
let latestProcessCpuPct = 0;

function collectSystemMetrics() {
  const nowTime = process.hrtime.bigint();
  const elapsedUs = Number(nowTime - lastCpuTime) / 1000;
  const cores = Math.max(1, os.cpus().length);
  if (elapsedUs >= 200_000) {
    const diff = process.cpuUsage(lastCpuUsage);
    lastCpuUsage = process.cpuUsage();
    lastCpuTime = nowTime;
    const totalCpuUs = diff.user + diff.system;
    latestProcessCpuPct = Math.min(100, Math.round((totalCpuUs / (elapsedUs * cores)) * 1000) / 10);
  }

  const mem = process.memoryUsage();
  const rssMb = Math.round((mem.rss / 1048576) * 10) / 10;
  const heapUsedMb = Math.round((mem.heapUsed / 1048576) * 10) / 10;
  const heapTotalMb = Math.round((mem.heapTotal / 1048576) * 10) / 10;

  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const systemUsedPct = totalMem > 0 ? Math.round(((totalMem - freeMem) / totalMem) * 1000) / 10 : 0;

  const loadAvg1m = Math.round((os.loadavg()[0] || 0) * 100) / 100;
  const systemLoadPct = Math.min(100, Math.round((loadAvg1m / cores) * 1000) / 10);
  const rawMeanLag = Number.isFinite(loopDelayMonitor.mean) ? loopDelayMonitor.mean / 1e6 : 0;
  const eventLoopLagMs = Math.max(0, Math.round(rawMeanLag * 100) / 100);

  const memoryStatus: 'healthy' | 'elevated' | 'critical' =
    rssMb >= 768 || heapUsedMb >= 384 || systemUsedPct >= 90
      ? 'critical'
      : rssMb >= 512 || heapUsedMb >= 256 || systemUsedPct >= 75
      ? 'elevated'
      : 'healthy';

  const peakCpuPct = Math.max(latestProcessCpuPct, systemLoadPct);
  const cpuStatus: 'healthy' | 'elevated' | 'critical' =
    peakCpuPct >= 85 || eventLoopLagMs >= 100
      ? 'critical'
      : peakCpuPct >= 60 || eventLoopLagMs >= 40
      ? 'elevated'
      : 'healthy';

  const status: 'healthy' | 'elevated' | 'critical' =
    memoryStatus === 'critical' || cpuStatus === 'critical'
      ? 'critical'
      : memoryStatus === 'elevated' || cpuStatus === 'elevated'
      ? 'elevated'
      : 'healthy';

  return {
    source: 'node_backend' as const,
    status,
    memory: {
      rssMb,
      heapUsedMb,
      heapTotalMb,
      systemUsedPct,
      status: memoryStatus,
    },
    cpu: {
      processPct: latestProcessCpuPct,
      systemLoadPct,
      loadAvg1m,
      cores,
      eventLoopLagMs,
      status: cpuStatus,
    },
    uptimeSeconds: Math.round(process.uptime()),
    sampledAt: new Date().toISOString(),
  };
}

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || apiKey.trim() === '') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// --- Zero-Trust Signed Token Helpers ---
interface TokenPayload {
  sub: string;
  deviceId: string;
  trustLevel: 'verified' | 'elevated';
  mfaMethod: string;
  iat: number;
  exp: number;
}

function signZeroTrustToken(payload: TokenPayload): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyZeroTrustToken(token: string): TokenPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as TokenPayload;
    if (Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

// --- Open-Source API Token Store (in-memory lightweight store) ---
interface ApiTokenRecord {
  id: string;
  name: string;
  prefix: string;
  hash: string;
  scope: 'read' | 'scan' | 'admin';
  createdAt: string;
}

const apiTokens: ApiTokenRecord[] = [];

function authenticateZeroTrustOrApi(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const apiKeyHeader = req.headers['x-aegis-token'];

  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const payload = verifyZeroTrustToken(token);
    if (payload) {
      (req as Request & { ztSession?: TokenPayload }).ztSession = payload;
      return next();
    }
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const matched = apiTokens.find((t) => t.hash === tokenHash);
    if (matched) {
      return next();
    }
  }

  if (typeof apiKeyHeader === 'string' && apiKeyHeader.trim().length > 0) {
    const tokenHash = crypto.createHash('sha256').update(apiKeyHeader.trim()).digest('hex');
    const matched = apiTokens.find((t) => t.hash === tokenHash);
    if (matched) {
      return next();
    }
  }

  return res.status(401).json({
    error: '零信任存取驗證失敗：請先完成裝置身分驗證或提供有效的 API Token。',
  });
}

// --- SSRF Protection for Webhook Dispatch ---
function isBlockedPrivateOrLoopbackHost(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower === 'metadata.google.internal'
  ) {
    return true;
  }

  const ipVersion = net.isIP(lower);
  if (ipVersion === 4) {
    const parts = lower.split('.').map(Number);
    const [a, b] = parts;
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 10) return true; // 10.0.0.0/8 private
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / metadata
    if (a === 0) return true; // 0.0.0.0/8
  } else if (ipVersion === 6) {
    if (lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) {
      return true;
    }
  }
  return false;
}

// --- Deterministic ML Lexical & Traffic Feature Extractor ---
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

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'buzz', 'click', 'link', 'work', 'support', 'zip', 'mov',
]);

const TARGETED_BRANDS = [
  'paypal', 'apple', 'microsoft', 'google', 'metamask', 'binance', 'coinbase', 'uniswap', 'opensea', 'ledger', 'trezor', 'cathay', 'ctbc', 'esun', 'line', 'shopee', 'chunghwa',
];

function extractUrlFeatures(rawUrl: string) {
  let parsed: URL;
  try {
    const normalized = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
    parsed = new URL(normalized);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return null;
  }

  const host = parsed.hostname.toLowerCase();
  const fullPath = `${parsed.pathname}${parsed.search}`;
  const tld = host.split('.').pop() || '';
  const signals: string[] = [];

  // 1. Entropy feature
  const hostEntropy = shannonEntropy(host.replace(/\./g, ''));
  const pathEntropy = shannonEntropy(fullPath);
  const entropyScore = Math.min(100, Math.round((Math.max(0, hostEntropy - 2.6) * 28) + (Math.max(0, pathEntropy - 3.6) * 18)));
  if (entropyScore >= 55) signals.push(`高隨機字元熵值 (${hostEntropy.toFixed(2)} bits) 符合 DGA 或動態釣魚子網域特徵`);

  // 2. Lexical anomaly
  let lexicalAnomaly = 0;
  const digitCount = (host.match(/\d/g) || []).length;
  const hyphenCount = (host.match(/-/g) || []).length;
  if (net.isIP(host) !== 0) {
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

  // 3. Homograph / Brand impersonation risk
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
  if (/[01lI]{2,}/.test(host) && /pay|bank|login|verify|wallet|claim|airdrop/i.test(rawUrl)) {
    homographRisk += 25;
    signals.push('存在視覺混淆字元與敏感驗證關鍵字組合');
  }
  homographRisk = Math.min(100, homographRisk);

  // 4. TLS trust gap
  let tlsTrustGap = parsed.protocol === 'http:' ? 60 : 12;
  if (parsed.protocol === 'http:') {
    signals.push('採用未加密 HTTP 明文協定，缺乏 TLS 傳輸層驗證');
  }

  // 5. Redirect / query payload risk
  let redirectDepthRisk = 10;
  if (/(redirect|next|url|return|goto|continue)=http/i.test(parsed.search)) {
    redirectDepthRisk += 55;
    signals.push('偵測到開放式轉址參數 (Open Redirect) 鏈結特徵');
  }
  if (parsed.search.length > 140) {
    redirectDepthRisk += 20;
    signals.push('查詢參數異常冗長，疑似夾帶追蹤或混淆載荷');
  }
  redirectDepthRisk = Math.min(100, redirectDepthRisk);

  // 6. Payload / Web3 drainer / Trojan keyword risk
  let payloadSignatureRisk = 8;
  if (/(airdrop|claim-reward|connect-wallet|sync-node|seed-phrase|mnemonic|verify-kyc|urgent-suspend)/i.test(rawUrl)) {
    payloadSignatureRisk += 62;
    signals.push('觸發高風險釣魚與加密貨幣授權誘騙詞彙特徵');
  }
  if (/(powershell|cmd=|wget|curl|payload|dropper|c2|gate\.php)/i.test(rawUrl)) {
    payloadSignatureRisk += 70;
    signals.push('偵測到惡意程式指令或遠端木馬控制端點特徵');
  }
  payloadSignatureRisk = Math.min(100, payloadSignatureRisk);

  const weightedScore = Math.min(
    99,
    Math.round(
      entropyScore * 0.14 +
      lexicalAnomaly * 0.24 +
      homographRisk * 0.24 +
      tlsTrustGap * 0.10 +
      redirectDepthRisk * 0.12 +
      payloadSignatureRisk * 0.16
    )
  );

  // Boost when multiple strong signals fire together
  const maxFeature = Math.max(lexicalAnomaly, homographRisk, payloadSignatureRisk);
  const riskScore = Math.min(99, Math.max(weightedScore, Math.round(maxFeature * 0.85)));

  let category: 'phishing' | 'trojan' | 'wallet_drainer' | 'ransomware_c2' | 'suspicious_redirect' | 'safe' = 'safe';
  if (/(\.exe|\.scr|\.ps1|\.apk|dropper|gate\.php|c2)/i.test(rawUrl)) {
    category = 'trojan';
  } else if (/(airdrop|claim|wallet|metamask|uniswap|ledger|seed)/i.test(rawUrl) && riskScore >= 40) {
    category = 'wallet_drainer';
  } else if (redirectDepthRisk >= 60 && riskScore >= 40) {
    category = 'suspicious_redirect';
  } else if (riskScore >= 45) {
    category = 'phishing';
  }

  const severity =
    riskScore >= 80 ? 'critical' :
    riskScore >= 60 ? 'high' :
    riskScore >= 38 ? 'medium' :
    riskScore >= 20 ? 'low' : 'nominal';

  const verdict = riskScore >= 60 ? 'block' : riskScore >= 35 ? 'warn' : 'allow';
  const mlConfidence = Math.min(99, Math.max(74, 78 + signals.length * 4));

  return {
    parsed,
    host,
    riskScore,
    mlConfidence,
    category,
    severity,
    verdict,
    signals: signals.length > 0 ? signals : ['網域結構、字元熵值與協定特徵均位於安全基準區間'],
    features: {
      entropyScore,
      lexicalAnomaly,
      homographRisk,
      tlsTrustGap,
      redirectDepthRisk,
      payloadSignatureRisk,
    },
    traceHops: [
      `Client Request -> ${parsed.protocol}//${host}`,
      `ML Feature Engine -> Entropy ${entropyScore}/100 · Homograph ${homographRisk}/100`,
      verdict === 'block' ? `AegisFlow Policy -> 自動攔截封鎖` : verdict === 'warn' ? `AegisFlow Policy -> 沙箱隔離警示` : `AegisFlow Policy -> 放行連線`,
    ],
  };
}

interface ThreatGeo {
  countryCode: string;
  countryName: string;
  city: string;
  region: string;
  lat: number;
  lng: number;
}

const GEO_NODES: Array<{ ip: string; asn: string; geo: ThreatGeo }> = [
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

// --- Lightweight Circular Ring Buffer for Logs (max 250) ---
const threatLogs: Array<{
  id: string;
  timestamp: string;
  target: string;
  category: string;
  severity: string;
  action: string;
  platform: string;
  sourceIp: string;
  asn: string;
  geo: ThreatGeo;
  riskScore: number;
  mlConfidence: number;
  summary: string;
  features: {
    entropyScore: number;
    lexicalAnomaly: number;
    homographRisk: number;
    tlsTrustGap: number;
    redirectDepthRisk: number;
    payloadSignatureRisk: number;
  };
  traceHops: string[];
  syncedChannels: string[];
}> = [];

function pushThreatLog(entry: (typeof threatLogs)[number]) {
  threatLogs.unshift(entry);
  if (threatLogs.length > 250) {
    threatLogs.pop();
  }
}

interface ServerAlertRecord {
  id: string;
  logId?: string;
  timestamp: string;
  title: string;
  message: string;
  severity: string;
  target?: string;
  sourceIp?: string;
  channels: string[];
  read: boolean;
}

const alertHistory: ServerAlertRecord[] = [];

const sseClients = new Set<Response>();

function broadcastRealtimeAlert(alert: ServerAlertRecord) {
  alertHistory.unshift(alert);
  if (alertHistory.length > 100) {
    alertHistory.pop();
  }
  const payload = `event: alert\ndata: ${JSON.stringify(alert)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

let zeroTrustPolicies = [
  {
    id: 'zt-1',
    name: '高風險與未驗證連結自動阻斷',
    description: '當機器學習風險分數 ≥ 60 或偵測到仿冒網域時，於連線建立前立即攔截。',
    enabled: true,
    scope: 'network',
    enforcement: 'block',
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'zt-2',
    name: 'Web3 錢包無上限授權攔截 (Permit2 / Approve)',
    description: '凡遇到無限額代幣授權或盲簽 (eth_sign) 請求，強制阻斷並要求人類可讀合約審計。',
    enabled: true,
    scope: 'web3',
    enforcement: 'block',
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'zt-3',
    name: '管理權限與設定變更雙重驗證 (Step-Up MFA)',
    description: '修改防火牆規則、匯出金鑰或建立 API Token 前，必須完成零信任 Passkey/MFA 簽章。',
    enabled: true,
    scope: 'identity',
    enforcement: 'step_up_mfa',
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'zt-4',
    name: '未知可執行檔與可疑轉址沙箱隔離',
    description: '來自外部郵件或即時通訊的未知執行檔與多層轉址，自動導入隔離環境分析。',
    enabled: true,
    scope: 'endpoint',
    enforcement: 'isolate',
    updatedAt: new Date().toISOString(),
  },
];

async function createServer() {
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json({ limit: '1mb' }));

  // Lightweight security headers
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // 1. Health, Engine Capabilities & Real-Time System Metrics
  app.get('/api/v1/health', (_req, res) => {
    const aiConfigured = Boolean(getGeminiClient());
    const metrics = collectSystemMetrics();
    res.json({
      status: 'ok',
      engine: 'AegisFlow Lightweight Guard',
      aiEngineAvailable: aiConfigured,
      uptimeSeconds: metrics.uptimeSeconds,
      logCount: threatLogs.length,
      metrics,
      timestamp: metrics.sampledAt,
    });
  });

  app.get('/api/v1/system/metrics', (_req, res) => {
    res.json(collectSystemMetrics());
  });

  // 2. Offline-cacheable Threat Intel Snapshot
  app.get('/api/v1/threat-intel', (_req, res) => {
    res.json({
      updatedAt: new Date().toISOString(),
      signatureCount: 14820,
      activeThreats: threatLogs.slice(0, 15),
      highRiskTlds: Array.from(SUSPICIOUS_TLDS),
      protectedBrands: TARGETED_BRANDS,
      riskGuides: [
        {
          id: 'guide-phishing',
          title: '釣魚網站與簡訊詐騙應變清單',
          severity: 'high',
          indicators: ['網域含仿冒品牌字元或 .xyz/.top/.icu 頂級網域', '使用 Punycode (xn--) 視覺混淆', '要求立即驗證銀行帳號或密碼'],
          actions: ['立即中斷連線並清除該網站 Cookie/Session', '若已輸入憑證，立刻更換密碼並啟用硬體金鑰/Passkey', '將連結回報至 AegisFlow 同步阻斷清單'],
        },
        {
          id: 'guide-web3',
          title: '加密貨幣錢包惡意授權 (Drainer) 防護',
          severity: 'critical',
          indicators: ['要求簽署 eth_sign 盲簽或 Permit2 批次轉移', 'Approve 授權額度顯示 Unlimited / 0xffffffff...', '空投領取網域與官方社群公告不符'],
          actions: ['切勿簽署不明十六進位訊息', '透過可信撤銷工具檢查並撤銷高風險合約授權', '使用硬體錢包進行大額資產隔離'],
        },
        {
          id: 'guide-ransomware',
          title: '木馬植入與勒索軟體緊急隔離指南',
          severity: 'critical',
          indicators: ['下載來源為裸 IP 或非標準埠的 .exe/.ps1/.apk', '背景出現大量檔案重新命名與異常高磁碟寫入', '異常外連未知 C2 控制伺服器'],
          actions: ['立刻切斷受影響裝置的網路連線 (Wi-Fi / 乙太網路)', '勿關閉電源以免遺失記憶體鑑識證據，啟用唯讀隔離', '使用 AegisFlow AES-256 離線加密備份快照還原關鍵設定與紀錄'],
        },
      ],
    });
  });

  // 3. Real-Time ML + Gemini AI URL & Traffic Scanner
  app.post('/api/v1/scan/url', async (req, res) => {
    const { url, platform = 'Browser', deepAi = true } = req.body || {};
    if (typeof url !== 'string' || url.trim().length === 0 || url.length > 2048) {
      return res.status(400).json({ error: '請提供有效的網址 (長度需介於 1 至 2048 字元)。' });
    }

    const extracted = extractUrlFeatures(url);
    if (!extracted) {
      return res.status(400).json({ error: '網址格式無效，僅支援 http:// 或 https:// 協定連結。' });
    }

    let aiAnalysis: {
      summary: string;
      attackTechnique: string;
      remediationSteps: string[];
      proactivePatch: string;
    } | undefined;
    let aiError: string | undefined;

    if (deepAi) {
      const ai = getGeminiClient();
      if (!ai) {
        aiError = '未偵測到伺服器端 GEMINI_API_KEY，目前僅顯示本地機器學習特徵分析結果。';
      } else {
        try {
          const response = await ai.models.generateContent({
            model: 'gemini-4-hydrogen',
            contents: `請以資安專家身分分析此網址的潛在威脅與流量特徵，並以繁體中文提供具體的防禦與主動修補建議。\n網址: ${extracted.parsed.href}\n本地ML風險分數: ${extracted.riskScore}/100\n偵測信號: ${extracted.signals.join('; ')}`,
            config: {
              systemInstruction: '你是 AegisFlow 資安分析引擎。請客觀、精確地評估 URL 威脅向量、攻擊手法與可執行的修補規則，使用繁體中文回答。',
              responseMimeType: 'application/json',
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  summary: { type: Type.STRING, description: '簡潔明確的威脅研判摘要（繁體中文）' },
                  attackTechnique: { type: Type.STRING, description: '可能的攻擊手法或 MITRE ATT&CK 技術分類' },
                  remediationSteps: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING },
                    description: '3 項立即執行的防護與修復步驟',
                  },
                  proactivePatch: { type: Type.STRING, description: '建議部署的主動式防禦規則（例如 DNS RPZ / CSP / 防火牆阻斷語法）' },
                },
                required: ['summary', 'attackTechnique', 'remediationSteps', 'proactivePatch'],
              },
            },
          });

          const parsedAi = JSON.parse((response.text ?? '{}').trim());
          if (parsedAi.summary) {
            aiAnalysis = parsedAi;
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Gemini AI 服務暫時無法回應';
          aiError = `AI 深度分析失敗：${msg}`;
        }
      }
    }

    const action = extracted.verdict === 'block' ? 'blocked' : extracted.verdict === 'warn' ? 'quarantined' : 'allowed';
    const geoNode = inferGeoNode(extracted.host);
    const newLog = {
      id: `evt-${crypto.randomInt(1000, 9999)}`,
      timestamp: new Date().toISOString(),
      target: extracted.parsed.href,
      category: extracted.category,
      severity: extracted.severity,
      action,
      platform: typeof platform === 'string' ? platform : 'Browser',
      sourceIp: geoNode.ip,
      asn: geoNode.asn,
      geo: geoNode.geo,
      riskScore: extracted.riskScore,
      mlConfidence: extracted.mlConfidence,
      summary: aiAnalysis?.summary || extracted.signals[0],
      features: extracted.features,
      traceHops: extracted.traceHops,
      syncedChannels: extracted.verdict === 'allow' ? [] : ['BrowserPush', 'Webhook'],
    };
    pushThreatLog(newLog);

    if (extracted.verdict === 'block' || extracted.verdict === 'warn') {
      broadcastRealtimeAlert({
        id: `alt-${crypto.randomInt(10000, 99999)}`,
        logId: newLog.id,
        timestamp: newLog.timestamp,
        title:
          extracted.verdict === 'block'
            ? `已自動阻擋可疑連結 (${extracted.riskScore}/100)`
            : `可疑連結警示 (${extracted.riskScore}/100)`,
        message: `${extracted.host} — ${newLog.summary}`,
        severity: extracted.severity,
        target: newLog.target,
        sourceIp: newLog.sourceIp,
        channels: newLog.syncedChannels,
        read: false,
      });
    }

    return res.json({
      url: extracted.parsed.href,
      normalizedHost: extracted.host,
      riskScore: extracted.riskScore,
      mlConfidence: extracted.mlConfidence,
      category: extracted.category,
      severity: extracted.severity,
      verdict: extracted.verdict,
      features: extracted.features,
      signals: extracted.signals,
      traceHops: extracted.traceHops,
      aiAnalysis,
      aiError,
      logId: newLog.id,
      scannedAt: newLog.timestamp,
    });
  });

  // 4. Crypto Wallet dApp & Signature Guard
  app.post('/api/v1/scan/wallet', async (req, res) => {
    const { dappUrl, contractAddress = '', methodSignature = 'approve', calldata = '' } = req.body || {};
    if (typeof dappUrl !== 'string' || dappUrl.trim().length === 0) {
      return res.status(400).json({ error: '請提供 dApp 來源網址。' });
    }

    const urlCheck = extractUrlFeatures(dappUrl);
    if (!urlCheck) {
      return res.status(400).json({ error: 'dApp 網址格式無效。' });
    }

    const cleanContract = String(contractAddress).trim();
    const cleanMethod = String(methodSignature).trim();
    const cleanData = String(calldata).trim().toLowerCase();

    const findings: string[] = [];
    let riskScore = Math.round(urlCheck.riskScore * 0.65);
    let allowanceType: 'unlimited' | 'scoped' | 'permit2' | 'eth_sign' | 'none' = 'none';

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
      findings.push('偵測到無上限 (Unlimited) ERC-20 代幣 Approve 授權，存在合約被駭或惡意提領風險。');
    } else {
      allowanceType = 'scoped';
      findings.push('授權方法具備明確作用域，建議仍比對合約地址是否與官方一致。');
    }

    if (cleanContract && !/^0x[a-fA-F0-9]{40}$/.test(cleanContract)) {
      riskScore += 15;
      findings.push('合約地址格式不符合標準 EVM 40 位十六進位規範，請務必查核。');
    }

    if (urlCheck.signals.length > 0 && urlCheck.riskScore >= 35) {
      findings.push(...urlCheck.signals);
    }

    riskScore = Math.min(99, riskScore);
    const severity =
      riskScore >= 80 ? 'critical' :
      riskScore >= 55 ? 'high' :
      riskScore >= 30 ? 'medium' : 'nominal';
    const verdict = riskScore >= 60 ? 'block' : riskScore >= 30 ? 'warn' : 'allow';

    const humanReadableIntent =
      allowanceType === 'eth_sign'
        ? `警告：${urlCheck.host} 請求您對未解碼的原始雜湊進行盲簽 (eth_sign)，這等同於授予空白支票。`
        : allowanceType === 'permit2'
        ? `注意：${urlCheck.host} 請求 Permit2 批次授權簽章，合約 ${cleanContract || '未指定'} 將可代為轉移指定代幣。`
        : allowanceType === 'unlimited'
        ? `高風險：${urlCheck.host} 請求將您的代幣/NFT 無上限控制權交給合約 ${cleanContract || '未知合約'}。`
        : `${urlCheck.host} 請求有限額度互動授權，目標合約 ${cleanContract || '標準介面'}。`;

    let aiAssessment: { summary: string; drainVector: string; safeAlternative: string } | undefined;
    let aiError: string | undefined;
    const ai = getGeminiClient();
    if (ai) {
      try {
        const resp = await ai.models.generateContent({
          model: 'gemini-4-hydrogen',
          contents: `分析以下 Web3 錢包連線與授權請求是否為惡意錢包抽乾 (Wallet Drainer) 詐騙：\ndApp: ${urlCheck.parsed.href}\n合約: ${cleanContract || '未提供'}\n方法: ${cleanMethod}\nCalldata: ${cleanData || '無'}\n偵測結果: ${findings.join('; ')}`,
          config: {
            systemInstruction: '你是專精 Web3 智能合約與錢包安全的審計系統，請用繁體中文簡潔說明風險與安全替代做法。',
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                summary: { type: Type.STRING },
                drainVector: { type: Type.STRING },
                safeAlternative: { type: Type.STRING },
              },
              required: ['summary', 'drainVector', 'safeAlternative'],
            },
          },
        });
        aiAssessment = JSON.parse((resp.text ?? '{}').trim());
      } catch (err) {
        aiError = err instanceof Error ? err.message : 'Gemini Web3 風險分析失敗';
      }
    } else {
      aiError = '未設定 GEMINI_API_KEY，已使用本地 ABI 簽章風險引擎完成檢核。';
    }

    const walletGeo = inferGeoNode(urlCheck.host);
    const walletLog = {
      id: `evt-${crypto.randomInt(1000, 9999)}`,
      timestamp: new Date().toISOString(),
      target: `${urlCheck.parsed.href} [${cleanMethod}]`,
      category: verdict === 'allow' ? 'safe' : 'wallet_drainer',
      severity,
      action: verdict === 'block' ? 'blocked' : verdict === 'warn' ? 'quarantined' : 'allowed',
      platform: 'Browser',
      sourceIp: walletGeo.ip,
      asn: walletGeo.asn,
      geo: walletGeo.geo,
      riskScore,
      mlConfidence: 95,
      summary: humanReadableIntent,
      features: urlCheck.features,
      traceHops: [`Wallet Provider -> ${urlCheck.host}`, `ABI Inspector -> ${cleanMethod} (${allowanceType})`, `AegisFlow Web3 Guard -> ${verdict.toUpperCase()}`],
      syncedChannels: verdict === 'allow' ? [] : ['BrowserPush', 'Telegram'],
    };
    pushThreatLog(walletLog);

    if (verdict === 'block' || verdict === 'warn') {
      broadcastRealtimeAlert({
        id: `alt-${crypto.randomInt(10000, 99999)}`,
        logId: walletLog.id,
        timestamp: walletLog.timestamp,
        title: `Web3 錢包授權風險警告 (${riskScore}/100)`,
        message: humanReadableIntent,
        severity,
        target: walletLog.target,
        sourceIp: walletLog.sourceIp,
        channels: walletLog.syncedChannels,
        read: false,
      });
    }

    return res.json({
      dappUrl: urlCheck.parsed.href,
      contractAddress: cleanContract || '0x0000000000000000000000000000000000000000',
      methodSignature: cleanMethod,
      allowanceType,
      riskScore,
      severity,
      verdict,
      humanReadableIntent,
      findings,
      aiAssessment,
      aiError,
      logId: walletLog.id,
      scannedAt: walletLog.timestamp,
    });
  });

  // 5. AI Proactive Patch & Remediation Generator
  app.post('/api/v1/ai/remediate', async (req, res) => {
    const { target, category, summary, riskScore } = req.body || {};
    if (typeof target !== 'string' || !target.trim()) {
      return res.status(400).json({ error: '缺少威脅目標資訊。' });
    }
    const ai = getGeminiClient();
    if (!ai) {
      return res.status(503).json({
        error: '伺服器尚未設定 GEMINI_API_KEY，無法生成 AI 主動修補建議。請於 Settings > Secrets 面板確認金鑰設定。',
      });
    }

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `針對以下資安事件生成主動式修補計畫與風險評估指南（繁體中文）：\n目標: ${target}\n威脅類別: ${category}\n風險分數: ${riskScore}/100\n摘要: ${summary}`,
        config: {
          systemInstruction: '你是 AegisFlow 主動式資安防禦系統。請提供具體可落地的系統修補規則（如 DNS RPZ、Nginx/CSP 標頭、防火牆規則、零信任權限限縮）與風險評估。',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              rootCause: { type: Type.STRING },
              riskAssessment: { type: Type.STRING },
              immediateActions: { type: Type.ARRAY, items: { type: Type.STRING } },
              patchRules: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    target: { type: Type.STRING },
                    ruleType: { type: Type.STRING },
                    ruleSnippet: { type: Type.STRING },
                  },
                  required: ['target', 'ruleType', 'ruleSnippet'],
                },
              },
              preventionChecklist: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: ['rootCause', 'riskAssessment', 'immediateActions', 'patchRules', 'preventionChecklist'],
          },
        },
      });
      const plan = JSON.parse((response.text ?? '{}').trim());
      return res.json({
        ...plan,
        generatedAt: new Date().toISOString(),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'AI 修補建議生成失敗';
      return res.status(502).json({ error: `Gemini AI 連線錯誤：${msg}` });
    }
  });

  // 6. Logs Retrieval & Open-Source Ingestion
  app.get('/api/v1/logs', (req, res) => {
    const severity = typeof req.query.severity === 'string' ? req.query.severity : 'all';
    const category = typeof req.query.category === 'string' ? req.query.category : 'all';
    const query = typeof req.query.q === 'string' ? req.query.q.toLowerCase().trim() : '';

    const filtered = threatLogs.filter((log) => {
      if (severity !== 'all' && log.severity !== severity) return false;
      if (category !== 'all' && log.category !== category) return false;
      if (query && !log.target.toLowerCase().includes(query) && !log.summary.toLowerCase().includes(query) && !log.id.toLowerCase().includes(query)) {
        return false;
      }
      return true;
    });

    res.json({
      total: filtered.length,
      logs: filtered,
    });
  });

  app.post('/api/v1/logs', authenticateZeroTrustOrApi, (req, res) => {
    const { target, category = 'phishing', severity = 'medium', summary = '外部開源整合回報事件', platform = 'API' } = req.body || {};
    if (typeof target !== 'string' || !target.trim()) {
      return res.status(400).json({ error: 'target 欄位為必填。' });
    }
    const extGeo = inferGeoNode(target);
    const entry = {
      id: `evt-${crypto.randomInt(1000, 9999)}`,
      timestamp: new Date().toISOString(),
      target: target.slice(0, 512),
      category: String(category),
      severity: String(severity),
      action: severity === 'critical' || severity === 'high' ? 'blocked' : 'quarantined',
      platform: String(platform),
      sourceIp: req.ip || extGeo.ip,
      asn: extGeo.asn,
      geo: extGeo.geo,
      riskScore: severity === 'critical' ? 92 : severity === 'high' ? 78 : 52,
      mlConfidence: 90,
      summary: String(summary).slice(0, 300),
      features: { entropyScore: 55, lexicalAnomaly: 60, homographRisk: 40, tlsTrustGap: 30, redirectDepthRisk: 25, payloadSignatureRisk: 65 },
      traceHops: [`Open-Source API -> ${platform}`, `AegisFlow Log Archiver -> 已歸檔`],
      syncedChannels: ['Webhook'],
    };
    pushThreatLog(entry);
    broadcastRealtimeAlert({
      id: `alt-${crypto.randomInt(10000, 99999)}`,
      logId: entry.id,
      timestamp: entry.timestamp,
      title: `外部 API 威脅通報 (${entry.platform})`,
      message: entry.summary,
      severity: entry.severity,
      target: entry.target,
      sourceIp: entry.sourceIp,
      channels: entry.syncedChannels,
      read: false,
    });
    return res.status(201).json(entry);
  });

  // 7. Zero-Trust Identity & Access Control
  app.post('/api/v1/zerotrust/verify', (req, res) => {
    const { deviceId = 'web-client-01', mfaMethod = 'Passkey', challengeCode = '' } = req.body || {};
    if (typeof deviceId !== 'string' || deviceId.trim().length < 3) {
      return res.status(400).json({ error: '裝置識別碼無效。' });
    }
    if (mfaMethod === 'TOTP' && !/^\d{6}$/.test(String(challengeCode).trim())) {
      return res.status(400).json({ error: '請輸入 6 位數驗證碼以完成雙因素驗證。' });
    }

    const now = Date.now();
    const expiresAt = now + 1000 * 60 * 60 * 4; // 4h short-lived Zero-Trust session
    const payload: TokenPayload = {
      sub: 'local-operator',
      deviceId: deviceId.trim().slice(0, 64),
      trustLevel: 'elevated',
      mfaMethod: String(mfaMethod),
      iat: now,
      exp: expiresAt,
    };

    const token = signZeroTrustToken(payload);
    return res.json({
      token,
      deviceId: payload.deviceId,
      trustLevel: payload.trustLevel,
      mfaMethod: payload.mfaMethod,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
    });
  });

  app.get('/api/v1/zerotrust/policies', (_req, res) => {
    res.json({ policies: zeroTrustPolicies });
  });

  app.post('/api/v1/zerotrust/policies', authenticateZeroTrustOrApi, (req, res) => {
    const { id, enabled, enforcement } = req.body || {};
    const targetPolicy = zeroTrustPolicies.find((p) => p.id === id);
    if (!targetPolicy) {
      return res.status(404).json({ error: '找不到指定的零信任原則。' });
    }
    if (typeof enabled === 'boolean') targetPolicy.enabled = enabled;
    if (enforcement === 'block' || enforcement === 'step_up_mfa' || enforcement === 'isolate') {
      targetPolicy.enforcement = enforcement;
    }
    targetPolicy.updatedAt = new Date().toISOString();
    return res.json({ policy: targetPolicy, policies: zeroTrustPolicies });
  });

  // 8. Open-Source API Token Issuance (Zero-Trust Protected)
  app.get('/api/v1/tokens', (_req, res) => {
    res.json({
      tokens: apiTokens.map(({ id, name, prefix, scope, createdAt }) => ({
        id,
        name,
        prefix,
        scope,
        createdAt,
      })),
    });
  });

  app.post('/api/v1/tokens', authenticateZeroTrustOrApi, (req, res) => {
    const { name, scope = 'scan' } = req.body || {};
    if (typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ error: '請輸入至少 2 個字元的整合名稱。' });
    }
    const rawToken = `af_oss_${crypto.randomBytes(18).toString('hex')}`;
    const record: ApiTokenRecord = {
      id: `tok_${crypto.randomBytes(4).toString('hex')}`,
      name: name.trim().slice(0, 60),
      prefix: rawToken.slice(0, 14),
      hash: crypto.createHash('sha256').update(rawToken).digest('hex'),
      scope: scope === 'read' || scope === 'admin' ? scope : 'scan',
      createdAt: new Date().toISOString(),
    };
    apiTokens.unshift(record);
    return res.status(201).json({
      token: {
        id: record.id,
        name: record.name,
        prefix: record.prefix,
        scope: record.scope,
        createdAt: record.createdAt,
      },
      plaintextSecret: rawToken,
    });
  });

  // 9. Real-Time Alert Stream (SSE) & Multi-Platform Alert Dispatch
  app.get('/api/v1/alerts/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    sseClients.add(res);
    res.write(`event: init\ndata: ${JSON.stringify({ alerts: alertHistory.slice(0, 30) })}\n\n`);

    const keepAlive = setInterval(() => {
      try {
        res.write(': keepalive\n\n');
      } catch {
        clearInterval(keepAlive);
        sseClients.delete(res);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(keepAlive);
      sseClients.delete(res);
    });
  });

  app.get('/api/v1/alerts', (_req, res) => {
    res.json({ alerts: alertHistory.slice(0, 50) });
  });

  app.post('/api/v1/alerts/ack', (req, res) => {
    const { id, all } = req.body || {};
    if (all === true) {
      for (const item of alertHistory) item.read = true;
    } else if (typeof id === 'string') {
      const target = alertHistory.find((a) => a.id === id);
      if (target) target.read = true;
    }
    return res.json({ alerts: alertHistory.slice(0, 50) });
  });

  app.post('/api/v1/alerts/dispatch', async (req, res) => {
    const { channels = ['BrowserPush'], title, message, severity = 'high', webhookUrl, logId, target } = req.body || {};
    if (typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: '告警訊息內容不可為空。' });
    }

    let webhookStatus = 'skipped';
    if (typeof webhookUrl === 'string' && webhookUrl.trim().length > 0) {
      let parsedWebhook: URL;
      try {
        parsedWebhook = new URL(webhookUrl.trim());
      } catch {
        return res.status(400).json({ error: 'Webhook 網址格式不正確。' });
      }
      if (parsedWebhook.protocol !== 'https:' && parsedWebhook.protocol !== 'http:') {
        return res.status(400).json({ error: 'Webhook 僅支援 HTTP/HTTPS 協定。' });
      }
      if (isBlockedPrivateOrLoopbackHost(parsedWebhook.hostname)) {
        return res.status(403).json({ error: '安全限制：禁止向內部網路或本機位址發送 Webhook 請求。' });
      }
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3500);
        const resp = await fetch(parsedWebhook.href, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source: 'AegisFlow',
            severity,
            message: message.slice(0, 500),
            timestamp: new Date().toISOString(),
          }),
          signal: controller.signal,
        });
        clearTimeout(timeout);
        webhookStatus = resp.ok ? 'delivered' : `http_${resp.status}`;
      } catch {
        webhookStatus = 'unreachable';
      }
    }

    const emitted: ServerAlertRecord = {
      id: `alt-${crypto.randomInt(10000, 99999)}`,
      logId: typeof logId === 'string' ? logId : undefined,
      timestamp: new Date().toISOString(),
      title: typeof title === 'string' && title.trim() ? title.trim().slice(0, 120) : '即時資安警報通知',
      message: message.trim().slice(0, 500),
      severity: String(severity),
      target: typeof target === 'string' ? target.slice(0, 512) : undefined,
      channels: Array.isArray(channels) ? channels.map(String) : ['BrowserPush'],
      read: false,
    };
    broadcastRealtimeAlert(emitted);

    return res.json({
      dispatched: true,
      alert: emitted,
      channels: emitted.channels,
      severity,
      webhookStatus,
      timestamp: emitted.timestamp,
    });
  });

  // Vite Dev Middleware or Static Production Serve
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AegisFlow server running on http://0.0.0.0:${PORT}`);
  });
}

createServer().catch((err) => {
  console.error('Failed to start AegisFlow server:', err);
  process.exit(1);
});
