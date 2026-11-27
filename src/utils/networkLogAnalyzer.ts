import type {
  MLFeatureVector,
  NetworkLogAnalysisResult,
  NetworkLogFinding,
  PlatformSource,
  ThreatCategory,
  ThreatGeoInfo,
  ThreatLogEntry,
  ThreatSeverity,
} from '../types/security';

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'buzz', 'click', 'link', 'work', 'support', 'zip', 'mov',
]);

const HIGH_RISK_PORTS = new Set([4444, 1337, 31337, 6667, 5555, 9001, 8443]);
const SENSITIVE_SERVICE_PORTS = new Set([22, 23, 445, 1433, 3389, 5900, 6379]);

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

function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip === '0.0.0.0'
  );
}

function detectFormat(lines: string[]): NetworkLogAnalysisResult['detectedFormat'] {
  let jsonCount = 0;
  let httpCount = 0;
  let dnsCount = 0;
  let fwCount = 0;

  for (const line of lines.slice(0, 25)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) jsonCount++;
    if (/"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^"]+"\s+\d{3}/.test(trimmed)) httpCount++;
    if (/(dnsmasq|named|query\[|A\?|AAAA\?|TXT\?|NXDOMAIN)/i.test(trimmed)) dnsCount++;
    if (/(DPT=|SPT=|SRC=|DST=|ALLOW|DENY|DROP|BLOCK|UFW|IPTABLES|FIREWALL)/i.test(trimmed)) fwCount++;
  }

  if (jsonCount >= Math.max(1, Math.floor(lines.slice(0, 25).length / 2))) return 'json_lines';
  if (httpCount >= dnsCount && httpCount >= fwCount && httpCount > 0) return 'nginx_apache';
  if (dnsCount >= httpCount && dnsCount >= fwCount && dnsCount > 0) return 'dns_query';
  if (fwCount > 0) return 'firewall_syslog';
  return 'mixed_text';
}

function extractLineFields(rawLine: string) {
  let normalizedText = rawLine;
  let parsedIp = '';
  let parsedUrl = '';
  let parsedPath = '';
  let parsedStatus: number | null = null;
  let parsedPort: number | null = null;
  let parsedDomain = '';
  let parsedBytes: number | null = null;

  if (rawLine.trim().startsWith('{')) {
    try {
      const obj = JSON.parse(rawLine.trim()) as Record<string, unknown>;
      normalizedText = Object.entries(obj)
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(' ');
      const ipCandidate = obj.src_ip || obj.sourceIp || obj.clientIp || obj.ip || obj.remote_addr;
      if (typeof ipCandidate === 'string') parsedIp = ipCandidate;
      const urlCandidate = obj.url || obj.uri || obj.path || obj.request || obj.target;
      if (typeof urlCandidate === 'string') parsedPath = urlCandidate;
      if (typeof obj.status === 'number') parsedStatus = obj.status;
      if (typeof obj.dport === 'number' || typeof obj.port === 'number') {
        parsedPort = Number(obj.dport ?? obj.port);
      }
      if (
        typeof obj.domain === 'string' ||
        typeof obj.qname === 'string' ||
        typeof obj.host === 'string' ||
        typeof obj.hostname === 'string'
      ) {
        parsedDomain = String(obj.domain ?? obj.qname ?? obj.host ?? obj.hostname);
      }
      if (typeof obj.bytes_out === 'number' || typeof obj.bytes === 'number') {
        parsedBytes = Number(obj.bytes_out ?? obj.bytes);
      }
    } catch {
      // Treat as raw line
    }
  }

  const ips = normalizedText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (!parsedIp && ips.length > 0) {
    parsedIp = ips.find((ip) => !isPrivateIp(ip)) ?? ips[0] ?? '';
  }

  const urlMatch = normalizedText.match(/https?:\/\/[^\s"'<>]+/i);
  if (urlMatch) {
    parsedUrl = urlMatch[0];
    try {
      const u = new URL(parsedUrl);
      parsedDomain = parsedDomain || u.hostname.toLowerCase();
      parsedPath = parsedPath || `${u.pathname}${u.search}`;
    } catch {
      // Ignore invalid URL parse
    }
  }

  const httpReqMatch = normalizedText.match(/"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)[^"]*"\s+(\d{3})/i);
  if (httpReqMatch) {
    parsedPath = parsedPath || httpReqMatch[1];
    parsedStatus = parsedStatus ?? Number(httpReqMatch[2]);
  }

  const statusMatch = normalizedText.match(/\bstatus[=:]?\s*(\d{3})\b/i);
  if (parsedStatus === null && statusMatch) {
    parsedStatus = Number(statusMatch[1]);
  }

  const dptMatch = normalizedText.match(/\b(?:DPT|dport|dst_port|port)[=:]\s*(\d{1,5})\b/i);
  if (parsedPort === null && dptMatch) {
    parsedPort = Number(dptMatch[1]);
  } else if (parsedPort === null) {
    const colonPort = normalizedText.match(/\b(?:\d{1,3}\.){3}\d{1,3}:(\d{2,5})\b/);
    if (colonPort) parsedPort = Number(colonPort[1]);
  }

  const domainMatch = normalizedText.match(/\b([a-z0-9-]+(?:\.[a-z0-9-]+){1,5})\b/i);
  if (!parsedDomain && domainMatch && !/^\d+\.\d+\.\d+\.\d+$/.test(domainMatch[1])) {
    parsedDomain = domainMatch[1].toLowerCase();
  }

  const bytesMatch = normalizedText.match(/\b(?:bytes_out|bytes|sent)[=:]\s*(\d+)\b/i);
  if (parsedBytes === null && bytesMatch) {
    parsedBytes = Number(bytesMatch[1]);
  }

  return {
    normalizedText,
    sourceIp: parsedIp || '0.0.0.0',
    url: parsedUrl,
    path: parsedPath,
    status: parsedStatus,
    port: parsedPort,
    domain: parsedDomain,
    bytes: parsedBytes,
  };
}

export function analyzeRawNetworkLogs(
  rawText: string,
  platform: PlatformSource = 'API',
  maxIngest = 40
): NetworkLogAnalysisResult {
  const allLines = rawText.split(/\r?\n/);
  const nonEmptyLines = allLines
    .map((line, index) => ({ line: line.trim(), lineNumber: index + 1 }))
    .filter((item) => item.line.length > 0)
    .slice(0, 1000);

  const detectedFormat = detectFormat(nonEmptyLines.map((i) => i.line));
  const parsedItems = nonEmptyLines.map((item) => ({
    ...item,
    fields: extractLineFields(item.line),
  }));

  // First pass: cross-line behavioral burst detection per source IP
  const ipStats = new Map<
    string,
    { total: number; authOrDeny: number; ports: Set<number> }
  >();

  for (const { line, fields } of parsedItems) {
    const ip = fields.sourceIp;
    if (!ip || ip === '0.0.0.0') continue;
    let stat = ipStats.get(ip);
    if (!stat) {
      stat = { total: 0, authOrDeny: 0, ports: new Set<number>() };
      ipStats.set(ip, stat);
    }
    stat.total += 1;
    if (fields.port) stat.ports.add(fields.port);

    const isAuthFailOrDeny =
      fields.status === 401 ||
      fields.status === 403 ||
      /(failed password|authentication failure|invalid user|denied|blocked|drop|wp-login|xmlrpc\.php)/i.test(line);
    if (isAuthFailOrDeny) {
      stat.authOrDeny += 1;
    }
  }

  const findings: NetworkLogFinding[] = [];
  const ingestedLogs: ThreatLogEntry[] = [];
  const attackerSummaryMap = new Map<string, { count: number; maxRisk: number }>();

  for (const { line, lineNumber, fields } of parsedItems) {
    const signals: string[] = [];
    let riskScore = 0;
    let category: ThreatCategory = 'safe';
    let attackType = '';
    const featureScores: MLFeatureVector = {
      entropyScore: 10,
      lexicalAnomaly: 10,
      homographRisk: 5,
      tlsTrustGap: 10,
      redirectDepthRisk: 5,
      payloadSignatureRisk: 10,
    };

    const combinedTargetText = `${fields.url} ${fields.path} ${line}`;

    // 1. Web Exploits: SQLi, XSS, Path Traversal, Log4Shell, RCE
    if (/(union\s+select|or\s+1=1|'--|\bsleep\(\d+|\bbenchmark\(|sqlmap)/i.test(combinedTargetText)) {
      riskScore += 72;
      category = 'trojan';
      attackType = attackType || 'SQL Injection 攻擊試探';
      featureScores.payloadSignatureRisk = Math.max(featureScores.payloadSignatureRisk, 88);
      signals.push('偵測到 SQL 注入特徵 (UNION SELECT / SQLMap / 邏輯繞過)');
    }
    if (/(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/etc\/shadow|win\.ini)/i.test(combinedTargetText)) {
      riskScore += 74;
      category = 'trojan';
      attackType = attackType || '路徑穿越與敏感檔讀取';
      featureScores.payloadSignatureRisk = Math.max(featureScores.payloadSignatureRisk, 85);
      signals.push('偵測到目錄穿越 (Path Traversal) 企圖讀取系統機密檔案');
    }
    if (/(\$\{jndi:|powershell|cmd\.exe|\/bin\/(?:ba)?sh|\bwget\s+http|\bcurl\s+http|eval\(|base64_decode|<script)/i.test(combinedTargetText)) {
      riskScore += 82;
      category = 'trojan';
      attackType = attackType || '遠端指令執行 / 載荷注入 (RCE)';
      featureScores.payloadSignatureRisk = Math.max(featureScores.payloadSignatureRisk, 94);
      signals.push('偵測到遠端指令執行 (RCE / JNDI / Shell Download) 高危載荷');
    }

    // 2. Vulnerability / Credential Scanning Probes
    if (/(\/\.env|\/\.git\/|\/wp-login\.php|\/xmlrpc\.php|\/phpmyadmin|\/actuator\/|nikto|nuclei|masscan|nmap|dirbuster)/i.test(combinedTargetText)) {
      riskScore += 58;
      if (category === 'safe') category = 'phishing';
      attackType = attackType || '自動化弱點掃描與敏感組態探測';
      featureScores.lexicalAnomaly = Math.max(featureScores.lexicalAnomaly, 72);
      signals.push('探測敏感環境設定 (.env / .git) 或出現自動化掃描器特徵');
    }

    // 3. C2 / Trojan Payload Staging / Reverse Shell Ports
    if (/(\.exe|\.ps1|\.bat|\.scr|\.apk|\.dll|gate\.php|beacon|dropper|c2)/i.test(combinedTargetText)) {
      riskScore += 76;
      category = 'trojan';
      attackType = attackType || '惡意木馬下載與 C2 通訊特徵';
      featureScores.payloadSignatureRisk = Math.max(featureScores.payloadSignatureRisk, 90);
      signals.push('路徑或參數包含可疑執行檔載荷或 C2 控制端點特徵');
    }
    if (fields.port && HIGH_RISK_PORTS.has(fields.port)) {
      riskScore += 68;
      category = 'ransomware_c2';
      attackType = attackType || `高風險遠端控制埠通訊 (:${fields.port})`;
      featureScores.lexicalAnomaly = Math.max(featureScores.lexicalAnomaly, 82);
      signals.push(`偵測到連線至常見反向 Shell / C2 高風險埠 :${fields.port}`);
    } else if (fields.port && SENSITIVE_SERVICE_PORTS.has(fields.port) && /(failed|deny|drop|block|invalid user)/i.test(line)) {
      riskScore += 48;
      if (category === 'safe') category = 'trojan';
      attackType = attackType || `管理服務埠爆破試探 (:${fields.port})`;
      signals.push(`對敏感服務埠 :${fields.port} 的失敗連線或阻斷紀錄`);
    }

    // 4. DNS Tunneling / DGA High-Entropy Domain
    if (fields.domain) {
      const labels = fields.domain.split('.');
      const longestLabel = labels.reduce((m, l) => (l.length > m.length ? l : m), '');
      const domainEntropy = shannonEntropy(longestLabel);
      const tld = labels[labels.length - 1] || '';

      if (longestLabel.length >= 34 || (longestLabel.length >= 14 && domainEntropy >= 3.75)) {
        riskScore += 62;
        category = category === 'safe' ? 'ransomware_c2' : category;
        attackType = attackType || 'DNS 通道 / DGA 演算法網域異常';
        featureScores.entropyScore = Math.max(featureScores.entropyScore, 86);
        signals.push(`網域標籤呈現高隨機字元熵值 (${domainEntropy.toFixed(2)} bits / 長度 ${longestLabel.length})，疑為 DGA 或 DNS 隱蔽通道`);
      }
      if (SUSPICIOUS_TLDS.has(tld)) {
        riskScore += 28;
        if (category === 'safe') category = 'phishing';
        featureScores.lexicalAnomaly = Math.max(featureScores.lexicalAnomaly, 60);
        signals.push(`連線指向高濫用風險頂級網域 (.${tld})`);
      }
      if (fields.domain.includes('xn--')) {
        riskScore += 54;
        category = category === 'safe' ? 'phishing' : category;
        featureScores.homographRisk = 78;
        signals.push('網域含 Punycode (xn--) 國際化字形偽裝風險');
      }
    }

    // 5. Embedded Phishing / Open Redirect / Wallet Drainer
    if (/(airdrop|claim-reward|connect-wallet|permit2|eth_sign|mnemonic|seed-phrase)/i.test(combinedTargetText)) {
      riskScore += 66;
      category = 'wallet_drainer';
      attackType = attackType || 'Web3 錢包抽乾 / 假空投誘騙連結';
      featureScores.payloadSignatureRisk = Math.max(featureScores.payloadSignatureRisk, 84);
      signals.push('日誌內含高風險 Web3 錢包授權誘騙或助記詞釣魚關鍵字');
    }
    if (/(redirect|next|url|return|goto)=http/i.test(combinedTargetText)) {
      riskScore += 45;
      if (category === 'safe') category = 'suspicious_redirect';
      featureScores.redirectDepthRisk = 74;
      signals.push('偵測到開放式轉址 (Open Redirect) 釣魚跳轉參數');
    }

    // 6. Cross-line Brute Force / Port Scan Burst
    const ipStat = ipStats.get(fields.sourceIp);
    if (ipStat) {
      if (ipStat.ports.size >= 4) {
        riskScore += 55;
        if (category === 'safe') category = 'trojan';
        attackType = attackType || '多埠口掃描偵察行為 (Port Scan)';
        signals.push(`來源 IP ${fields.sourceIp} 於此批日誌內橫跨探測 ${ipStat.ports.size} 個不同通訊埠`);
      } else if (ipStat.authOrDeny >= 4 && (fields.status === 401 || fields.status === 403 || /(failed|invalid user|wp-login|deny|drop)/i.test(line))) {
        riskScore += 52;
        if (category === 'safe') category = 'phishing';
        attackType = attackType || '高頻密碼爆破 / 暴力嘗試 (Brute Force)';
        signals.push(`來源 IP ${fields.sourceIp} 短時間內累計 ${ipStat.authOrDeny} 次驗證失敗或拒絕存取`);
      }
    }

    // 7. Abnormal Outbound Exfiltration Volume
    if (fields.bytes && fields.bytes >= 10_000_000 && fields.sourceIp && !isPrivateIp(fields.sourceIp)) {
      riskScore += 46;
      if (category === 'safe') category = 'ransomware_c2';
      attackType = attackType || '大量異常資料外傳 (Exfiltration)';
      signals.push(`單筆傳輸達 ${(fields.bytes / 1_048_576).toFixed(1)} MB，建議核查是否為機密外洩`);
    }

    if (signals.length === 0 || riskScore < 35) {
      continue;
    }

    riskScore = Math.min(99, riskScore);
    const severity: ThreatSeverity =
      riskScore >= 80 ? 'critical' :
      riskScore >= 60 ? 'high' :
      riskScore >= 40 ? 'medium' : 'low';

    const targetDisplay =
      fields.url ||
      (fields.path && fields.domain ? `${fields.domain}${fields.path}` : '') ||
      fields.path ||
      (fields.domain ? `${fields.domain}${fields.port ? `:${fields.port}` : ''}` : '') ||
      line.slice(0, 120);

    const logId = `log-${Date.now().toString(36).slice(-4)}-${lineNumber}`;
    const geoNode = inferGeoNode(`${fields.sourceIp}-${targetDisplay}`);
    const resolvedIp = fields.sourceIp !== '0.0.0.0' ? fields.sourceIp : geoNode.ip;

    findings.push({
      lineNumber,
      rawLine: line.slice(0, 400),
      sourceIp: resolvedIp,
      target: targetDisplay,
      attackType: attackType || '可疑網路異常行為',
      category: category === 'safe' ? 'phishing' : category,
      severity,
      riskScore,
      signals,
      logId,
    });

    const currentIpSum = attackerSummaryMap.get(resolvedIp);
    if (currentIpSum) {
      currentIpSum.count += 1;
      currentIpSum.maxRisk = Math.max(currentIpSum.maxRisk, riskScore);
    } else {
      attackerSummaryMap.set(resolvedIp, { count: 1, maxRisk: riskScore });
    }

    if (ingestedLogs.length < maxIngest) {
      ingestedLogs.push({
        id: logId,
        timestamp: new Date().toISOString(),
        target: targetDisplay.slice(0, 240),
        category: category === 'safe' ? 'phishing' : category,
        severity,
        action: riskScore >= 60 ? 'blocked' : 'quarantined',
        platform,
        sourceIp: resolvedIp,
        asn: geoNode.asn,
        geo: geoNode.geo,
        riskScore,
        mlConfidence: Math.min(98, 76 + signals.length * 6),
        summary: `[日誌行 #${lineNumber}] ${attackType || '可疑行徑'}：${signals[0]}`,
        features: featureScores,
        traceHops: [
          `Source IP -> ${resolvedIp}${fields.port ? `:${fields.port}` : ''}`,
          `Log Behavior Analyzer -> ${attackType || '異常特徵比對'} (Line #${lineNumber})`,
          riskScore >= 60 ? 'AegisFlow Policy -> 建議立即封鎖來源 IP / 阻斷規則' : 'AegisFlow Policy -> 列入高度觀察清單',
        ],
        syncedChannels: riskScore >= 60 ? ['BrowserPush'] : [],
      });
    }
  }

  const topAttackerIps = Array.from(attackerSummaryMap.entries())
    .map(([ip, stat]) => ({ ip, count: stat.count, maxRisk: stat.maxRisk }))
    .sort((a, b) => b.maxRisk - a.maxRisk || b.count - a.count)
    .slice(0, 6);

  findings.sort((a, b) => b.riskScore - a.riskScore || a.lineNumber - b.lineNumber);

  return {
    totalLines: nonEmptyLines.length,
    parsedEntries: parsedItems.length,
    maliciousCount: findings.length,
    cleanCount: Math.max(0, parsedItems.length - findings.length),
    detectedFormat,
    topAttackerIps,
    findings,
    ingestedLogs,
    analyzedAt: new Date().toISOString(),
  };
}
