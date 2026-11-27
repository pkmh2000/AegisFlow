export type ThreatCategory =
  | 'phishing'
  | 'trojan'
  | 'wallet_drainer'
  | 'ransomware_c2'
  | 'suspicious_redirect'
  | 'safe';

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'nominal';

export type PlatformSource = 'Windows' | 'macOS' | 'iOS' | 'Android' | 'Browser' | 'API';

export interface MLFeatureVector {
  entropyScore: number; // 0-100
  lexicalAnomaly: number; // 0-100
  homographRisk: number; // 0-100
  tlsTrustGap: number; // 0-100
  redirectDepthRisk: number; // 0-100
  payloadSignatureRisk: number; // 0-100
}

export interface ThreatGeoInfo {
  countryCode: string;
  countryName: string;
  city: string;
  region: string;
  lat: number;
  lng: number;
}

export interface ThreatLogEntry {
  id: string;
  timestamp: string;
  target: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  action: 'blocked' | 'quarantined' | 'allowed' | 'alerted';
  platform: PlatformSource;
  sourceIp: string;
  asn: string;
  geo?: ThreatGeoInfo;
  riskScore: number;
  mlConfidence: number;
  summary: string;
  features: MLFeatureVector;
  traceHops: string[];
  syncedChannels: string[];
  aiRemediation?: AIRemediationPlan;
}

export interface AIRemediationPlan {
  rootCause: string;
  riskAssessment: string;
  immediateActions: string[];
  patchRules: {
    target: string;
    ruleType: string;
    ruleSnippet: string;
  }[];
  preventionChecklist: string[];
  generatedAt: string;
}

export interface URLScanResult {
  url: string;
  normalizedHost: string;
  riskScore: number;
  mlConfidence: number;
  category: ThreatCategory;
  severity: ThreatSeverity;
  verdict: 'block' | 'warn' | 'allow';
  features: MLFeatureVector;
  signals: string[];
  traceHops: string[];
  aiAnalysis?: {
    summary: string;
    attackTechnique: string;
    remediationSteps: string[];
    proactivePatch: string;
  };
  aiError?: string;
  logId?: string;
  scannedAt: string;
}

export interface WalletScanResult {
  dappUrl: string;
  contractAddress: string;
  methodSignature: string;
  allowanceType: 'unlimited' | 'scoped' | 'permit2' | 'eth_sign' | 'none';
  riskScore: number;
  severity: ThreatSeverity;
  verdict: 'block' | 'warn' | 'allow';
  humanReadableIntent: string;
  findings: string[];
  aiAssessment?: {
    summary: string;
    drainVector: string;
    safeAlternative: string;
  };
  aiError?: string;
  logId?: string;
  scannedAt: string;
}

export interface ZeroTrustPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  scope: 'network' | 'identity' | 'web3' | 'endpoint';
  enforcement: 'block' | 'step_up_mfa' | 'isolate';
  updatedAt: string;
}

export interface ZeroTrustSession {
  token: string;
  deviceId: string;
  trustLevel: 'verified' | 'elevated';
  mfaMethod: 'Passkey' | 'TOTP' | 'HardwareKey';
  issuedAt: string;
  expiresAt: string;
}

export interface AlertChannelConfig {
  id: string;
  channel: 'BrowserPush' | 'LINE_Notify' | 'Slack' | 'Discord' | 'Telegram' | 'Webhook';
  label: string;
  enabled: boolean;
  targetSummary: string;
  webhookUrl?: string;
  lastDispatchedAt?: string;
}

export interface RealtimeAlertItem {
  id: string;
  logId?: string;
  timestamp: string;
  title: string;
  message: string;
  severity: ThreatSeverity;
  target?: string;
  sourceIp?: string;
  channels: string[];
  read: boolean;
}

export interface ProtectionSettings {
  preset: 'home' | 'strict_zerotrust' | 'web3_guardian';
  autoBlockMaliciousLinks: boolean;
  mlTrafficInspection: boolean;
  walletSignatureGuard: boolean;
  realtimePushAlerts: boolean;
  alertSoundEnabled: boolean;
  multiPlatformLogSync: boolean;
  sandboxUntrustedRedirects: boolean;
  offlineCacheEnabled: boolean;
}

export type DashboardWidgetId =
  | 'system_perf'
  | 'threat_trend'
  | 'geo_heatmap'
  | 'ml_traffic'
  | 'threat_feed'
  | 'wallet_guard'
  | 'zerotrust_status'
  | 'backup_integrity';

export interface SystemMetricsSnapshot {
  source: 'node_backend' | 'browser_runtime';
  status: 'healthy' | 'elevated' | 'critical';
  memory: {
    rssMb: number;
    heapUsedMb: number;
    heapTotalMb: number;
    systemUsedPct: number;
    status: 'healthy' | 'elevated' | 'critical';
  };
  cpu: {
    processPct: number;
    systemLoadPct: number;
    loadAvg1m: number;
    cores: number;
    eventLoopLagMs: number;
    status: 'healthy' | 'elevated' | 'critical';
  };
  uptimeSeconds: number;
  sampledAt: string;
}

export interface DashboardWidgetConfig {
  id: DashboardWidgetId;
  title: string;
  visible: boolean;
  order: number;
}

export interface BackupSnapshotMeta {
  id: string;
  createdAt: string;
  sha256: string;
  recordCount: number;
  sizeBytes: number;
  cipher: 'AES-256-GCM';
}

export interface SecurityDrillScenario {
  id: string;
  title: string;
  category: ThreatCategory;
  difficulty: '基礎' | '進階' | '專家';
  prompt: string;
  artifactLabel: string;
  artifactContent: string;
  options: {
    id: string;
    label: string;
    isCorrect: boolean;
    explanation: string;
  }[];
  remediationTip: string;
}
