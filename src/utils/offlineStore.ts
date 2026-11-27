import type {
  AlertChannelConfig,
  BackupSnapshotMeta,
  DashboardWidgetConfig,
  ProtectionSettings,
  RealtimeAlertItem,
  ThreatLogEntry,
} from '../types/security';

const KEYS = {
  LOGS: 'aegisflow_offline_logs_v2',
  SETTINGS: 'aegisflow_protection_settings_v1',
  WIDGETS: 'aegisflow_dashboard_widgets_v1',
  ALERTS: 'aegisflow_alert_channels_v1',
  ALERT_FEED: 'aegisflow_alert_feed_v2',
  BACKUPS: 'aegisflow_backup_history_v1',
  DRILL_SCORES: 'aegisflow_drill_scores_v1',
  INTEL: 'aegisflow_threat_intel_v1',
} as const;

export const DEFAULT_SETTINGS: ProtectionSettings = {
  preset: 'strict_zerotrust',
  defaultPlatform: 'Browser',
  autoBlockMaliciousLinks: true,
  mlTrafficInspection: true,
  walletSignatureGuard: true,
  realtimePushAlerts: true,
  alertSoundEnabled: true,
  multiPlatformLogSync: true,
  sandboxUntrustedRedirects: true,
  offlineCacheEnabled: true,
};

export const DEFAULT_WIDGETS: DashboardWidgetConfig[] = [
  { id: 'system_perf', title: '輕量化系統效能監控', visible: true, order: 0 },
  { id: 'threat_trend', title: '過去 7 天威脅攔截趨勢', visible: true, order: 1 },
  { id: 'geo_heatmap', title: '威脅地理分佈熱力圖', visible: true, order: 2 },
  { id: 'ml_traffic', title: 'ML 流量特徵即時監控', visible: true, order: 3 },
  { id: 'threat_feed', title: '最新攔截與威脅動態', visible: true, order: 4 },
  { id: 'wallet_guard', title: 'Web3 錢包授權保護摘要', visible: true, order: 5 },
  { id: 'zerotrust_status', title: '零信任身分與原則執行狀態', visible: true, order: 6 },
  { id: 'backup_integrity', title: '抗勒索加密備份快照狀態', visible: true, order: 7 },
];

export const DEFAULT_ALERT_CHANNELS: AlertChannelConfig[] = [
  {
    id: 'ch-push',
    channel: 'BrowserPush',
    label: '瀏覽器 / PWA 即時推播',
    enabled: true,
    targetSummary: '本機桌機與行動裝置',
  },
  {
    id: 'ch-line',
    channel: 'LINE_Notify',
    label: 'LINE 緊急告警群組',
    enabled: true,
    targetSummary: '個人資安警示頻道',
  },
  {
    id: 'ch-slack',
    channel: 'Slack',
    label: 'Slack SecOps Webhook',
    enabled: false,
    targetSummary: '#sec-alerts',
    webhookUrl: '',
  },
  {
    id: 'ch-discord',
    channel: 'Discord',
    label: 'Discord 防禦通知頻道',
    enabled: false,
    targetSummary: 'Security-Watch',
    webhookUrl: '',
  },
  {
    id: 'ch-telegram',
    channel: 'Telegram',
    label: 'Telegram Bot 同步通知',
    enabled: true,
    targetSummary: '@AegisWatchBot',
  },
];

export const DEFAULT_ALERT_FEED: RealtimeAlertItem[] = [];

function safeRead<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function safeWrite(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore quota errors cleanly
  }
}

export const offlineStore = {
  getLogs: (): ThreatLogEntry[] => safeRead<ThreatLogEntry[]>(KEYS.LOGS, []),
  saveLogs: (logs: ThreatLogEntry[]) => safeWrite(KEYS.LOGS, logs.slice(0, 120)),

  getSettings: (): ProtectionSettings => ({
    ...DEFAULT_SETTINGS,
    ...safeRead<Partial<ProtectionSettings>>(KEYS.SETTINGS, DEFAULT_SETTINGS),
  }),
  saveSettings: (settings: ProtectionSettings) => safeWrite(KEYS.SETTINGS, settings),

  getWidgets: (): DashboardWidgetConfig[] => {
    const saved = safeRead<DashboardWidgetConfig[]>(KEYS.WIDGETS, DEFAULT_WIDGETS);
    const existingIds = new Set(saved.map((w) => w.id));
    const missing = DEFAULT_WIDGETS.filter((w) => !existingIds.has(w.id));
    if (missing.length === 0) return saved;
    return [...missing, ...saved].map((w, idx) => ({ ...w, order: idx }));
  },
  saveWidgets: (widgets: DashboardWidgetConfig[]) => safeWrite(KEYS.WIDGETS, widgets),

  getAlertChannels: (): AlertChannelConfig[] => safeRead<AlertChannelConfig[]>(KEYS.ALERTS, DEFAULT_ALERT_CHANNELS),
  saveAlertChannels: (channels: AlertChannelConfig[]) => safeWrite(KEYS.ALERTS, channels),

  getAlertFeed: (): RealtimeAlertItem[] => safeRead<RealtimeAlertItem[]>(KEYS.ALERT_FEED, DEFAULT_ALERT_FEED),
  saveAlertFeed: (items: RealtimeAlertItem[]) => safeWrite(KEYS.ALERT_FEED, items.slice(0, 80)),

  getBackupHistory: (): BackupSnapshotMeta[] => safeRead<BackupSnapshotMeta[]>(KEYS.BACKUPS, []),
  saveBackupHistory: (history: BackupSnapshotMeta[]) => safeWrite(KEYS.BACKUPS, history.slice(0, 20)),

  getDrillScores: (): Record<string, boolean> => safeRead<Record<string, boolean>>(KEYS.DRILL_SCORES, {}),
  saveDrillScores: (scores: Record<string, boolean>) => safeWrite(KEYS.DRILL_SCORES, scores),

  getCachedIntel: <T>(fallback: T): T => safeRead<T>(KEYS.INTEL, fallback),
  saveCachedIntel: (intel: unknown) => safeWrite(KEYS.INTEL, intel),
};
