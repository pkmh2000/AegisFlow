import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  Bell,
  BookOpen,
  Code2,
  HardDrive,
  HelpCircle,
  LayoutDashboard,
  Lock,
  Menu,
  Moon,
  SearchCheck,
  Shield,
  Sun,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import { AlertCenterDrawer } from './components/AlertCenterDrawer';
import { BackupVaultView } from './components/BackupVaultView';
import { DashboardView } from './components/DashboardView';
import { DrillsGuidesView, type GuidesSectionId } from './components/DrillsGuidesView';
import { LogAnalyzerView } from './components/LogAnalyzerView';
import { OpenApiSettingsView } from './components/OpenApiSettingsView';
import { PWAInstallButton } from './components/PWAInstallButton';
import { ScannerView } from './components/ScannerView';
import { ZeroTrustView } from './components/ZeroTrustView';
import { useOnlineStatus } from './hooks/useOnlineStatus';
import type {
  AIRemediationPlan,
  AlertChannelConfig,
  BackupSnapshotMeta,
  DashboardWidgetConfig,
  ProtectionSettings,
  RealtimeAlertItem,
  ThreatLogEntry,
  ThreatSeverity,
  ZeroTrustPolicy,
  ZeroTrustSession,
} from './types/security';
import { playCriticalAlertSound } from './utils/alertSound';
import { offlineStore } from './utils/offlineStore';

type TabId = 'dashboard' | 'scanner' | 'logs' | 'zerotrust' | 'backup' | 'drills' | 'api';

const NAV_ITEMS: {
  id: TabId;
  label: string;
  shortLabel: string;
  Icon: React.ComponentType<{ className?: string }>;
}[] = [
  { id: 'dashboard', label: '防護總覽儀表板', shortLabel: '總覽', Icon: LayoutDashboard },
  { id: 'scanner', label: '連結與錢包防護', shortLabel: '掃描', Icon: SearchCheck },
  { id: 'logs', label: '深度日誌與溯源', shortLabel: '日誌', Icon: Activity },
  { id: 'zerotrust', label: '零信任存取控管', shortLabel: '零信任', Icon: Lock },
  { id: 'backup', label: '抗勒索加密備份', shortLabel: '備份', Icon: HardDrive },
  { id: 'drills', label: '操作說明與演練', shortLabel: '說明', Icon: BookOpen },
  { id: 'api', label: '開源 API 與設定', shortLabel: '設定', Icon: Code2 },
];

export default function App() {
  const { isOnline, networkOnline, simulatedOffline, setSimulatedOffline } = useOnlineStatus();

  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [guidesSection, setGuidesSection] = useState<GuidesSectionId>('guide');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);

  const [logs, setLogs] = useState<ThreatLogEntry[]>(() => offlineStore.getLogs());
  const [selectedLog, setSelectedLog] = useState<ThreatLogEntry | null>(null);
  const [quickScanUrl, setQuickScanUrl] = useState('');

  const [settings, setSettings] = useState<ProtectionSettings>(() => offlineStore.getSettings());
  const [widgets, setWidgets] = useState<DashboardWidgetConfig[]>(() => offlineStore.getWidgets());
  const [alertChannels, setAlertChannels] = useState<AlertChannelConfig[]>(() =>
    offlineStore.getAlertChannels()
  );
  const [backups, setBackups] = useState<BackupSnapshotMeta[]>(() =>
    offlineStore.getBackupHistory()
  );
  const [drillScores, setDrillScores] = useState<Record<string, boolean>>(() =>
    offlineStore.getDrillScores()
  );

  // Zero-Trust session stored strictly in React memory (never localStorage)
  const [ztSession, setZtSession] = useState<ZeroTrustSession | null>(null);
  const [policies, setPolicies] = useState<ZeroTrustPolicy[]>([
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
  ]);

  const [tokens, setTokens] = useState<
    Array<{ id: string; name: string; prefix: string; scope: string; createdAt: string }>
  >([]);

  const [alerts, setAlerts] = useState<RealtimeAlertItem[]>(() => offlineStore.getAlertFeed());
  const [alertDrawerOpen, setAlertDrawerOpen] = useState(false);

  const unreadAlertCount = useMemo(() => alerts.filter((a) => !a.read).length, [alerts]);

  const handledAlertIdsRef = useRef<Set<string>>(new Set());
  const handledLogIdsRef = useRef<Set<string>>(new Set());

  const [toastAlert, setToastAlert] = useState<{
    title: string;
    body: string;
    severity?: ThreatSeverity;
    logId?: string;
  } | null>(null);

  const fireClientNotification = useCallback(
    (title: string, body: string, severity?: ThreatSeverity, logId?: string) => {
      setToastAlert({ title, body, severity, logId });
      if (severity === 'critical' && settings.alertSoundEnabled) {
        void playCriticalAlertSound();
      }
      if (
        settings.realtimePushAlerts &&
        typeof Notification !== 'undefined' &&
        Notification.permission === 'granted'
      ) {
        try {
          new Notification(title, { body });
        } catch {
          // Ignore browser restriction
        }
      }
    },
    [settings.realtimePushAlerts, settings.alertSoundEnabled]
  );

  const triggerToast = useCallback(
    (
      title: string,
      body: string,
      severity?: ThreatSeverity,
      meta?: { logId?: string; target?: string }
    ) => {
      fireClientNotification(title, body, severity, meta?.logId);

      if (severity === 'critical' || severity === 'high' || severity === 'medium') {
        if (meta?.logId) handledLogIdsRef.current.add(meta.logId);
        const newAlert: RealtimeAlertItem = {
          id: `alt-${Date.now().toString(36)}-${Math.floor(Math.random() * 900 + 100)}`,
          logId: meta?.logId,
          timestamp: new Date().toISOString(),
          title,
          message: body,
          severity,
          target: meta?.target,
          channels: alertChannels.filter((c) => c.enabled).map((c) => c.channel),
          read: false,
        };
        handledAlertIdsRef.current.add(newAlert.id);
        setAlerts((prev) => {
          const updated = [newAlert, ...prev.filter((a) => !meta?.logId || a.logId !== meta.logId)].slice(0, 80);
          offlineStore.saveAlertFeed(updated);
          return updated;
        });
      }
    },
    [alertChannels, fireClientNotification]
  );

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) root.classList.add('dark');
    else root.classList.remove('dark');
  }, [darkMode]);

  const isJsonResponse = (resp: Response) =>
    resp.ok && Boolean(resp.headers.get('content-type')?.includes('application/json'));

  const refreshServerData = useCallback(async () => {
    if (!isOnline) return;
    try {
      const [logsRes, polRes, tokRes, intelRes] = await Promise.all([
        fetch('/api/v1/logs'),
        fetch('/api/v1/zerotrust/policies'),
        fetch('/api/v1/tokens'),
        fetch('/api/v1/threat-intel'),
      ]);
      if (isJsonResponse(logsRes)) {
        const d = await logsRes.json();
        if (Array.isArray(d.logs)) {
          setLogs(d.logs);
          if (settings.offlineCacheEnabled) offlineStore.saveLogs(d.logs);
        }
      }
      if (isJsonResponse(polRes)) {
        const p = await polRes.json();
        if (Array.isArray(p.policies)) setPolicies(p.policies);
      }
      if (isJsonResponse(tokRes)) {
        const t = await tokRes.json();
        if (Array.isArray(t.tokens)) setTokens(t.tokens);
      }
      if (isJsonResponse(intelRes)) {
        const intel = await intelRes.json();
        if (settings.offlineCacheEnabled) offlineStore.saveCachedIntel(intel);
      }
    } catch {
      // Fall back silently to offlineStore / static seed data
    }
  }, [isOnline, settings.offlineCacheEnabled]);

  const handleAddLocalLog = useCallback(
    (entry: ThreatLogEntry) => {
      setLogs((prev) => {
        const updated = [entry, ...prev].slice(0, 200);
        if (settings.offlineCacheEnabled) offlineStore.saveLogs(updated);
        return updated;
      });
    },
    [settings.offlineCacheEnabled]
  );

  const handleBatchAddLocalLogs = useCallback(
    (entries: ThreatLogEntry[]) => {
      if (entries.length === 0) return;
      setLogs((prev) => {
        const existingIds = new Set(prev.map((l) => l.id));
        const fresh = entries.filter((e) => !existingIds.has(e.id));
        const updated = [...fresh, ...prev].slice(0, 200);
        if (settings.offlineCacheEnabled) offlineStore.saveLogs(updated);
        return updated;
      });
    },
    [settings.offlineCacheEnabled]
  );

  useEffect(() => {
    refreshServerData();
  }, [refreshServerData]);

  // Real-time Server-Sent Events subscription for instant multi-client threat alerts
  useEffect(() => {
    if (!isOnline || typeof EventSource === 'undefined') return;
    let source: EventSource | null = null;
    let cancelled = false;

    const connectAlertStream = async () => {
      try {
        const probe = await fetch('/api/v1/health');
        if (cancelled || !isJsonResponse(probe)) return;

        source = new EventSource('/api/v1/alerts/stream');

        source.addEventListener('init', (evt) => {
          try {
            const payload = JSON.parse((evt as MessageEvent).data) as { alerts?: RealtimeAlertItem[] };
            if (!Array.isArray(payload.alerts)) return;
            setAlerts((prev) => {
              const seenIds = new Set(prev.map((a) => a.id));
              const seenLogIds = new Set(prev.map((a) => a.logId).filter(Boolean));
              const merged = [...prev];
              for (const item of payload.alerts!) {
                if (!seenIds.has(item.id) && (!item.logId || !seenLogIds.has(item.logId))) {
                  merged.push(item);
                }
                handledAlertIdsRef.current.add(item.id);
                if (item.logId) handledLogIdsRef.current.add(item.logId);
              }
              merged.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
              const capped = merged.slice(0, 80);
              offlineStore.saveAlertFeed(capped);
              return capped;
            });
          } catch {
            // Ignore malformed init payload
          }
        });

        source.addEventListener('alert', (evt) => {
          try {
            const incoming = JSON.parse((evt as MessageEvent).data) as RealtimeAlertItem;
            if (
              handledAlertIdsRef.current.has(incoming.id) ||
              (incoming.logId && handledLogIdsRef.current.has(incoming.logId))
            ) {
              return;
            }
            handledAlertIdsRef.current.add(incoming.id);
            if (incoming.logId) handledLogIdsRef.current.add(incoming.logId);

            setAlerts((prev) => {
              if (prev.some((a) => a.id === incoming.id)) return prev;
              const updated = [incoming, ...prev].slice(0, 80);
              offlineStore.saveAlertFeed(updated);
              return updated;
            });

            fireClientNotification(incoming.title, incoming.message, incoming.severity, incoming.logId);
            void refreshServerData();
          } catch {
            // Ignore malformed SSE event
          }
        });
      } catch {
        // Static-host fallback: no backend SSE stream available
      }
    };

    void connectAlertStream();

    return () => {
      cancelled = true;
      source?.close();
    };
  }, [isOnline, fireClientNotification, refreshServerData]);

  const handleUpdateSettings = (next: ProtectionSettings) => {
    setSettings(next);
    offlineStore.saveSettings(next);
  };

  const handleUpdateWidgets = (next: DashboardWidgetConfig[]) => {
    setWidgets(next);
    offlineStore.saveWidgets(next);
  };

  const handleUpdateAlertChannels = (next: AlertChannelConfig[]) => {
    setAlertChannels(next);
    offlineStore.saveAlertChannels(next);
  };

  const handleRecordBackup = (meta: BackupSnapshotMeta) => {
    const next = [meta, ...backups];
    setBackups(next);
    offlineStore.saveBackupHistory(next);
  };

  const handleRestoreBackup = (restored: {
    logs: ThreatLogEntry[];
    settings: ProtectionSettings;
    alertChannels: AlertChannelConfig[];
  }) => {
    if (Array.isArray(restored.logs)) {
      setLogs(restored.logs);
      offlineStore.saveLogs(restored.logs);
    }
    if (restored.settings) {
      handleUpdateSettings(restored.settings);
    }
    if (Array.isArray(restored.alertChannels)) {
      handleUpdateAlertChannels(restored.alertChannels);
    }
  };

  const handleUpdateLogRemediation = (logId: string, plan: AIRemediationPlan) => {
    setLogs((prev) => {
      const updated = prev.map((l) => (l.id === logId ? { ...l, aiRemediation: plan } : l));
      if (settings.offlineCacheEnabled) offlineStore.saveLogs(updated);
      return updated;
    });
    setSelectedLog((prev) => (prev && prev.id === logId ? { ...prev, aiRemediation: plan } : prev));
  };

  const handleRecordDrill = (drillId: string, passed: boolean) => {
    const next = { ...drillScores, [drillId]: passed };
    setDrillScores(next);
    offlineStore.saveDrillScores(next);
  };

  const handleMarkAlertRead = (id: string) => {
    setAlerts((prev) => {
      const next = prev.map((a) => (a.id === id ? { ...a, read: true } : a));
      offlineStore.saveAlertFeed(next);
      return next;
    });
    if (isOnline) {
      void fetch('/api/v1/alerts/ack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      }).catch(() => undefined);
    }
  };

  const handleMarkAllAlertsRead = () => {
    setAlerts((prev) => {
      const next = prev.map((a) => ({ ...a, read: true }));
      offlineStore.saveAlertFeed(next);
      return next;
    });
    if (isOnline) {
      void fetch('/api/v1/alerts/ack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ all: true }),
      }).catch(() => undefined);
    }
  };

  const handleClearReadAlerts = () => {
    setAlerts((prev) => {
      const next = prev.filter((a) => !a.read);
      offlineStore.saveAlertFeed(next);
      return next;
    });
  };

  const handleInspectAlert = (alert: RealtimeAlertItem) => {
    handleMarkAlertRead(alert.id);
    if (alert.logId) {
      const matched = logs.find((l) => l.id === alert.logId);
      if (matched) setSelectedLog(matched);
    }
    setAlertDrawerOpen(false);
    setActiveTab('logs');
  };

  const handleOpenScannerFromAlerts = () => {
    setAlertDrawerOpen(false);
    setActiveTab('scanner');
  };

  const currentNavLabel = NAV_ITEMS.find((n) => n.id === activeTab)?.label ?? '防護總覽';

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-slate-50 text-slate-900 dark:bg-[#0B1120] dark:text-slate-100">
      {/* Desktop Left Sidebar */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:border-r lg:border-slate-200 lg:bg-white dark:lg:border-slate-800 dark:lg:bg-slate-900 shrink-0">
        <div className="flex h-16 items-center gap-2.5 border-b border-slate-200 px-6 dark:border-slate-800">
          <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
          <span className="text-base font-bold tracking-tight text-slate-900 dark:text-slate-50 whitespace-nowrap shrink-0">
            AegisFlow
          </span>
        </div>

        <nav className="flex-1 space-y-1 p-4" aria-label="主導覽選單">
          {NAV_ITEMS.map(({ id, label, Icon }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setActiveTab(id)}
                className={`w-full flex items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  active
                    ? 'bg-slate-900 text-white dark:bg-blue-600 dark:text-white'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span className="truncate">{label}</span>
              </button>
            );
          })}
        </nav>

        <div className="border-t border-slate-200 p-4 dark:border-slate-800 space-y-2.5">
          <button
            type="button"
            onClick={() => setSimulatedOffline((v) => !v)}
            className="w-full flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300 dark:hover:bg-slate-800 cursor-pointer"
          >
            <span className="flex items-center gap-2">
              {isOnline ? (
                <Wifi className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <WifiOff className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
              )}
              <span>{isOnline ? '連線模式' : '離線瀏覽模式'}</span>
            </span>
            <span className="text-[11px] text-slate-500">
              {simulatedOffline ? '切換在線' : '預覽離線'}
            </span>
          </button>
        </div>
      </aside>

      {/* Mobile Slide-Out Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-slate-950/60"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative z-10 flex w-72 flex-col bg-white p-4 dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800">
            <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                <span className="text-base font-bold text-slate-900 dark:text-slate-50">AegisFlow</span>
              </div>
              <button
                type="button"
                aria-label="關閉選單"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <nav className="mt-4 flex-1 space-y-1">
              {NAV_ITEMS.map(({ id, label, Icon }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => {
                    setActiveTab(id);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 rounded-lg px-3.5 py-3 text-sm font-medium cursor-pointer ${
                    activeTab === id
                      ? 'bg-slate-900 text-white dark:bg-blue-600'
                      : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{label}</span>
                </button>
              ))}
            </nav>
            <button
              type="button"
              onClick={() => setSimulatedOffline((v) => !v)}
              className="mt-4 flex items-center justify-between rounded-lg border border-slate-200 px-3.5 py-2.5 text-xs font-medium text-slate-700 dark:border-slate-700 dark:text-slate-300 cursor-pointer"
            >
              <span>{isOnline ? '切換離線瀏覽預覽' : '恢復線上連線模式'}</span>
              {isOnline ? <Wifi className="h-4 w-4 text-emerald-600" /> : <WifiOff className="h-4 w-4 text-amber-600" />}
            </button>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 pb-16 lg:pb-0">
        {/* Workspace Header */}
        <header className="sticky top-0 z-30 flex h-14 sm:h-16 items-center justify-between gap-4 border-b border-slate-200 bg-white/95 px-4 sm:px-6 backdrop-blur-xs dark:border-slate-800 dark:bg-slate-900/95">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="開啟導覽選單"
              onClick={() => setMobileMenuOpen(true)}
              className="rounded-lg p-2 text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800 lg:hidden cursor-pointer"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-2 text-xs sm:text-sm min-w-0">
              <span className="font-semibold text-slate-900 dark:text-slate-100 lg:hidden whitespace-nowrap">
                AegisFlow
              </span>
              <span className="text-slate-400 lg:hidden" aria-hidden="true">/</span>
              <span className="truncate font-medium text-slate-700 dark:text-slate-200">
                {currentNavLabel}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => {
                setGuidesSection('guide');
                setActiveTab('drills');
              }}
              aria-label="開啟各項功能說明與操作手冊"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <HelpCircle className="h-4 w-4 text-slate-600 dark:text-slate-300" aria-hidden="true" />
              <span className="hidden md:inline">功能說明</span>
            </button>

            <button
              type="button"
              onClick={() => setAlertDrawerOpen(true)}
              aria-label={`開啟即時警報通知中心，目前 ${unreadAlertCount} 則未讀`}
              className="relative inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Bell
                className={`h-4 w-4 ${
                  unreadAlertCount > 0 ? 'text-blue-600 dark:text-blue-400' : ''
                }`}
                aria-hidden="true"
              />
              <span className="hidden sm:inline">警報通知</span>
              {unreadAlertCount > 0 && (
                <span className="font-mono tabular-nums text-[11px] font-bold text-red-600 dark:text-red-400">
                  {unreadAlertCount}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => setDarkMode((d) => !d)}
              aria-label={darkMode ? '切換淺色介面' : '切換深色介面'}
              className="rounded-lg border border-slate-200 bg-white p-2 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 cursor-pointer"
            >
              {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            <PWAInstallButton />

            <button
              type="button"
              onClick={() => setActiveTab('scanner')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <SearchCheck className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">掃描可疑連結</span>
              <span className="sm:hidden">掃描</span>
            </button>
          </div>
        </header>

        {/* Offline Banner */}
        {!isOnline && (
          <div className="border-b border-amber-200 bg-amber-50 px-4 py-2 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-200 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <WifiOff className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>
                離線瀏覽模式運行中：已自動載入本機快取的威脅日誌、風險指南、資安演練與 AES-256 加密備份工具。
              </span>
            </div>
            {networkOnline && simulatedOffline && (
              <button
                type="button"
                onClick={() => setSimulatedOffline(false)}
                className="font-semibold underline cursor-pointer"
              >
                結束離線預覽
              </button>
            )}
          </div>
        )}

        {/* Toast Alert Notification */}
        {toastAlert && (
          <div
            className={`fixed bottom-20 right-4 lg:bottom-6 lg:right-6 z-50 max-w-sm rounded-xl border bg-white p-4 shadow-lg dark:bg-slate-900 ${
              toastAlert.severity === 'critical'
                ? 'border-red-300 dark:border-red-800'
                : 'border-slate-200 dark:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-2.5">
                {toastAlert.severity === 'critical' ? (
                  <AlertOctagon className="mt-0.5 h-4 w-4 text-red-600 dark:text-red-400 shrink-0" />
                ) : (
                  <Bell className="mt-0.5 h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" />
                )}
                <div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    {toastAlert.title}
                  </div>
                  <p className="mt-1 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {toastAlert.body}
                  </p>
                  <div className="mt-2.5 flex items-center gap-3 text-xs">
                    {toastAlert.logId && (
                      <button
                        type="button"
                        onClick={() => {
                          const matched = logs.find((l) => l.id === toastAlert.logId);
                          if (matched) setSelectedLog(matched);
                          setActiveTab('logs');
                          setToastAlert(null);
                        }}
                        className="font-semibold text-blue-600 hover:underline dark:text-blue-400 cursor-pointer"
                      >
                        查看威脅溯源
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        setAlertDrawerOpen(true);
                        setToastAlert(null);
                      }}
                      className="font-medium text-slate-600 hover:underline dark:text-slate-400 cursor-pointer"
                    >
                      開啟警報中心
                    </button>
                  </div>
                </div>
              </div>
              <button
                type="button"
                aria-label="關閉通知"
                onClick={() => setToastAlert(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}

        <AlertCenterDrawer
          open={alertDrawerOpen}
          onClose={() => setAlertDrawerOpen(false)}
          alerts={alerts}
          settings={settings}
          onUpdateSettings={handleUpdateSettings}
          onMarkRead={handleMarkAlertRead}
          onMarkAllRead={handleMarkAllAlertsRead}
          onClearRead={handleClearReadAlerts}
          onInspectAlert={handleInspectAlert}
          onOpenScanner={handleOpenScannerFromAlerts}
        />

        {/* Main Viewport */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1360px] w-full mx-auto">
          {activeTab === 'dashboard' && (
            <DashboardView
              logs={logs}
              settings={settings}
              onUpdateSettings={handleUpdateSettings}
              widgets={widgets}
              onUpdateWidgets={handleUpdateWidgets}
              policies={policies}
              session={ztSession}
              backups={backups}
              isOnline={isOnline}
              onQuickScanUrl={(url) => {
                setQuickScanUrl(url);
                setActiveTab('scanner');
              }}
              onNavigate={(tab) => setActiveTab(tab)}
              onSelectLog={(log) => setSelectedLog(log)}
            />
          )}

          {activeTab === 'scanner' && (
            <ScannerView
              initialUrl={quickScanUrl}
              selectedPlatform={settings.defaultPlatform}
              onSelectPlatform={(defaultPlatform) =>
                handleUpdateSettings({ ...settings, defaultPlatform })
              }
              isOnline={isOnline}
              onScanComplete={refreshServerData}
              onAddLocalLog={handleAddLocalLog}
              onNotifyThreat={triggerToast}
            />
          )}

          {activeTab === 'logs' && (
            <LogAnalyzerView
              logs={logs}
              selectedLog={selectedLog}
              selectedPlatform={settings.defaultPlatform}
              onSelectLog={setSelectedLog}
              onUpdateLogRemediation={handleUpdateLogRemediation}
              onRefreshLogs={refreshServerData}
              onBatchAddLocalLogs={handleBatchAddLocalLogs}
              alertChannels={alertChannels}
              isOnline={isOnline}
              onNotifyToast={triggerToast}
            />
          )}

          {activeTab === 'zerotrust' && (
            <ZeroTrustView
              policies={policies}
              session={ztSession}
              onSessionVerified={(s) => {
                setZtSession(s);
                triggerToast('零信任身分驗證完成', `裝置 ${s.deviceId} 已取得高信任工作階段憑證。`);
              }}
              onPoliciesUpdated={(next) => {
                setPolicies(next);
                triggerToast('零信任原則已更新', '防護規則已即時同步套用。');
              }}
              isOnline={isOnline}
            />
          )}

          {activeTab === 'backup' && (
            <BackupVaultView
              logs={logs}
              settings={settings}
              alertChannels={alertChannels}
              backups={backups}
              onRecordBackup={handleRecordBackup}
              onRestoreBackup={handleRestoreBackup}
            />
          )}

          {activeTab === 'drills' && (
            <DrillsGuidesView
              drillScores={drillScores}
              onRecordDrillResult={handleRecordDrill}
              onResetDrills={() => {
                setDrillScores({});
                offlineStore.saveDrillScores({});
              }}
              activeSection={guidesSection}
              onChangeSection={setGuidesSection}
            />
          )}

          {activeTab === 'api' && (
            <OpenApiSettingsView
              settings={settings}
              onUpdateSettings={handleUpdateSettings}
              alertChannels={alertChannels}
              onUpdateAlertChannels={handleUpdateAlertChannels}
              session={ztSession}
              tokens={tokens}
              onRefreshTokens={refreshServerData}
              isOnline={isOnline}
              onNotifyToast={triggerToast}
            />
          )}
        </main>
      </div>

      {/* Mobile Bottom Navigation Bar (Compact <= 15% viewport cap) */}
      <nav
        aria-label="行動端快速切換"
        className="fixed bottom-0 inset-x-0 z-30 flex items-center justify-around border-t border-slate-200 bg-white/95 py-1.5 backdrop-blur-xs dark:border-slate-800 dark:bg-slate-900/95 lg:hidden"
      >
        {NAV_ITEMS.slice(0, 5).map(({ id, shortLabel, Icon }) => {
          const active = activeTab === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => setActiveTab(id)}
              className={`flex min-h-[44px] min-w-[44px] flex-col items-center justify-center gap-0.5 px-2 text-[11px] font-medium cursor-pointer ${
                active
                  ? 'text-blue-600 dark:text-blue-400'
                  : 'text-slate-500 dark:text-slate-400'
              }`}
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              <span>{shortLabel}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
}
