import React, { useMemo, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ChevronRight,
  Eye,
  EyeOff,
  HardDrive,
  Lock,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Wallet,
  X,
} from 'lucide-react';
import type {
  BackupSnapshotMeta,
  DashboardWidgetConfig,
  DashboardWidgetId,
  ProtectionSettings,
  ThreatLogEntry,
  ZeroTrustPolicy,
  ZeroTrustSession,
} from '../types/security';
import { getActionLabel, getCategoryLabel, SeverityText } from './SeverityLabel';
import { SystemPerformanceWidget } from './SystemPerformanceWidget';
import { ThreatGeoHeatmap } from './ThreatGeoHeatmap';
import { ThreatTrendChart } from './ThreatTrendChart';

interface DashboardViewProps {
  logs: ThreatLogEntry[];
  settings: ProtectionSettings;
  onUpdateSettings: (next: ProtectionSettings) => void;
  widgets: DashboardWidgetConfig[];
  onUpdateWidgets: (next: DashboardWidgetConfig[]) => void;
  policies: ZeroTrustPolicy[];
  session: ZeroTrustSession | null;
  backups: BackupSnapshotMeta[];
  isOnline: boolean;
  onQuickScanUrl: (url: string) => void;
  onNavigate: (tab: 'scanner' | 'logs' | 'zerotrust' | 'backup' | 'drills' | 'api') => void;
  onSelectLog: (log: ThreatLogEntry) => void;
  onDeleteLog?: (id: string) => void;
}

const PRESETS: { id: ProtectionSettings['preset']; label: string; desc: string }[] = [
  { id: 'home', label: '一般居家防護', desc: '自動攔截釣魚網站與明顯木馬，低干擾日常瀏覽' },
  { id: 'strict_zerotrust', label: '嚴格零信任模式', desc: '全流量 ML 深度檢查、未知執行檔隔離與 MFA 驗證' },
  { id: 'web3_guardian', label: 'Web3 資產專護', desc: '強化 Permit2 / Approve 簽章審查與假空投阻斷' },
];

export const DashboardView: React.FC<DashboardViewProps> = ({
  logs,
  settings,
  onUpdateSettings,
  widgets,
  onUpdateWidgets,
  policies,
  session,
  backups,
  isOnline,
  onQuickScanUrl,
  onNavigate,
  onSelectLog,
  onDeleteLog,
}) => {
  const [quickUrl, setQuickUrl] = useState('');
  const [customizeMode, setCustomizeMode] = useState(false);

  const stats = useMemo(() => {
    const blocked = logs.filter((l) => l.action === 'blocked' || l.action === 'quarantined').length;
    const web3Threats = logs.filter((l) => l.category === 'wallet_drainer').length;
    const avgConfidence = logs.length
      ? Math.round(logs.reduce((acc, l) => acc + l.mlConfidence, 0) / logs.length)
      : null;
    const activePolicies = policies.filter((p) => p.enabled).length;
    return { blocked, web3Threats, avgConfidence, activePolicies };
  }, [logs, policies]);

  const sortedWidgets = useMemo(
    () => [...widgets].sort((a, b) => a.order - b.order),
    [widgets]
  );

  const applyPreset = (preset: ProtectionSettings['preset']) => {
    if (preset === 'home') {
      onUpdateSettings({
        ...settings,
        preset,
        autoBlockMaliciousLinks: true,
        mlTrafficInspection: true,
        walletSignatureGuard: true,
        sandboxUntrustedRedirects: false,
      });
    } else if (preset === 'strict_zerotrust') {
      onUpdateSettings({
        ...settings,
        preset,
        autoBlockMaliciousLinks: true,
        mlTrafficInspection: true,
        walletSignatureGuard: true,
        realtimePushAlerts: true,
        multiPlatformLogSync: true,
        sandboxUntrustedRedirects: true,
      });
    } else {
      onUpdateSettings({
        ...settings,
        preset,
        autoBlockMaliciousLinks: true,
        mlTrafficInspection: true,
        walletSignatureGuard: true,
        realtimePushAlerts: true,
        sandboxUntrustedRedirects: true,
      });
    }
  };

  const toggleWidget = (id: DashboardWidgetId) => {
    onUpdateWidgets(
      widgets.map((w) => (w.id === id ? { ...w, visible: !w.visible } : w))
    );
  };

  const moveWidget = (id: DashboardWidgetId, direction: -1 | 1) => {
    const ordered = [...sortedWidgets];
    const idx = ordered.findIndex((w) => w.id === id);
    const targetIdx = idx + direction;
    if (idx < 0 || targetIdx < 0 || targetIdx >= ordered.length) return;
    const temp = ordered[idx];
    ordered[idx] = ordered[targetIdx];
    ordered[targetIdx] = temp;
    onUpdateWidgets(ordered.map((w, i) => ({ ...w, order: i })));
  };

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    onQuickScanUrl(quickUrl.trim());
  };

  // ML Traffic Feature Baseline bars derived from latest logs
  const featureAverages = useMemo(() => {
    const sample = logs.slice(0, 8);
    if (sample.length === 0) {
      return [];
    }
    const avg = (key: keyof ThreatLogEntry['features']) =>
      Math.round(sample.reduce((sum, l) => sum + (l.features?.[key] ?? 0), 0) / sample.length);
    return [
      { label: '字元熵值異常', value: avg('entropyScore') },
      { label: '網域詞彙風險', value: avg('lexicalAnomaly') },
      { label: '品牌仿冒特徵', value: avg('homographRisk') },
      { label: '轉址跳轉深度', value: avg('redirectDepthRisk') },
      { label: '載荷簽章風險', value: avg('payloadSignatureRisk') },
    ];
  }, [logs]);

  return (
    <div className="space-y-6">
      {/* Top Quick Protection & Instant URL Check Hero Panel */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="max-w-2xl space-y-1.5">
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span>自動化機器學習防護中樞</span>
              <span aria-hidden="true">·</span>
              <span>{isOnline ? '雲端與本機雙引擎即時同步' : '離線快取防禦模式運行中'}</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50 text-balance">
              即時偵測可疑連結、惡意錢包授權與異常流量
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
              支援一般使用者一鍵啟用防護策略，同時為進階管理者提供自定義儀表板與深度溯源分析。
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setCustomizeMode((v) => !v)}
              className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                customizeMode
                  ? 'border-blue-600 bg-blue-50 text-blue-700 dark:border-blue-500 dark:bg-blue-950/60 dark:text-blue-300'
                  : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700'
              }`}
            >
              <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{customizeMode ? '完成儀表板自訂' : '自訂儀表板'}</span>
            </button>
          </div>
        </div>

        {/* Instant URL Scanner Bar */}
        <form onSubmit={handleQuickSubmit} className="mt-5 flex flex-col gap-2.5 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
            <input
              type="text"
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              placeholder="貼上欲檢測的網址或 dApp 連結進行 ML + AI 威脅特徵分析（例如 https://...）"
              className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2.5 pl-10 pr-9 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-blue-500"
            />
            {quickUrl && (
              <button
                type="button"
                onClick={() => setQuickUrl('')}
                aria-label="清除檢測網址"
                title="清除輸入內容"
                className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            )}
          </div>
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-blue-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>立即檢測</span>
            <ChevronRight className="h-4 w-4" aria-hidden="true" />
          </button>
        </form>

        {/* Simple Beginner Presets */}
        <div className="mt-5 pt-5 border-t border-slate-100 dark:border-slate-800">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <span className="text-xs font-medium text-slate-600 dark:text-slate-400">
              簡易防護等級預設：
            </span>
            <div className="flex flex-wrap gap-1.5 rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
              {PRESETS.map((p) => {
                const active = settings.preset === p.id;
                return (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => applyPreset(p.id)}
                    title={p.desc}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      active
                        ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                        : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                    }`}
                  >
                    {p.label}
                  </button>
                );
              })}
            </div>
          </div>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {PRESETS.find((p) => p.id === settings.preset)?.desc}
          </p>
        </div>
      </section>

      {/* Customize Widgets Drawer Bar */}
      {customizeMode && (
        <section className="rounded-xl border border-blue-200 bg-blue-50/50 p-4 dark:border-blue-900/60 dark:bg-blue-950/20">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              自定義儀表板模組顯示與排序
            </h2>
            <span className="text-xs text-slate-500 dark:text-slate-400">設定自動儲存於本機</span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {sortedWidgets.map((w, idx) => (
              <div
                key={w.id}
                className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 dark:border-slate-800 dark:bg-slate-900"
              >
                <button
                  type="button"
                  onClick={() => toggleWidget(w.id)}
                  className="flex items-center gap-2 text-xs font-medium text-slate-800 dark:text-slate-200 cursor-pointer truncate"
                >
                  {w.visible ? (
                    <Eye className="h-3.5 w-3.5 text-blue-600 shrink-0" />
                  ) : (
                    <EyeOff className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                  )}
                  <span className={w.visible ? '' : 'line-through text-slate-400'}>{w.title}</span>
                </button>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    disabled={idx === 0}
                    onClick={() => moveWidget(w.id, -1)}
                    aria-label={`上移 ${w.title}`}
                    className="rounded p-1 text-slate-500 hover:bg-slate-100 disabled:opacity-30 dark:hover:bg-slate-800 cursor-pointer"
                  >
                    <ArrowUp className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    disabled={idx === sortedWidgets.length - 1}
                    onClick={() => moveWidget(w.id, 1)}
                    aria-label={`下移 ${w.title}`}
                    className="rounded p-1 text-slate-500 hover:bg-slate-100 disabled:opacity-30 dark:hover:bg-slate-800 cursor-pointer"
                  >
                    <ArrowDown className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* 4-Column Tabular KPI Strip */}
      <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500 dark:text-slate-400">已攔截 / 隔離威脅</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {stats.blocked}
          </div>
          <div className="mt-1 text-xs text-emerald-700 dark:text-emerald-400">
            自動阻斷生效中
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500 dark:text-slate-400">ML 特徵判別信心</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {stats.avgConfidence !== null ? `${stats.avgConfidence}%` : '—'}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {stats.avgConfidence !== null ? '6 維度流量特徵模型' : '執行正式掃描後統計'}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500 dark:text-slate-400">Web3 錢包防護攔截</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {stats.web3Threats}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Permit2 / 盲簽過濾
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500 dark:text-slate-400">零信任原則啟用數</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {stats.activePolicies} / {policies.length}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {session ? '已通過高信任驗證' : '標準存取模式'}
          </div>
        </div>
      </section>

      {/* Customizable Modular Grid */}
      <div className="grid gap-6 lg:grid-cols-2">
        {sortedWidgets
          .filter((w) => w.visible)
          .map((widget) => {
            if (widget.id === 'system_perf') {
              return <SystemPerformanceWidget key={widget.id} isOnline={isOnline} />;
            }

            if (widget.id === 'threat_trend') {
              return (
                <ThreatTrendChart
                  key={widget.id}
                  logs={logs}
                  onNavigateLogs={() => onNavigate('logs')}
                />
              );
            }

            if (widget.id === 'geo_heatmap') {
              return (
                <ThreatGeoHeatmap
                  key={widget.id}
                  logs={logs}
                  onInspectLog={(log) => {
                    onSelectLog(log);
                    onNavigate('logs');
                  }}
                />
              );
            }

            if (widget.id === 'ml_traffic') {
              return (
                <section
                  key={widget.id}
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                        {widget.title}
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        近期攔截樣本平均風險特徵分佈（0–100 權重指標）
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => onNavigate('scanner')}
                      className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      開啟檢測器
                    </button>
                  </div>

                  {featureAverages.length === 0 ? (
                    <div className="mt-5 rounded-lg border border-slate-100 bg-slate-50 px-4 py-8 text-center dark:border-slate-800 dark:bg-slate-950">
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        尚無掃描特徵樣本，執行正式連結或錢包掃描後將即時呈現平均風險權重。
                      </p>
                      <button
                        type="button"
                        onClick={() => onNavigate('scanner')}
                        className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 transition-colors cursor-pointer"
                      >
                        <span>前往正式掃描</span>
                        <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  ) : (
                    <div className="mt-5 space-y-3.5">
                      {featureAverages.map((item) => (
                        <div key={item.label} className="space-y-1.5">
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-slate-700 dark:text-slate-300">{item.label}</span>
                            <span className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                              {item.value} / 100
                            </span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                            <div
                              className={`h-full rounded-full transition-all duration-300 ${
                                item.value >= 70
                                  ? 'bg-red-600 dark:bg-red-500'
                                  : item.value >= 45
                                  ? 'bg-amber-500'
                                  : 'bg-blue-600 dark:bg-blue-500'
                              }`}
                              style={{ width: `${item.value === 0 ? 0 : Math.max(4, item.value)}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              );
            }

            if (widget.id === 'threat_feed') {
              return (
                <section
                  key={widget.id}
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                        {widget.title}
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        點擊任一事件可檢視溯源路徑與 AI 主動修補建議
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => onNavigate('logs')}
                      className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      完整日誌
                    </button>
                  </div>

                  {logs.length === 0 ? (
                    <div className="mt-5 rounded-lg border border-slate-100 bg-slate-50 px-4 py-8 text-center dark:border-slate-800 dark:bg-slate-950">
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        目前尚無正式掃描與攔截事件紀錄。
                      </p>
                      <button
                        type="button"
                        onClick={() => onNavigate('scanner')}
                        className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 transition-colors cursor-pointer"
                      >
                        <span>立即執行正式掃描</span>
                        <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  ) : (
                    <div className="mt-4 divide-y divide-slate-100 dark:divide-slate-800">
                      {logs.slice(0, 4).map((log) => (
                        <div
                          key={log.id}
                          className="flex items-start gap-2 py-3 hover:bg-slate-50/80 dark:hover:bg-slate-800/40 rounded-lg px-2 -mx-2 transition-colors"
                        >
                          <button
                            type="button"
                            onClick={() => {
                              onSelectLog(log);
                              onNavigate('logs');
                            }}
                            className="min-w-0 flex-1 text-left cursor-pointer"
                          >
                            <div className="flex items-center justify-between gap-3">
                              <SeverityText severity={log.severity} />
                              <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">
                                {log.platform} · {getActionLabel(log.action)} · 風險 {log.riskScore}
                              </span>
                            </div>
                            <div className="mt-1 truncate font-mono text-xs text-slate-800 dark:text-slate-200">
                              {log.target}
                            </div>
                            <div className="mt-0.5 truncate text-xs text-slate-500 dark:text-slate-400">
                              {getCategoryLabel(log.category)} · {log.summary}
                            </div>
                          </button>
                          {onDeleteLog && (
                            <button
                              type="button"
                              onClick={() => onDeleteLog(log.id)}
                              aria-label={`刪除威脅動態 ${log.id}`}
                              title="刪除此筆紀錄"
                              className="mt-0.5 rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:text-slate-500 dark:hover:bg-red-950/40 dark:hover:text-red-400 shrink-0 cursor-pointer"
                            >
                              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              );
            }

            if (widget.id === 'wallet_guard') {
              return (
                <section
                  key={widget.id}
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2.5">
                      <Wallet className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
                      <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                        {widget.title}
                      </h2>
                    </div>
                    <button
                      type="button"
                      onClick={() => onNavigate('scanner')}
                      className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      驗證錢包授權
                    </button>
                  </div>
                  <p className="mt-2 text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                    即時解析 dApp 連線與智能合約 Calldata，自動識別惡意無上限 Approve、setApprovalForAll 與 Permit2 離線盲簽詐騙。
                  </p>
                  <div className="mt-4 grid grid-cols-2 gap-3 border-t border-slate-100 pt-4 dark:border-slate-800 text-xs">
                    <div>
                      <div className="text-slate-500 dark:text-slate-400">無上限授權過濾</div>
                      <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                        {settings.walletSignatureGuard ? '強制攔截中' : '已暫停'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 dark:text-slate-400">盲簽 (eth_sign) 警示</div>
                      <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                        自動阻斷並解析原意
                      </div>
                    </div>
                  </div>
                </section>
              );
            }

            if (widget.id === 'zerotrust_status') {
              return (
                <section
                  key={widget.id}
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2.5">
                      <Lock className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
                      <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                        {widget.title}
                      </h2>
                    </div>
                    <button
                      type="button"
                      onClick={() => onNavigate('zerotrust')}
                      className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      管理權限
                    </button>
                  </div>
                  <p className="mt-2 text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                    所有高風險原則變更與開源 API 金鑰發行皆採用 HMAC-SHA256 短效工作階段驗證，落實最小權限控管。
                  </p>
                  <div className="mt-4 flex items-center justify-between border-t border-slate-100 pt-4 dark:border-slate-800 text-xs">
                    <span className="text-slate-500 dark:text-slate-400">
                      目前裝置狀態：{session ? `已認證 (${session.mfaMethod})` : '尚未執行高信任認證'}
                    </span>
                    <span className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                      {stats.activePolicies} 項啟用
                    </span>
                  </div>
                </section>
              );
            }

            return (
              <section
                key={widget.id}
                className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 lg:col-span-2"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-start gap-3">
                    <HardDrive className="mt-0.5 h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
                    <div>
                      <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                        {widget.title}
                      </h2>
                      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                        {backups.length > 0
                          ? `最近一次加密快照建立於 ${new Date(backups[0].createdAt).toLocaleString('zh-TW')} · SHA-256 驗證通過 (${backups[0].cipher})`
                          : '尚未建立抗勒索離線加密快照，建議立即將規則與威脅日誌封裝保存。'}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onNavigate('backup')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>前往加密備份保險庫</span>
                  </button>
                </div>
              </section>
            );
          })}
      </div>
    </div>
  );
};
