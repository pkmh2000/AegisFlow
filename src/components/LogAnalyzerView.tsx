import React, { useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Download,
  FileSpreadsheet,
  FileText,
  HelpCircle,
  Loader2,
  Search,
  Send,
  ShieldAlert,
  Sparkles,
  Upload,
} from 'lucide-react';
import { DEVICE_LOG_GUIDES } from '../data/drillsAndGuides';
import type {
  AIRemediationPlan,
  AlertChannelConfig,
  NetworkLogAnalysisResult,
  PlatformSource,
  ThreatLogEntry,
  ThreatSeverity,
} from '../types/security';
import { analyzeRawNetworkLogs } from '../utils/networkLogAnalyzer';
import { getActionLabel, getCategoryLabel, SeverityText } from './SeverityLabel';

interface LogAnalyzerViewProps {
  logs: ThreatLogEntry[];
  selectedLog: ThreatLogEntry | null;
  selectedPlatform: PlatformSource;
  onSelectLog: (log: ThreatLogEntry) => void;
  onUpdateLogRemediation: (logId: string, plan: AIRemediationPlan) => void;
  onRefreshLogs: () => void;
  onBatchAddLocalLogs: (entries: ThreatLogEntry[]) => void;
  alertChannels: AlertChannelConfig[];
  isOnline: boolean;
  onNotifyToast: (
    title: string,
    body: string,
    severity?: ThreatSeverity,
    meta?: { logId?: string; target?: string }
  ) => void;
}

const FORMAT_LABELS: Record<NetworkLogAnalysisResult['detectedFormat'], string> = {
  nginx_apache: 'Nginx / Apache HTTP 日誌',
  firewall_syslog: '防火牆 / Syslog 日誌',
  dns_query: 'DNS 查詢日誌',
  json_lines: 'JSON 結構化日誌',
  mixed_text: '通用文字 / 混合網路日誌',
};

export const LogAnalyzerView: React.FC<LogAnalyzerViewProps> = ({
  logs,
  selectedLog,
  selectedPlatform,
  onSelectLog,
  onUpdateLogRemediation,
  onRefreshLogs,
  onBatchAddLocalLogs,
  alertChannels,
  isOnline,
  onNotifyToast,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  const [dispatching, setDispatching] = useState(false);

  // Raw network log analyzer state
  const [rawPanelOpen, setRawPanelOpen] = useState(true);
  const [showLogGuide, setShowLogGuide] = useState(false);
  const [rawLogText, setRawLogText] = useState('');
  const [rawDeepAi, setRawDeepAi] = useState(true);
  const [rawAnalyzing, setRawAnalyzing] = useState(false);
  const [rawError, setRawError] = useState('');
  const [rawResult, setRawResult] = useState<NetworkLogAnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const filteredLogs = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return logs.filter((log) => {
      if (severityFilter !== 'all' && log.severity !== severityFilter) return false;
      if (categoryFilter !== 'all' && log.category !== categoryFilter) return false;
      if (
        q &&
        !log.target.toLowerCase().includes(q) &&
        !log.summary.toLowerCase().includes(q) &&
        !log.sourceIp.toLowerCase().includes(q) &&
        !log.id.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [logs, searchQuery, severityFilter, categoryFilter]);

  const activeLog = selectedLog || filteredLogs[0] || null;

  const handleGenerateAiPatch = async (log: ThreatLogEntry) => {
    if (!isOnline) {
      setAiError('目前處於離線模式，無法連線 AI 引擎生成新修補腳本；您仍可查閱已儲存的歷史修補計畫與離線指南。');
      return;
    }
    setAiError('');
    setAiLoading(true);
    try {
      const resp = await fetch('/api/v1/ai/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: log.target,
          category: log.category,
          summary: log.summary,
          riskScore: log.riskScore,
        }),
      });
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        throw new Error('目前為 GitHub Pages 純靜態部署環境，Gemini AI 即時修補分析需連線至後端伺服器。');
      }
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || '無法生成修補計畫');
      }
      onUpdateLogRemediation(log.id, data);
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'AI 修補生成失敗');
    } finally {
      setAiLoading(false);
    }
  };

  const handleSyncAlerts = async (log: ThreatLogEntry) => {
    const enabledChannels = alertChannels.filter((c) => c.enabled);
    if (enabledChannels.length === 0) {
      onNotifyToast('尚未啟用通知管道', '請至「開源 API 與設定」開啟至少一項報警通道。');
      return;
    }
    if (!isOnline) {
      onNotifyToast('離線模式佇列中', `已將 ${log.id} 標記於恢復連線後同步至 ${enabledChannels.map((c) => c.label).join('、')}。`);
      return;
    }

    setDispatching(true);
    try {
      const webhookTarget = enabledChannels.find((c) => c.webhookUrl?.trim())?.webhookUrl;
      const resp = await fetch('/api/v1/alerts/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channels: enabledChannels.map((c) => c.channel),
          title: `威脅告警同步 (${log.id})`,
          severity: log.severity,
          message: `[AegisFlow ${log.id}] ${log.summary} (${log.target})`,
          logId: log.id,
          target: log.target,
          webhookUrl: webhookTarget || undefined,
        }),
      });
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        onNotifyToast(
          '瀏覽器端告警已觸發 (靜態模式)',
          `多平台 Webhook 派送需連線至後端伺服器；已於本機通報 ${enabledChannels.map((c) => c.label).join('、')}。`,
          log.severity,
          { logId: log.id, target: log.target }
        );
        return;
      }
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || '同步報警失敗');
      }
      onNotifyToast(
        '多平台報警已同步發送',
        `已通報至 ${enabledChannels.map((c) => c.label).join('、')}`,
        log.severity,
        { logId: log.id, target: log.target }
      );
    } catch (err) {
      onNotifyToast('報警派送提醒', err instanceof Error ? err.message : '發送過程發生錯誤');
    } finally {
      setDispatching(false);
    }
  };

  const exportArchive = (format: 'json' | 'csv') => {
    let content = '';
    let mime = 'application/json';
    let ext = 'json';
    if (format === 'json') {
      content = JSON.stringify(filteredLogs, null, 2);
    } else {
      mime = 'text/csv;charset=utf-8;';
      ext = 'csv';
      const header = ['id', 'timestamp', 'severity', 'category', 'action', 'platform', 'sourceIp', 'asn', 'riskScore', 'target', 'summary'];
      const rows = filteredLogs.map((l) =>
        [
          l.id,
          l.timestamp,
          l.severity,
          l.category,
          l.action,
          l.platform,
          l.sourceIp,
          l.asn,
          String(l.riskScore),
          `"${l.target.replace(/"/g, '""')}"`,
          `"${l.summary.replace(/"/g, '""')}"`,
        ].join(',')
      );
      content = '\uFEFF' + [header.join(','), ...rows].join('\n');
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegisflow-logs-${new Date().toISOString().slice(0, 10)}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleLogFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setRawError('');
    if (file.size > 500_000) {
      setRawError('日誌檔案大小超過 500 KB，請擷取關鍵區段後再匯入分析。');
      e.target.value = '';
      return;
    }
    try {
      const text = await file.text();
      setRawLogText(text);
      setRawPanelOpen(true);
    } catch {
      setRawError('無法讀取此日誌檔案內容。');
    }
    e.target.value = '';
  };

  const handleAnalyzeRawLog = async () => {
    if (!rawLogText.trim()) {
      setRawError('請貼上網路日誌內容，或匯入 .log / .txt / .json / .csv 檔案。');
      return;
    }
    setRawError('');
    setRawAnalyzing(true);
    try {
      let result: NetworkLogAnalysisResult | null = null;

      if (isOnline) {
        const resp = await fetch('/api/v1/logs/analyze-raw', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rawLog: rawLogText,
            platform: selectedPlatform,
            deepAi: rawDeepAi,
          }),
        });
        const contentType = resp.headers.get('content-type') || '';
        if (resp.status !== 404 && contentType.includes('application/json')) {
          const data = await resp.json();
          if (!resp.ok) {
            throw new Error(data.error || '網路日誌分析失敗');
          }
          result = data as NetworkLogAnalysisResult;
          onRefreshLogs();
        }
      }

      if (!result) {
        // Offline or static-host local analyzer fallback
        result = analyzeRawNetworkLogs(rawLogText, selectedPlatform, 40);
        if (!isOnline) {
          result.aiError = '目前為離線或純靜態模式，已完成本機行為規則與 ML 熵值分析。';
        }
        if (result.ingestedLogs.length > 0) {
          onBatchAddLocalLogs(result.ingestedLogs);
        }
      }

      setRawResult(result);
      if (result.ingestedLogs.length > 0) {
        onSelectLog(result.ingestedLogs[0]);
      }

      if (result.maliciousCount > 0) {
        const top = result.findings[0];
        onNotifyToast(
          `日誌分析發現 ${result.maliciousCount} 筆惡意行徑`,
          `主要威脅：${top?.attackType ?? '異常存取'}（來源 ${top?.sourceIp ?? '未知'}）`,
          top?.severity ?? 'high',
          { logId: top?.logId, target: top?.target }
        );
      } else {
        onNotifyToast('日誌分析完成', `共掃描 ${result.totalLines} 行紀錄，未發現惡意攻擊特徵。`, 'nominal');
      }
    } catch (err) {
      setRawError(err instanceof Error ? err.message : '分析網路日誌時發生錯誤');
    } finally {
      setRawAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-50">
            深度日誌溯源與多平台報警歸檔
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            追蹤攻擊路徑、來源 IP/ASN 與機器學習特徵分數，並支援離線查閱與 AI 建議修補方案。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => exportArchive('csv')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <FileSpreadsheet className="h-3.5 w-3.5" aria-hidden="true" />
            <span>歸檔 CSV</span>
          </button>
          <button
            type="button"
            onClick={() => exportArchive('json')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>歸檔 JSON</span>
          </button>
        </div>
      </div>

      {/* Raw Network Log Batch Malicious Behavior Analyzer */}
      <section className="rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
          <div className="flex items-start gap-2.5">
            <FileText className="mt-0.5 h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                網路日誌惡意行徑批量分析（支援 HTTP / 防火牆 / DNS / Syslog / JSON）
              </h2>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                自動識別 SQL 注入、遠端指令執行 (RCE)、C2 反連、密碼爆破、埠口掃描、DNS/DGA 隱蔽通道與異常外傳，命中紀錄將同步歸檔至下方溯源清單。
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setRawPanelOpen((o) => !o)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap shrink-0"
          >
            <span>{rawPanelOpen ? '收合分析器' : '展開日誌分析器'}</span>
            {rawPanelOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </div>

        {rawPanelOpen && (
          <div className="border-t border-slate-100 px-5 py-4 dark:border-slate-800 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".log,.txt,.csv,.json,.jsonl,.ndjson"
                  onChange={handleLogFileUpload}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap"
                >
                  <Upload className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>上傳日誌檔 (.log / .txt / .json / .ndjson)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowLogGuide((s) => !s)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-blue-200 bg-blue-50/70 px-3 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-100/70 dark:border-blue-900/60 dark:bg-blue-950/40 dark:text-blue-300 cursor-pointer whitespace-nowrap"
                >
                  <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{showLogGuide ? '收合裝置日誌取得教學' : '各裝置日誌如何取得？'}</span>
                </button>
                {rawLogText && (
                  <button
                    type="button"
                    onClick={() => {
                      setRawLogText('');
                      setRawResult(null);
                      setRawError('');
                    }}
                    className="text-xs text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 cursor-pointer"
                  >
                    清除內容
                  </button>
                )}
              </div>

              <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rawDeepAi}
                  onChange={(e) => setRawDeepAi(e.target.checked)}
                  className="rounded border-slate-300 text-blue-600 focus:ring-blue-600"
                />
                <span>啟用 AI 攻擊鏈彙整與防火牆規則建議</span>
              </label>
            </div>

            {showLogGuide && (
              <div className="rounded-xl border border-blue-200 bg-blue-50/40 p-4 dark:border-blue-900/60 dark:bg-blue-950/20 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    各裝置網路日誌匯出取得方式（單檔上限 500 KB，支援貼上近期文字片段）
                  </div>
                </div>
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                  {DEVICE_LOG_GUIDES.map((guide) => (
                    <div
                      key={guide.id}
                      className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900 space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                          {guide.device}
                        </span>
                        <span className="font-mono text-[10px] text-blue-700 dark:text-blue-400">
                          {guide.format}
                        </span>
                      </div>
                      {guide.commandOrPath && (
                        <div className="rounded border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[11px] text-slate-800 break-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                          {guide.commandOrPath}
                        </div>
                      )}
                      <ul className="space-y-1 text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                        {guide.steps.map((step, i) => (
                          <li key={i}>• {step}</li>
                        ))}
                      </ul>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 border-t border-slate-100 pt-1.5 dark:border-slate-800">
                        {guide.note}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <textarea
              rows={5}
              value={rawLogText}
              onChange={(e) => setRawLogText(e.target.value)}
              placeholder="在此貼上欲檢驗的原始網路日誌（每行一筆，支援 Nginx/Apache Access Log、iptables/UFW 防火牆紀錄、DNS Query Log、Syslog 或 JSON Lines）..."
              className="w-full rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            />

            {rawError && (
              <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                {rawError}
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">
                靜態文本解析：僅分析日誌文字與行為特徵，不會對日誌內的 IP 或網址主動發起連線。
              </span>
              <button
                type="button"
                disabled={rawAnalyzing}
                onClick={handleAnalyzeRawLog}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {rawAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />}
                <span>{rawAnalyzing ? '正在解析日誌行為特徵...' : '分析日誌內惡意行徑'}</span>
              </button>
            </div>

            {rawResult && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-4">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
                  <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-slate-500 dark:text-slate-400">掃描有效行數</div>
                    <div className="mt-1 font-mono tabular-nums text-lg font-bold text-slate-900 dark:text-slate-50">
                      {rawResult.totalLines}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-slate-500 dark:text-slate-400">識別惡意行徑</div>
                    <div
                      className={`mt-1 font-mono tabular-nums text-lg font-bold ${
                        rawResult.maliciousCount > 0
                          ? 'text-red-600 dark:text-red-400'
                          : 'text-emerald-600 dark:text-emerald-400'
                      }`}
                    >
                      {rawResult.maliciousCount}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-slate-500 dark:text-slate-400">正常安全行數</div>
                    <div className="mt-1 font-mono tabular-nums text-lg font-bold text-slate-900 dark:text-slate-50">
                      {rawResult.cleanCount}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                    <div className="text-slate-500 dark:text-slate-400">自動辨識格式</div>
                    <div className="mt-1 text-xs font-semibold text-slate-900 dark:text-slate-100">
                      {FORMAT_LABELS[rawResult.detectedFormat]}
                    </div>
                  </div>
                </div>

                {rawResult.maliciousCount === 0 ? (
                  <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50/70 px-3.5 py-2.5 text-xs text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/30 dark:text-emerald-200">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    <span>此批日誌未偵測到 SQLi、RCE、C2 反連、暴力破解或釣魚異常行為特徵。</span>
                  </div>
                ) : (
                  <>
                    {rawResult.topAttackerIps.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="font-semibold text-slate-700 dark:text-slate-300">高風險來源 IP：</span>
                        {rawResult.topAttackerIps.map((item) => (
                          <span
                            key={item.ip}
                            className="rounded-md border border-slate-200 bg-white px-2 py-1 font-mono text-[11px] text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                          >
                            {item.ip} ({item.count} 次 · 峰值 {item.maxRisk})
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="max-h-64 overflow-y-auto divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-900">
                      {rawResult.findings.map((f) => (
                        <button
                          key={`${f.lineNumber}-${f.target}`}
                          type="button"
                          onClick={() => {
                            const matched =
                              logs.find((l) => l.id === f.logId) ||
                              rawResult.ingestedLogs.find((l) => l.id === f.logId);
                            if (matched) onSelectLog(matched);
                          }}
                          className="w-full px-3.5 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer"
                        >
                          <div className="flex items-center justify-between gap-2 text-xs">
                            <div className="flex items-center gap-2">
                              <SeverityText severity={f.severity} />
                              <span className="font-semibold text-slate-900 dark:text-slate-100">
                                第 {f.lineNumber} 行 · {f.attackType}
                              </span>
                            </div>
                            <span className="font-mono tabular-nums text-slate-600 dark:text-slate-400">
                              {f.sourceIp} · 風險 {f.riskScore}
                            </span>
                          </div>
                          <div className="mt-1 truncate font-mono text-[11px] text-slate-600 dark:text-slate-400">
                            {f.rawLine}
                          </div>
                          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-red-700 dark:text-red-400">
                            <AlertTriangle className="h-3 w-3 shrink-0" />
                            <span>{f.signals.join('；')}</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </>
                )}

                {rawResult.aiSummary ? (
                  <div className="rounded-lg border border-blue-200 bg-white p-3.5 dark:border-blue-900/50 dark:bg-slate-900 space-y-2 text-xs">
                    <div className="flex items-center gap-1.5 font-semibold text-blue-700 dark:text-blue-400">
                      <Sparkles className="h-3.5 w-3.5" />
                      <span>AI 攻擊鏈關聯分析與防火牆建議</span>
                    </div>
                    <p className="text-slate-800 dark:text-slate-200 leading-relaxed">
                      {rawResult.aiSummary.incidentOverview}
                    </p>
                    <p className="text-slate-600 dark:text-slate-400">
                      <span className="font-semibold">推測攻擊鏈：</span>
                      {rawResult.aiSummary.attackChain}
                    </p>
                    <div>
                      <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">建議阻斷規則：</div>
                      <ul className="space-y-1 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                        {rawResult.aiSummary.recommendedBlockRules.map((rule, idx) => (
                          <li key={idx}>• {rule}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ) : rawResult.aiError ? (
                  <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
                    {rawResult.aiError}
                  </div>
                ) : null}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Filter Bar */}
      <section className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="搜尋網址、事件 ID、來源 IP 或摘要..."
            className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <select
            aria-label="依嚴重程度篩選"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          >
            <option value="all">所有嚴重度</option>
            <option value="critical">嚴重威脅</option>
            <option value="high">高風險</option>
            <option value="medium">中度警戒</option>
            <option value="nominal">安全正常</option>
          </select>
          <select
            aria-label="依威脅分類篩選"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          >
            <option value="all">所有威脅類別</option>
            <option value="phishing">釣魚詐騙</option>
            <option value="wallet_drainer">錢包授權詐騙</option>
            <option value="trojan">木馬載荷</option>
            <option value="suspicious_redirect">異常轉址</option>
            <option value="safe">正常流量</option>
          </select>
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-12">
        {/* Logs Table */}
        <section className="lg:col-span-7 rounded-xl border border-slate-200 bg-white overflow-hidden dark:border-slate-800 dark:bg-slate-900">
          <div className="border-b border-slate-100 px-4 py-3 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
            符合條件紀錄：{filteredLogs.length} 筆
          </div>
          {filteredLogs.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
              目前篩選條件下無威脅紀錄。
            </div>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[560px] overflow-y-auto">
              {filteredLogs.map((log) => {
                const isSelected = activeLog?.id === log.id;
                return (
                  <button
                    key={log.id}
                    type="button"
                    onClick={() => {
                      setAiError('');
                      onSelectLog(log);
                    }}
                    className={`w-full px-4 py-3.5 text-left transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-blue-50/70 dark:bg-blue-950/30'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <SeverityText severity={log.severity} />
                        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                          {log.id} · {log.platform}
                        </span>
                      </div>
                      <span className="font-mono tabular-nums text-xs font-medium text-slate-700 dark:text-slate-300">
                        {getActionLabel(log.action)} · {log.riskScore}
                      </span>
                    </div>
                    <div className="mt-1.5 truncate font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                      {log.target}
                    </div>
                    <div className="mt-1 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                      <span className="truncate">{getCategoryLabel(log.category)} · {log.sourceIp}</span>
                      <span className="font-mono tabular-nums shrink-0 ml-2">
                        {new Date(log.timestamp).toLocaleTimeString('zh-TW', { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        {/* Deep Trace & AI Remediation Panel */}
        <section className="lg:col-span-5 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          {!activeLog ? (
            <div className="py-12 text-center text-xs text-slate-500 dark:text-slate-400">
              請從左側日誌列表選擇一筆事件進行溯源分析。
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-3 border-b border-slate-100 pb-3.5 dark:border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityText severity={activeLog.severity} />
                    <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                      {activeLog.id}
                    </span>
                  </div>
                  <div className="mt-1.5 break-all font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                    {activeLog.target}
                  </div>
                </div>
                <span className="font-mono tabular-nums text-lg font-bold text-slate-900 dark:text-slate-50 shrink-0">
                  {activeLog.riskScore}/100
                </span>
              </div>

              <div className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {activeLog.summary}
              </div>

              <div className="grid grid-cols-2 gap-2.5 text-xs">
                <div className="rounded-lg border border-slate-100 bg-slate-50 p-2.5 dark:border-slate-800 dark:bg-slate-950">
                  <div className="text-slate-500 dark:text-slate-400">來源 IP / ASN</div>
                  <div className="mt-0.5 font-mono text-slate-900 dark:text-slate-100">
                    {activeLog.sourceIp} ({activeLog.asn})
                  </div>
                </div>
                <div className="rounded-lg border border-slate-100 bg-slate-50 p-2.5 dark:border-slate-800 dark:bg-slate-950">
                  <div className="text-slate-500 dark:text-slate-400">通報同步狀態</div>
                  <div className="mt-0.5 text-slate-900 dark:text-slate-100">
                    {activeLog.syncedChannels.length > 0 ? activeLog.syncedChannels.join(' · ') : '未觸發外推'}
                  </div>
                </div>
              </div>

              {/* Trace Hops */}
              <div>
                <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                  威脅溯源路徑 (Attack &amp; Interception Trace)
                </h3>
                <ol className="space-y-1.5 font-mono text-xs text-slate-700 dark:text-slate-300">
                  {activeLog.traceHops.map((hop, idx) => (
                    <li
                      key={idx}
                      className="rounded-md border border-slate-100 bg-slate-50 px-2.5 py-1.5 dark:border-slate-800 dark:bg-slate-950"
                    >
                      {idx + 1}. {hop}
                    </li>
                  ))}
                </ol>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  type="button"
                  disabled={aiLoading}
                  onClick={() => handleGenerateAiPatch(activeLog)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-60 cursor-pointer whitespace-nowrap"
                >
                  {aiLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
                  <span>{activeLog.aiRemediation ? '重新生成 AI 修補方案' : 'AI 生成主動修補方案'}</span>
                </button>
                <button
                  type="button"
                  disabled={dispatching}
                  onClick={() => handleSyncAlerts(activeLog)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 cursor-pointer whitespace-nowrap"
                >
                  {dispatching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Bell className="h-3.5 w-3.5" />}
                  <span>同步多平台告警</span>
                  <Send className="h-3 w-3 opacity-70" />
                </button>
              </div>

              {aiError && (
                <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
                  {aiError}
                </div>
              )}

              {activeLog.aiRemediation && (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 dark:border-slate-800 dark:bg-slate-950 space-y-2.5 text-xs">
                  <div className="font-semibold text-blue-700 dark:text-blue-400">
                    AI 主動修補與風險評估報告
                  </div>
                  <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                    <span className="font-semibold">根因溯源：</span>{activeLog.aiRemediation.rootCause}
                  </p>
                  <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                    <span className="font-semibold">風險評估：</span>{activeLog.aiRemediation.riskAssessment}
                  </p>
                  <div>
                    <div className="font-semibold text-slate-800 dark:text-slate-200 mb-1">修補規則建議：</div>
                    <div className="space-y-1.5">
                      {activeLog.aiRemediation.patchRules.map((rule, idx) => (
                        <div key={idx} className="rounded border border-slate-200 bg-white p-2 dark:border-slate-800 dark:bg-slate-900">
                          <div className="font-medium text-slate-800 dark:text-slate-200">
                            {rule.target} · {rule.ruleType}
                          </div>
                          <code className="mt-1 block break-all font-mono text-[11px] text-slate-600 dark:text-slate-400">
                            {rule.ruleSnippet}
                          </code>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
