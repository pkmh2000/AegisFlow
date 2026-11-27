import React, { useMemo, useState } from 'react';
import {
  Bell,
  Download,
  FileSpreadsheet,
  Loader2,
  Search,
  Send,
  Sparkles,
} from 'lucide-react';
import type {
  AIRemediationPlan,
  AlertChannelConfig,
  ThreatLogEntry,
  ThreatSeverity,
} from '../types/security';
import { getActionLabel, getCategoryLabel, SeverityText } from './SeverityLabel';

interface LogAnalyzerViewProps {
  logs: ThreatLogEntry[];
  selectedLog: ThreatLogEntry | null;
  onSelectLog: (log: ThreatLogEntry) => void;
  onUpdateLogRemediation: (logId: string, plan: AIRemediationPlan) => void;
  alertChannels: AlertChannelConfig[];
  isOnline: boolean;
  onNotifyToast: (
    title: string,
    body: string,
    severity?: ThreatSeverity,
    meta?: { logId?: string; target?: string }
  ) => void;
}

export const LogAnalyzerView: React.FC<LogAnalyzerViewProps> = ({
  logs,
  selectedLog,
  onSelectLog,
  onUpdateLogRemediation,
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
