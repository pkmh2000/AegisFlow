import React, { useState } from 'react';
import { Bell, Check, Code2, Copy, Key, Play, Settings2, Volume2, X } from 'lucide-react';
import type {
  AlertChannelConfig,
  ProtectionSettings,
  ThreatSeverity,
  ZeroTrustSession,
} from '../types/security';
import { playCriticalAlertSound } from '../utils/alertSound';

interface OpenApiSettingsViewProps {
  settings: ProtectionSettings;
  onUpdateSettings: (next: ProtectionSettings) => void;
  alertChannels: AlertChannelConfig[];
  onUpdateAlertChannels: (next: AlertChannelConfig[]) => void;
  session: ZeroTrustSession | null;
  tokens: Array<{ id: string; name: string; prefix: string; scope: string; createdAt: string }>;
  onRefreshTokens: () => void;
  isOnline: boolean;
  onNotifyToast: (title: string, body: string, severity?: ThreatSeverity) => void;
}

export const OpenApiSettingsView: React.FC<OpenApiSettingsViewProps> = ({
  settings,
  onUpdateSettings,
  alertChannels,
  onUpdateAlertChannels,
  session,
  tokens,
  onRefreshTokens,
  isOnline,
  onNotifyToast,
}) => {
  const [newTokenName, setNewTokenName] = useState('');
  const [newTokenScope, setNewTokenScope] = useState<'read' | 'scan' | 'admin'>('scan');
  const [issuedSecret, setIssuedSecret] = useState('');
  const [tokenError, setTokenError] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [apiTestResult, setApiTestResult] = useState('');

  const originUrl = typeof window !== 'undefined' ? window.location.origin : 'https://your-aegisflow-host';

  const curlExample = `curl -X POST "${originUrl}/api/v1/scan/url" \\
  -H "Content-Type: application/json" \\
  -H "x-aegis-token: <YOUR_OPEN_API_TOKEN>" \\
  -d '{"url": "https://example-airdrop.xyz/claim", "platform": "API", "deepAi": true}'`;

  const tsExample = `const res = await fetch("${originUrl}/api/v1/scan/url", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-aegis-token": process.env.AEGIS_API_TOKEN!,
  },
  body: JSON.stringify({ url: targetUrl, platform: "API" }),
});
const verdict = await res.json();`;

  const copyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1800);
    } catch {
      // Ignore clipboard failure cleanly
    }
  };

  const handleIssueToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!session) {
      setTokenError('基於零信任原則，發行新 API Token 前請先至「零信任控管」完成裝置驗證。');
      return;
    }
    if (!isOnline) {
      setTokenError('離線模式下無法簽發 API 金鑰。');
      return;
    }
    setTokenError('');
    try {
      const resp = await fetch('/api/v1/tokens', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({ name: newTokenName, scope: newTokenScope }),
      });
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        throw new Error('目前為 GitHub Pages 純靜態部署環境，API Token 簽發需連線至 Node.js 後端伺服器。');
      }
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Token 建立失敗');
      setIssuedSecret(data.plaintextSecret);
      setNewTokenName('');
      onRefreshTokens();
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : '建立 Token 失敗');
    }
  };

  const runLiveHealthPing = async () => {
    if (!isOnline) {
      setApiTestResult('離線模式中：API 探索器已切換為離線文件檢視。');
      return;
    }
    try {
      const resp = await fetch('/api/v1/health');
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        setApiTestResult(
          JSON.stringify(
            {
              mode: 'static-github-pages',
              version: '1.0.0-beta.1',
              message: '目前運行於 GitHub Pages 靜態託管環境；本機端 ML 掃描與 AES-256 備份可正常運作，後端 REST API 端點需於 Node.js 伺服器啟動。',
            },
            null,
            2
          )
        );
        return;
      }
      const data = await resp.json();
      setApiTestResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setApiTestResult(err instanceof Error ? err.message : 'API 測試失敗');
    }
  };

  const toggleSetting = (key: keyof Omit<ProtectionSettings, 'preset'>) => {
    onUpdateSettings({
      ...settings,
      [key]: !settings[key],
    });
  };

  const toggleChannel = (id: string) => {
    onUpdateAlertChannels(
      alertChannels.map((c) => (c.id === id ? { ...c, enabled: !c.enabled } : c))
    );
  };

  const updateWebhookUrl = (id: string, webhookUrl: string) => {
    onUpdateAlertChannels(
      alertChannels.map((c) => (c.id === id ? { ...c, webhookUrl } : c))
    );
  };

  const requestBrowserPushPermission = async () => {
    if (typeof Notification === 'undefined') {
      onNotifyToast('不支援系統通知', '目前瀏覽器環境未提供原生 Notification API。');
      return;
    }
    const perm = await Notification.requestPermission();
    if (perm === 'granted') {
      new Notification('AegisFlow 即時威脅通知已啟用', {
        body: '當偵測到高風險釣魚連結或惡意錢包授權時，將第一時間警示您。',
      });
    } else {
      onNotifyToast('瀏覽器通知權限未開啟', '已改用應用程式內即時告警橫幅通知您。');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-50">
          開源 API 串接、多平台自動告警與簡易設定
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          提供標準化 RESTful API 供開發者串接既有的 SIEM / 防火牆生態系統，同時讓一般使用者輕鬆調整防禦與通知選項。
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-12">
        {/* Simple Protection Toggles */}
        <section className="lg:col-span-5 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">
          <div className="flex items-center gap-2">
            <Settings2 className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              簡易安全防護選項
            </h2>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
            {(
              [
                ['autoBlockMaliciousLinks', '自動阻擋高風險可疑連結', 'ML 風險值達標時立即攔截'],
                ['mlTrafficInspection', '機器學習流量特徵即時分析', '檢查字元熵值與品牌仿冒'],
                ['walletSignatureGuard', 'Web3 加密貨幣錢包授權保護', '過濾 Permit2 與無上限授權'],
                ['sandboxUntrustedRedirects', '可疑轉址強制隔離沙箱', '阻斷開放式轉址跳轉陷阱'],
                ['realtimePushAlerts', '即時威脅偵測通知警示', '發生攔截事件立刻推送警示'],
                ['alertSoundEnabled', '播放警示音', '偵測到嚴重 (critical) 威脅時播放資安警報音效'],
                ['multiPlatformLogSync', '多平台同步報警與日誌歸檔', '桌機、手機與 Webhook 同步'],
                ['offlineCacheEnabled', '離線瀏覽模式快取同步', '斷網時仍可查閱威脅報告與指南'],
              ] as const
            ).map(([key, label, desc]) => (
              <label
                key={key}
                className="flex items-center justify-between gap-3 py-3 cursor-pointer"
              >
                <div>
                  <div className="font-medium text-slate-900 dark:text-slate-100">{label}</div>
                  <div className="text-slate-500 dark:text-slate-400">{desc}</div>
                </div>
                <input
                  type="checkbox"
                  checked={settings[key]}
                  onChange={() => toggleSetting(key)}
                  className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600 shrink-0"
                />
              </label>
            ))}
          </div>
        </section>

        {/* Multi-Platform Alert Channels */}
        <section className="lg:col-span-7 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Bell className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                自動告警通知與多平台 Webhook
              </h2>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={async () => {
                  const ok = await playCriticalAlertSound();
                  if (!ok) {
                    onNotifyToast('無法播放音效', '請確認瀏覽器音效權限或系統音量設定。');
                  } else {
                    onNotifyToast('已試聽嚴重威脅警報音', '當偵測到 critical 等級威脅時將自動觸發此警示音效。', 'high');
                  }
                }}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap"
              >
                <Volume2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>試聽警示音</span>
              </button>
              <button
                type="button"
                onClick={requestBrowserPushPermission}
                className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap"
              >
                測試瀏覽器通知
              </button>
            </div>
          </div>

          <label className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-xs dark:border-slate-800 dark:bg-slate-950 cursor-pointer">
            <div className="flex items-center gap-2.5">
              <Volume2 className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
              <div>
                <div className="font-semibold text-slate-900 dark:text-slate-100">
                  播放警示音（高嚴重性威脅自動警報）
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  當偵測到 critical 等級木馬、釣魚或錢包抽乾威脅時，透過 Web Audio API 立即鳴響警示
                </div>
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.alertSoundEnabled}
              onChange={() => toggleSetting('alertSoundEnabled')}
              className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600 shrink-0"
            />
          </label>

          <div className="space-y-3">
            {alertChannels.map((ch) => (
              <div
                key={ch.id}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 dark:border-slate-800 dark:bg-slate-950 space-y-2"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      {ch.label}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      目標：{ch.targetSummary}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => toggleChannel(ch.id)}
                    className={`rounded-md px-3 py-1 text-xs font-medium cursor-pointer ${
                      ch.enabled
                        ? 'bg-blue-600 text-white'
                        : 'border border-slate-200 bg-white text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300'
                    }`}
                  >
                    {ch.enabled ? '已開啟' : '未啟用'}
                  </button>
                </div>

                {(ch.channel === 'Slack' || ch.channel === 'Discord') && (
                  <div className="relative">
                    <input
                      type="url"
                      value={ch.webhookUrl || ''}
                      onChange={(e) => updateWebhookUrl(ch.id, e.target.value)}
                      placeholder={`輸入 ${ch.channel} HTTPS Webhook 網址（系統自動阻擋內網 SSRF 位址）`}
                      className="w-full rounded-md border border-slate-200 bg-white py-1.5 pl-2.5 pr-8 font-mono text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                    />
                    {ch.webhookUrl && (
                      <button
                        type="button"
                        onClick={() => updateWebhookUrl(ch.id, '')}
                        aria-label={`清除 ${ch.channel} Webhook 網址`}
                        title="清除輸入內容"
                        className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                      >
                        <X className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Open-Source API Integration Section */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Code2 className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              開源 REST API 串接文件與開發者金鑰
            </h2>
          </div>
          <button
            type="button"
            onClick={runLiveHealthPing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer self-start"
          >
            <Play className="h-3.5 w-3.5" aria-hidden="true" />
            <span>測試 /api/v1/health 端點</span>
          </button>
        </div>

        {apiTestResult && (
          <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-800 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
            {apiTestResult}
          </pre>
        )}

        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-medium text-slate-700 dark:text-slate-300">
              <span>cURL 連結與流量掃描範例</span>
              <button
                type="button"
                onClick={() => copyText('curl', curlExample)}
                className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 cursor-pointer"
              >
                {copiedId === 'curl' ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedId === 'curl' ? '已複製' : '複製'}</span>
              </button>
            </div>
            <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-950 p-3.5 font-mono text-xs text-slate-100">
              {curlExample}
            </pre>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-medium text-slate-700 dark:text-slate-300">
              <span>TypeScript / Node.js SDK 整合範例</span>
              <button
                type="button"
                onClick={() => copyText('ts', tsExample)}
                className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 cursor-pointer"
              >
                {copiedId === 'ts' ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedId === 'ts' ? '已複製' : '複製'}</span>
              </button>
            </div>
            <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-950 p-3.5 font-mono text-xs text-slate-100">
              {tsExample}
            </pre>
          </div>
        </div>

        {/* API Token Issuance */}
        <div className="border-t border-slate-100 pt-4 dark:border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-800 dark:text-slate-200">
            <Key className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" aria-hidden="true" />
            <span>發行開源整合 API Token (需先完成零信任驗證)</span>
          </div>

          <form onSubmit={handleIssueToken} className="flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <input
                type="text"
                value={newTokenName}
                onChange={(e) => setNewTokenName(e.target.value)}
                placeholder="系統整合名稱（例如 Wazuh SIEM / 企業 Gateway）"
                className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-3 pr-9 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              />
              {newTokenName && (
                <button
                  type="button"
                  onClick={() => setNewTokenName('')}
                  aria-label="清除系統整合名稱"
                  title="清除輸入內容"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              )}
            </div>
            <select
              aria-label="API Token 權限範圍"
              value={newTokenScope}
              onChange={(e) => setNewTokenScope(e.target.value as 'read' | 'scan' | 'admin')}
              className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            >
              <option value="scan">scan (掃描與寫入日誌)</option>
              <option value="read">read (唯讀情資)</option>
              <option value="admin">admin (完整原則管理)</option>
            </select>
            <button
              type="submit"
              className="rounded-lg bg-slate-900 px-4 py-2 text-xs font-medium text-white hover:bg-slate-800 dark:bg-blue-600 dark:hover:bg-blue-500 cursor-pointer whitespace-nowrap"
            >
              建立金鑰
            </button>
          </form>

          {tokenError && (
            <div className="text-xs text-red-600 dark:text-red-400">{tokenError}</div>
          )}

          {issuedSecret && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200">
              <div className="font-semibold">新 API Token 已發行（僅顯示一次，請立即複製保存）：</div>
              <div className="mt-1 font-mono break-all select-all">{issuedSecret}</div>
            </div>
          )}

          <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
            {tokens.map((t) => (
              <div key={t.id} className="flex items-center justify-between py-2">
                <div>
                  <span className="font-medium text-slate-900 dark:text-slate-100">{t.name}</span>
                  <span className="ml-2 font-mono text-slate-500 dark:text-slate-400">
                    {t.prefix}... · {t.scope}
                  </span>
                </div>
                <span className="font-mono text-slate-500 dark:text-slate-400">
                  {new Date(t.createdAt).toLocaleDateString('zh-TW')}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};
