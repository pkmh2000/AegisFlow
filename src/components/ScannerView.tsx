import React, { useEffect, useState } from 'react';
import {
  AlertOctagon,
  CheckCircle2,
  Cpu,
  Globe,
  Loader2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wallet,
  X,
} from 'lucide-react';
import type { PlatformSource, ThreatLogEntry, ThreatSeverity, URLScanResult, WalletScanResult } from '../types/security';
import { scanUrlLocally, scanWalletLocally } from '../utils/clientScanner';
import { getCategoryLabel, SeverityText } from './SeverityLabel';

interface ScannerViewProps {
  initialUrl?: string;
  onClearInitialUrl?: () => void;
  selectedPlatform: PlatformSource;
  onSelectPlatform: (platform: PlatformSource) => void;
  isOnline: boolean;
  onScanComplete: () => void;
  onAddLocalLog?: (entry: ThreatLogEntry) => void;
  onNotifyThreat: (
    title: string,
    body: string,
    severity?: ThreatSeverity,
    meta?: { logId?: string; target?: string }
  ) => void;
}

export const ScannerView: React.FC<ScannerViewProps> = ({
  initialUrl = '',
  onClearInitialUrl,
  selectedPlatform,
  onSelectPlatform,
  isOnline,
  onScanComplete,
  onAddLocalLog,
  onNotifyThreat,
}) => {
  const [mode, setMode] = useState<'url' | 'wallet'>('url');

  // URL scanner state
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [deepAi, setDeepAi] = useState(true);
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlError, setUrlError] = useState('');
  const [urlResult, setUrlResult] = useState<URLScanResult | null>(null);

  // Wallet scanner state
  const [dappUrl, setDappUrl] = useState('');
  const [contractAddress, setContractAddress] = useState('');
  const [methodSignature, setMethodSignature] = useState('Permit2.permitBatch');
  const [calldata, setCalldata] = useState('');
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletError, setWalletError] = useState('');
  const [walletResult, setWalletResult] = useState<WalletScanResult | null>(null);

  useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
      setMode('url');
    }
  }, [initialUrl]);

  const runUrlScan = async (targetUrl?: string) => {
    const urlToScan = (targetUrl ?? urlInput).trim();
    if (!urlToScan) {
      setUrlError('請輸入欲分析的網址或網域。');
      return;
    }

    setUrlError('');
    setUrlLoading(true);
    try {
      if (isOnline) {
        const resp = await fetch('/api/v1/scan/url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlToScan, platform: selectedPlatform, deepAi }),
        });
        const contentType = resp.headers.get('content-type') || '';
        if (resp.status !== 404 && contentType.includes('application/json')) {
          const data = await resp.json();
          if (!resp.ok) {
            throw new Error(data.error || '掃描失敗');
          }
          setUrlResult(data);
          onScanComplete();
          if (data.verdict === 'block' || data.verdict === 'warn') {
            onNotifyThreat(
              data.verdict === 'block' ? `已自動阻擋可疑連結 (${data.riskScore}/100)` : `可疑連結警示 (${data.riskScore}/100)`,
              `${data.normalizedHost} — ${data.signals?.[0] || '觸發機器學習風險特徵'}`,
              data.severity,
              { logId: data.logId, target: data.url }
            );
          }
          return;
        }
      }

      // Static-host (GitHub Pages) or offline local ML fallback
      const { result, logEntry } = scanUrlLocally(urlToScan, selectedPlatform);
      setUrlResult(result);
      onAddLocalLog?.(logEntry);
      if (result.verdict === 'block' || result.verdict === 'warn') {
        onNotifyThreat(
          result.verdict === 'block' ? `已自動阻擋可疑連結 (${result.riskScore}/100)` : `可疑連結警示 (${result.riskScore}/100)`,
          `${result.normalizedHost} — ${result.signals[0] || '觸發本機 ML 風險特徵'}`,
          result.severity,
          { logId: logEntry.id, target: result.url }
        );
      }
    } catch (err) {
      setUrlError(err instanceof Error ? err.message : '分析過程發生錯誤');
    } finally {
      setUrlLoading(false);
    }
  };

  const runWalletScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!dappUrl.trim()) {
      setWalletError('請輸入 dApp 來源網址。');
      return;
    }
    setWalletError('');
    setWalletLoading(true);
    try {
      if (isOnline) {
        const resp = await fetch('/api/v1/scan/wallet', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dappUrl,
            contractAddress,
            methodSignature,
            calldata,
            platform: selectedPlatform,
          }),
        });
        const contentType = resp.headers.get('content-type') || '';
        if (resp.status !== 404 && contentType.includes('application/json')) {
          const data = await resp.json();
          if (!resp.ok) {
            throw new Error(data.error || '錢包授權檢測失敗');
          }
          setWalletResult(data);
          onScanComplete();
          if (data.verdict === 'block' || data.verdict === 'warn') {
            onNotifyThreat(
              `Web3 錢包授權風險警告 (${data.riskScore}/100)`,
              data.humanReadableIntent,
              data.severity,
              { logId: data.logId, target: data.dappUrl }
            );
          }
          return;
        }
      }

      // Static-host (GitHub Pages) or offline local Web3 ABI fallback
      const { result, logEntry } = scanWalletLocally(
        dappUrl,
        contractAddress,
        methodSignature,
        calldata,
        selectedPlatform
      );
      setWalletResult(result);
      onAddLocalLog?.(logEntry);
      if (result.verdict === 'block' || result.verdict === 'warn') {
        onNotifyThreat(
          `Web3 錢包授權風險警告 (${result.riskScore}/100)`,
          result.humanReadableIntent,
          result.severity,
          { logId: logEntry.id, target: result.dappUrl }
        );
      }
    } catch (err) {
      setWalletError(err instanceof Error ? err.message : '錢包防護引擎呼叫失敗');
    } finally {
      setWalletLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Mode Switcher */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-50">
            即時威脅掃描與 Web3 錢包授權防護
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            透過 6 維度機器學習流量特徵模型與 AI 主動式修補分析，於點擊或簽署前自動阻斷詐騙風險。
          </p>
        </div>

        <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80 self-start">
          <button
            type="button"
            onClick={() => setMode('url')}
            className={`inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              mode === 'url'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
            }`}
          >
            <Globe className="h-3.5 w-3.5" aria-hidden="true" />
            <span>可疑連結 &amp; ML 流量分析</span>
          </button>
          <button
            type="button"
            onClick={() => setMode('wallet')}
            className={`inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              mode === 'wallet'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
            }`}
          >
            <Wallet className="h-3.5 w-3.5" aria-hidden="true" />
            <span>加密貨幣錢包防護</span>
          </button>
        </div>
      </div>

      {mode === 'url' ? (
        <div className="grid gap-6 lg:grid-cols-12">
          <section className="lg:col-span-5 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              輸入檢測目標與設備來源
            </h2>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <label htmlFor="url-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  目標網址 (HTTP / HTTPS)
                </label>
                {urlInput && (
                  <button
                    type="button"
                    onClick={() => {
                      setUrlInput('');
                      setUrlError('');
                      onClearInitialUrl?.();
                    }}
                    className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>清除網址</span>
                  </button>
                )}
              </div>
              <textarea
                id="url-input"
                rows={3}
                value={urlInput}
                onChange={(e) => {
                  const val = e.target.value;
                  setUrlInput(val);
                  if (!val) onClearInitialUrl?.();
                }}
                placeholder="https://example.com/..."
                className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label htmlFor="platform-select" className="flex items-center gap-1.5 text-xs font-medium text-slate-700 dark:text-slate-300">
                  <Lock className="h-3 w-3 text-blue-600 dark:text-blue-400" aria-hidden="true" />
                  <span>監控端點平台 (已鎖定固定)</span>
                </label>
                <select
                  id="platform-select"
                  value={selectedPlatform}
                  onChange={(e) => onSelectPlatform(e.target.value as PlatformSource)}
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                >
                  <option value="Browser">桌機瀏覽器擴充 (Browser)</option>
                  <option value="Windows">Windows 端點</option>
                  <option value="macOS">macOS 端點</option>
                  <option value="iOS">iOS PWA 防護</option>
                  <option value="Android">Android 行動裝置</option>
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex w-full items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-700 dark:border-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={deepAi}
                    onChange={(e) => setDeepAi(e.target.checked)}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-600"
                  />
                  <span>啟用 AI 建議修補</span>
                </label>
              </div>
            </div>

            <div className="text-[11px] text-slate-500 dark:text-slate-400">
              平台選擇將自動記憶並套用於後續 URL 與錢包掃描（切換分頁或重整皆保持固定）。
            </div>

            {urlError && (
              <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                {urlError}
              </div>
            )}

            <button
              type="button"
              disabled={urlLoading}
              onClick={() => runUrlScan()}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60 transition-colors cursor-pointer"
            >
              {urlLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cpu className="h-4 w-4" />}
              <span>{urlLoading ? '正在萃取流量特徵與 AI 研判...' : '執行即時分析與自動攔截判定'}</span>
            </button>

            <div className="flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50/70 px-3 py-2.5 text-[11px] leading-relaxed text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/25 dark:text-emerald-200">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
              <span>
                靜態沙箱安全保證：貼上連結僅在本機或後端進行字串語法、熵值特徵與 AI 語意解析，絕不會實際造訪該網址或下載檔案，不會造成木馬與釣魚侵入。
              </span>
            </div>
          </section>

          <section className="lg:col-span-7 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
            {!urlResult ? (
              <div className="flex h-full min-h-[320px] flex-col items-center justify-center text-center px-4">
                <Globe className="h-10 w-10 text-slate-300 dark:text-slate-700" aria-hidden="true" />
                <h3 className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                  等待輸入連結進行檢測
                </h3>
                <p className="mt-1 max-w-md text-xs text-slate-500 dark:text-slate-400">
                  掃描器會同步計算字元熵值、Punycode 仿冒風險、開放式轉址特徵，並結合 AI 主動生成防火牆與 DNS 修補建議。
                </p>
              </div>
            ) : (
              <div className="space-y-5">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between border-b border-slate-100 pb-4 dark:border-slate-800">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2.5">
                      <SeverityText severity={urlResult.severity} />
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        · {getCategoryLabel(urlResult.category)} · 信心度 {urlResult.mlConfidence}%
                      </span>
                    </div>
                    <div className="mt-1.5 break-all font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {urlResult.url}
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <div className="text-xs text-slate-500 dark:text-slate-400">ML 風險指數</div>
                    <div className="font-mono tabular-nums text-2xl font-bold text-slate-900 dark:text-slate-50">
                      {urlResult.riskScore} / 100
                    </div>
                  </div>
                </div>

                {/* Auto Interception Verdict */}
                <div
                  className={`flex items-start gap-3 rounded-lg border p-3.5 text-sm ${
                    urlResult.verdict === 'block'
                      ? 'border-red-200 bg-red-50/70 text-red-900 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-200'
                      : urlResult.verdict === 'warn'
                      ? 'border-amber-200 bg-amber-50/70 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200'
                      : 'border-emerald-200 bg-emerald-50/70 text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200'
                  }`}
                >
                  {urlResult.verdict === 'allow' ? (
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                  ) : (
                    <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold">
                      {urlResult.verdict === 'block'
                        ? '自動化防禦決策：已立即攔截阻斷並歸檔日誌'
                        : urlResult.verdict === 'warn'
                        ? '自動化防禦決策：中度疑慮，建議於隔離沙箱開啟'
                        : '自動化防禦決策：流量特徵正常，允許安全連線'}
                    </div>
                    <ul className="mt-1.5 space-y-1 text-xs opacity-90">
                      {urlResult.signals.map((sig, i) => (
                        <li key={i}>• {sig}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* 6-Dimension ML Feature Breakdown */}
                <div>
                  <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2.5">
                    流量特徵向量分解
                  </h3>
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 text-xs">
                    {[
                      ['字元熵值', urlResult.features.entropyScore],
                      ['詞彙異常', urlResult.features.lexicalAnomaly],
                      ['品牌仿冒', urlResult.features.homographRisk],
                      ['TLS 缺口', urlResult.features.tlsTrustGap],
                      ['轉址深度', urlResult.features.redirectDepthRisk],
                      ['載荷風險', urlResult.features.payloadSignatureRisk],
                    ].map(([label, score]) => (
                      <div key={String(label)} className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
                        <div className="text-slate-500 dark:text-slate-400">{label}</div>
                        <div className="mt-0.5 font-mono tabular-nums text-sm font-semibold text-slate-900 dark:text-slate-100">
                          {score} / 100
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* AI Proactive Patch */}
                {urlResult.aiAnalysis ? (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-semibold text-blue-700 dark:text-blue-400">
                      <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>AI 主動式風險研判與建議修補</span>
                    </div>
                    <p className="text-sm text-slate-800 dark:text-slate-200 leading-relaxed">
                      {urlResult.aiAnalysis.summary}
                    </p>
                    <div className="text-xs text-slate-600 dark:text-slate-400">
                      攻擊手法歸類：<span className="font-medium text-slate-900 dark:text-slate-200">{urlResult.aiAnalysis.attackTechnique}</span>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">建議立即處置步驟：</div>
                      <ol className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
                        {urlResult.aiAnalysis.remediationSteps.map((step, idx) => (
                          <li key={idx}>{idx + 1}. {step}</li>
                        ))}
                      </ol>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">主動修補規則建議：</div>
                      <pre className="overflow-x-auto rounded-md border border-slate-200 bg-white p-2.5 font-mono text-xs text-slate-800 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200">
                        {urlResult.aiAnalysis.proactivePatch}
                      </pre>
                    </div>
                  </div>
                ) : urlResult.aiError ? (
                  <div className="rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-2.5 text-xs text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
                    {urlResult.aiError}
                  </div>
                ) : null}
              </div>
            )}
          </section>
        </div>
      ) : (
        /* Web3 Wallet Guard */
        <div className="grid gap-6 lg:grid-cols-12">
          <form
            onSubmit={runWalletScan}
            className="lg:col-span-5 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4"
          >
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              錢包授權與合約簽名預檢
            </h2>
            <div className="space-y-1.5">
              <label htmlFor="dapp-url" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                dApp 來源網址
              </label>
              <div className="relative">
                <input
                  id="dapp-url"
                  type="text"
                  value={dappUrl}
                  onChange={(e) => setDappUrl(e.target.value)}
                  placeholder="https://app.example.com"
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-3 pr-9 font-mono text-xs text-slate-900 placeholder:text-slate-400 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                />
                {dappUrl && (
                  <button
                    type="button"
                    onClick={() => {
                      setDappUrl('');
                      setWalletError('');
                    }}
                    aria-label="清除 dApp 來源網址"
                    title="清除輸入內容"
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>
            </div>
            <div className="space-y-1.5">
              <label htmlFor="contract-addr" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                授權目標合約地址 (Spender)
              </label>
              <div className="relative">
                <input
                  id="contract-addr"
                  type="text"
                  value={contractAddress}
                  onChange={(e) => setContractAddress(e.target.value)}
                  placeholder="0x..."
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-3 pr-9 font-mono text-xs text-slate-900 placeholder:text-slate-400 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                />
                {contractAddress && (
                  <button
                    type="button"
                    onClick={() => setContractAddress('')}
                    aria-label="清除合約地址"
                    title="清除輸入內容"
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>
            </div>
            <div className="space-y-1.5">
              <label htmlFor="method-sig" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                簽名 / 合約呼叫方法
              </label>
              <select
                id="method-sig"
                value={methodSignature}
                onChange={(e) => setMethodSignature(e.target.value)}
                className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              >
                <option value="Permit2.permitBatch">Permit2.permitBatch (離線批次授權)</option>
                <option value="approve">ERC20.approve (代幣授權)</option>
                <option value="setApprovalForAll">ERC721.setApprovalForAll (全系列 NFT 授權)</option>
                <option value="eth_sign">eth_sign (原始雜湊盲簽)</option>
                <option value="exactInputSingle">exactInputSingle (限額交換)</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <label htmlFor="calldata-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  交易 Calldata (選填)
                </label>
                {calldata && (
                  <button
                    type="button"
                    onClick={() => setCalldata('')}
                    className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>清除內容</span>
                  </button>
                )}
              </div>
              <textarea
                id="calldata-input"
                rows={2}
                value={calldata}
                onChange={(e) => setCalldata(e.target.value)}
                placeholder="0x...（若無可留空）"
                className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-400 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              />
            </div>

            <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs dark:border-slate-800 dark:bg-slate-950">
              <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
                <Lock className="h-3 w-3 text-blue-600 dark:text-blue-400" aria-hidden="true" />
                <span>目前固定監控平台：</span>
              </span>
              <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                {selectedPlatform}
              </span>
            </div>

            {walletError && (
              <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                {walletError}
              </div>
            )}

            <button
              type="submit"
              disabled={walletLoading}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60 transition-colors cursor-pointer"
            >
              {walletLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
              <span>{walletLoading ? '正在解析合約授權風險...' : '驗證錢包簽名安全'}</span>
            </button>

            <div className="flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50/70 px-3 py-2.5 text-[11px] leading-relaxed text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/25 dark:text-emerald-200">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
              <span>
                純靜態合約審計：僅解析您貼上的 dApp 網址、合約地址與 Calldata 簽名方法，絕不會主動觸發錢包彈窗或送出鏈上交易。
              </span>
            </div>
          </form>

          <section className="lg:col-span-7 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
            {!walletResult ? (
              <div className="flex h-full min-h-[320px] flex-col items-center justify-center text-center px-4">
                <Wallet className="h-10 w-10 text-slate-300 dark:text-slate-700" aria-hidden="true" />
                <h3 className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                  加密貨幣錢包授權預檢待命
                </h3>
                <p className="mt-1 max-w-md text-xs text-slate-500 dark:text-slate-400">
                  於錢包簽署交易前先檢驗來源 dApp、合約地址與 Calldata，防止惡意空投網站竊取資產控制權。
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-4 border-b border-slate-100 pb-4 dark:border-slate-800">
                  <div>
                    <SeverityText severity={walletResult.severity} />
                    <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {walletResult.methodSignature} · {walletResult.allowanceType}
                    </div>
                    <div className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                      {walletResult.dappUrl}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-xs text-slate-500 dark:text-slate-400">錢包風險指數</div>
                    <div className="font-mono tabular-nums text-2xl font-bold text-slate-900 dark:text-slate-50">
                      {walletResult.riskScore} / 100
                    </div>
                  </div>
                </div>

                <div
                  className={`rounded-lg border p-3.5 text-sm ${
                    walletResult.verdict === 'block'
                      ? 'border-red-200 bg-red-50/70 text-red-900 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-200'
                      : walletResult.verdict === 'warn'
                      ? 'border-amber-200 bg-amber-50/70 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200'
                      : 'border-emerald-200 bg-emerald-50/70 text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200'
                  }`}
                >
                  <div className="font-semibold">人類可讀授權意圖翻譯：</div>
                  <p className="mt-1 text-xs leading-relaxed">{walletResult.humanReadableIntent}</p>
                </div>

                <div>
                  <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">風險檢核明細：</div>
                  <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-400">
                    {walletResult.findings.map((f, idx) => (
                      <li key={idx}>• {f}</li>
                    ))}
                  </ul>
                </div>

                {walletResult.aiAssessment ? (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2 text-xs">
                    <div className="flex items-center gap-2 font-semibold text-blue-700 dark:text-blue-400">
                      <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>AI 智能合約安全評估</span>
                    </div>
                    <p className="text-sm text-slate-800 dark:text-slate-200">{walletResult.aiAssessment.summary}</p>
                    <div className="text-slate-600 dark:text-slate-400">
                      潛在盜幣途徑：{walletResult.aiAssessment.drainVector}
                    </div>
                    <div className="text-emerald-700 dark:text-emerald-400 font-medium">
                      安全替代建議：{walletResult.aiAssessment.safeAlternative}
                    </div>
                  </div>
                ) : walletResult.aiError ? (
                  <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
                    {walletResult.aiError}
                  </div>
                ) : null}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
};
