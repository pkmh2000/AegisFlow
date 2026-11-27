import React, { useRef, useState } from 'react';
import { CheckCircle2, Download, HardDrive, Lock, ShieldCheck, Upload } from 'lucide-react';
import type {
  AlertChannelConfig,
  BackupSnapshotMeta,
  ProtectionSettings,
  ThreatLogEntry,
} from '../types/security';
import { createEncryptedVault, decryptAndVerifyVault } from '../utils/cryptoVault';

interface BackupVaultViewProps {
  logs: ThreatLogEntry[];
  settings: ProtectionSettings;
  alertChannels: AlertChannelConfig[];
  backups: BackupSnapshotMeta[];
  onRecordBackup: (meta: BackupSnapshotMeta) => void;
  onRestoreBackup: (restored: {
    logs: ThreatLogEntry[];
    settings: ProtectionSettings;
    alertChannels: AlertChannelConfig[];
  }) => void;
}

export const BackupVaultView: React.FC<BackupVaultViewProps> = ({
  logs,
  settings,
  alertChannels,
  backups,
  onRecordBackup,
  onRestoreBackup,
}) => {
  const [passphrase, setPassphrase] = useState('');
  const [creating, setCreating] = useState(false);
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoring, setRestoring] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleCreateBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passphrase.trim().length < 8) {
      setStatusMessage({ type: 'err', text: '為防止暴力破解，加密主密碼長度至少需 8 個字元。' });
      return;
    }

    setCreating(true);
    setStatusMessage(null);
    try {
      const payload = { logs, settings, alertChannels, exportedAt: new Date().toISOString() };
      const { vault, jsonString } = await createEncryptedVault(payload, passphrase, logs.length);

      const blob = new Blob([jsonString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegisflow-snapshot-${new Date().toISOString().slice(0, 10)}.aegisvault`;
      a.click();
      URL.revokeObjectURL(url);

      onRecordBackup({
        id: `snap-${Date.now().toString(36)}`,
        createdAt: vault.createdAt,
        sha256: vault.sha256Plaintext,
        recordCount: vault.recordCount,
        sizeBytes: jsonString.length,
        cipher: 'AES-256-GCM',
      });

      setStatusMessage({
        type: 'ok',
        text: `已建立不可變 AES-256-GCM 離線備份並下載！SHA-256 校驗碼：${vault.sha256Plaintext.slice(0, 16)}...`,
      });
      setPassphrase('');
    } catch (err) {
      setStatusMessage({
        type: 'err',
        text: err instanceof Error ? err.message : '加密備份失敗',
      });
    } finally {
      setCreating(false);
    }
  };

  const handleFileRestore = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!restorePassphrase.trim()) {
      setStatusMessage({ type: 'err', text: '請先輸入解密密碼，再選擇 .aegisvault 備份檔。' });
      e.target.value = '';
      return;
    }

    setRestoring(true);
    setStatusMessage(null);
    try {
      const text = await file.text();
      const result = await decryptAndVerifyVault<{
        logs: ThreatLogEntry[];
        settings: ProtectionSettings;
        alertChannels: AlertChannelConfig[];
      }>(text, restorePassphrase);

      onRestoreBackup(result.data);
      setStatusMessage({
        type: 'ok',
        text: `SHA-256 完整性驗證通過！已成功還原 ${result.data.logs?.length ?? 0} 筆日誌與全部防護規則（快照時間：${new Date(result.createdAt).toLocaleString('zh-TW')}）。`,
      });
      setRestorePassphrase('');
    } catch (err) {
      setStatusMessage({
        type: 'err',
        text: err instanceof Error ? err.message : '備份還原失敗',
      });
    } finally {
      setRestoring(false);
      e.target.value = '';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-50">
          抗勒索軟體高強度加密備份機制
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          於瀏覽器端原生使用 Web Crypto API (PBKDF2 150,000 次疊代 + AES-256-GCM + SHA-256) 封裝防禦原則與威脅日誌，全程可於離線環境執行與還原。
        </p>
      </div>

      {statusMessage && (
        <div
          className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-xs ${
            statusMessage.type === 'ok'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200'
              : 'border-red-200 bg-red-50 text-red-900 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-200'
          }`}
        >
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{statusMessage.text}</span>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Create Encrypted Snapshot */}
        <form
          onSubmit={handleCreateBackup}
          className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4"
        >
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              建立不可變離線加密快照
            </h2>
          </div>

          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
            將目前 {logs.length} 筆威脅日誌、防護設定與多平台報警通道配置打包為單一防竄改檔案，建議另存於唯讀或氣隙離線載體。
          </p>

          <div className="space-y-1.5">
            <label htmlFor="vault-pass" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
              設定加密保護密碼 (至少 8 字元，系統不會儲存此密碼)
            </label>
            <input
              id="vault-pass"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="輸入高強度加密密碼..."
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>

          <button
            type="submit"
            disabled={creating}
            className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60 transition-colors cursor-pointer"
          >
            <Download className="h-4 w-4" aria-hidden="true" />
            <span>{creating ? '正在進行 AES-256-GCM 加密封裝...' : '匯出加密備份 (.aegisvault)'}</span>
          </button>
        </form>

        {/* Restore & Verify Snapshot */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              驗證 SHA-256 並還原快照
            </h2>
          </div>

          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
            若遭遇勒索軟體攻擊或需跨裝置轉移環境，上傳 <code className="font-mono">.aegisvault</code> 檔案並驗證原始雜湊校驗碼即可乾淨復原。
          </p>

          <div className="space-y-1.5">
            <label htmlFor="restore-pass" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
              備份解密密碼
            </label>
            <input
              id="restore-pass"
              type="password"
              value={restorePassphrase}
              onChange={(e) => setRestorePassphrase(e.target.value)}
              placeholder="輸入建立快照時設定的密碼..."
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            />
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept=".aegisvault,.json"
            onChange={handleFileRestore}
            className="hidden"
          />

          <button
            type="button"
            disabled={restoring}
            onClick={() => fileInputRef.current?.click()}
            className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 transition-colors cursor-pointer"
          >
            <Upload className="h-4 w-4" aria-hidden="true" />
            <span>{restoring ? '正在驗證並解密...' : '選擇 .aegisvault 備份檔還原'}</span>
          </button>
        </div>
      </div>

      {/* Snapshot History */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-2 mb-3">
          <HardDrive className="h-4 w-4 text-slate-500" aria-hidden="true" />
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            本機備份快照紀錄
          </h2>
        </div>

        {backups.length === 0 ? (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            尚無備份紀錄。建立第一次快照後，雜湊校驗碼與時間戳記將顯示於此以便核對。
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  <th className="py-2 pr-4 font-medium">快照時間</th>
                  <th className="py-2 pr-4 font-medium">加密演算法</th>
                  <th className="py-2 pr-4 font-medium">資料筆數</th>
                  <th className="py-2 font-medium">SHA-256 完整性雜湊</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {backups.map((b) => (
                  <tr key={b.id}>
                    <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-800 dark:text-slate-200">
                      {new Date(b.createdAt).toLocaleString('zh-TW')}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-slate-700 dark:text-slate-300">
                      {b.cipher}
                    </td>
                    <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                      {b.recordCount} 筆
                    </td>
                    <td className="py-2.5 font-mono text-slate-500 dark:text-slate-400 truncate max-w-[260px]">
                      {b.sha256}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
