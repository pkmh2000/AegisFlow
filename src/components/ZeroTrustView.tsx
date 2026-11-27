import React, { useState } from 'react';
import { CheckCircle2, Fingerprint, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import type { ZeroTrustPolicy, ZeroTrustSession } from '../types/security';

interface ZeroTrustViewProps {
  policies: ZeroTrustPolicy[];
  session: ZeroTrustSession | null;
  onSessionVerified: (session: ZeroTrustSession) => void;
  onPoliciesUpdated: (policies: ZeroTrustPolicy[]) => void;
  isOnline: boolean;
}

export const ZeroTrustView: React.FC<ZeroTrustViewProps> = ({
  policies,
  session,
  onSessionVerified,
  onPoliciesUpdated,
  isOnline,
}) => {
  const [deviceId, setDeviceId] = useState('Aegis-Workstation-Primary');
  const [mfaMethod, setMfaMethod] = useState<'Passkey' | 'TOTP' | 'HardwareKey'>('Passkey');
  const [totpCode, setTotpCode] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isOnline) {
      setErrorMsg('目前為離線狀態，無法向零信任驗證伺服器簽發工作階段憑證。');
      return;
    }
    setErrorMsg('');
    setVerifying(true);
    try {
      const resp = await fetch('/api/v1/zerotrust/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId,
          mfaMethod,
          challengeCode: mfaMethod === 'TOTP' ? totpCode : 'passkey-verified',
        }),
      });
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        throw new Error('目前為 GitHub Pages 純靜態部署環境，HMAC-SHA256 工作階段憑證簽發需連線至後端伺服器。');
      }
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || '零信任驗證失敗');
      onSessionVerified(data);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '身分驗證失敗');
    } finally {
      setVerifying(false);
    }
  };

  const togglePolicy = async (policy: ZeroTrustPolicy) => {
    if (!session) {
      setErrorMsg('零信任原則變更需先完成下方裝置與身分驗證（Step-Up MFA）。');
      return;
    }
    if (!isOnline) {
      setErrorMsg('目前為離線模式，無法同步更新伺服器原則。');
      return;
    }
    setErrorMsg('');
    setUpdatingId(policy.id);
    try {
      const resp = await fetch('/api/v1/zerotrust/policies', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({ id: policy.id, enabled: !policy.enabled }),
      });
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        throw new Error('純靜態部署環境不支援伺服器端原則寫入。');
      }
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || '原則更新失敗');
      onPoliciesUpdated(data.policies);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '原則更新發生錯誤');
    } finally {
      setUpdatingId(null);
    }
  };

  const changeEnforcement = async (
    policy: ZeroTrustPolicy,
    enforcement: ZeroTrustPolicy['enforcement']
  ) => {
    if (!session) {
      setErrorMsg('調整執行強度前請先完成零信任驗證。');
      return;
    }
    setErrorMsg('');
    setUpdatingId(policy.id);
    try {
      const resp = await fetch('/api/v1/zerotrust/policies', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({ id: policy.id, enforcement }),
      });
      const contentType = resp.headers.get('content-type') || '';
      if (resp.status === 404 || !contentType.includes('application/json')) {
        throw new Error('純靜態部署環境不支援伺服器端原則寫入。');
      }
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || '原則更新失敗');
      onPoliciesUpdated(data.policies);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '原則更新失敗');
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-50">
          零信任存取架構與權限控管 (Zero-Trust Access)
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          永不預設信任任何裝置或連線：驗證憑證僅保存於安全記憶體中，修改關鍵原則與發行 API 金鑰皆需通過 Step-Up 驗證。
        </p>
      </div>

      {errorMsg && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
          {errorMsg}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-12">
        {/* Identity & Device Posture Verification */}
        <section className="lg:col-span-5 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              裝置信任與身分驗證
            </h2>
            {session ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>已驗證工作階段</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400">
                <Lock className="h-3.5 w-3.5" aria-hidden="true" />
                <span>待提升權限</span>
              </span>
            )}
          </div>

          {session ? (
            <div className="space-y-3 rounded-lg border border-emerald-200 bg-emerald-50/50 p-4 text-xs dark:border-emerald-900/50 dark:bg-emerald-950/20">
              <div className="font-semibold text-emerald-900 dark:text-emerald-200">
                高信任存取憑證生效中 (記憶體安全託管)
              </div>
              <div className="space-y-1 text-slate-700 dark:text-slate-300 font-mono">
                <div>裝置名稱：{session.deviceId}</div>
                <div>驗證方式：{session.mfaMethod}</div>
                <div>信任等級：{session.trustLevel}</div>
                <div>有效期限：{new Date(session.expiresAt).toLocaleTimeString('zh-TW')}</div>
              </div>
            </div>
          ) : (
            <form onSubmit={handleVerify} className="space-y-3.5">
              <div className="space-y-1.5">
                <label htmlFor="zt-device" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  端點裝置識別名稱
                </label>
                <input
                  id="zt-device"
                  type="text"
                  value={deviceId}
                  onChange={(e) => setDeviceId(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                />
              </div>

              <div className="space-y-1.5">
                <span className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  驗證方法
                </span>
                <div className="grid grid-cols-3 gap-1.5 rounded-lg bg-slate-100 p-1 dark:bg-slate-800">
                  {(['Passkey', 'HardwareKey', 'TOTP'] as const).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setMfaMethod(m)}
                      className={`rounded-md py-1.5 text-xs font-medium transition-colors cursor-pointer ${
                        mfaMethod === m
                          ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              {mfaMethod === 'TOTP' && (
                <div className="space-y-1.5">
                  <label htmlFor="zt-totp" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    6 位數動態驗證碼
                  </label>
                  <input
                    id="zt-totp"
                    type="text"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    placeholder="輸入 6 位數驗證碼"
                    className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-sm tracking-widest text-slate-900 placeholder:text-slate-400 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={verifying}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-slate-800 dark:bg-blue-600 dark:hover:bg-blue-500 transition-colors cursor-pointer"
              >
                {mfaMethod === 'Passkey' ? (
                  <Fingerprint className="h-4 w-4" />
                ) : (
                  <KeyRound className="h-4 w-4" />
                )}
                <span>{verifying ? '正在簽發 HMAC-SHA256 憑證...' : '完成零信任身分驗證'}</span>
              </button>
            </form>
          )}

          <div className="border-t border-slate-100 pt-3.5 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            安全架構說明：憑證簽章採用伺服器端 <code className="font-mono">HMAC-SHA256</code>，且僅保留於瀏覽器執行記憶體內，不寫入 localStorage 以阻絕 XSS 竊取風險。
          </div>
        </section>

        {/* Granular Zero-Trust Policies */}
        <section className="lg:col-span-7 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              最小權限防禦原則清單
            </h2>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              共 {policies.length} 項控管規則
            </span>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {policies.map((policy) => (
              <div key={policy.id} className="py-4 first:pt-1 last:pb-1 space-y-2.5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <ShieldCheck
                        className={`h-4 w-4 shrink-0 ${
                          policy.enabled ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400'
                        }`}
                        aria-hidden="true"
                      />
                      <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {policy.name}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                      {policy.description}
                    </p>
                  </div>

                  <button
                    type="button"
                    disabled={updatingId === policy.id}
                    onClick={() => togglePolicy(policy)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      policy.enabled
                        ? 'bg-blue-600 text-white hover:bg-blue-700'
                        : 'border border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300'
                    }`}
                  >
                    {policy.enabled ? '已啟用' : '已停用'}
                  </button>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <span>作用域：{policy.scope}</span>
                  <div className="flex items-center gap-2">
                    <span>執行動作：</span>
                    <select
                      aria-label={`${policy.name} 執行動作`}
                      value={policy.enforcement}
                      disabled={updatingId === policy.id}
                      onChange={(e) =>
                        changeEnforcement(policy, e.target.value as ZeroTrustPolicy['enforcement'])
                      }
                      className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200"
                    >
                      <option value="block">自動阻斷 (Block)</option>
                      <option value="step_up_mfa">要求雙重驗證 (Step-Up MFA)</option>
                      <option value="isolate">沙箱隔離 (Isolate)</option>
                    </select>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
};
