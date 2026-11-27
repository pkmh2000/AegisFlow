import React, { useMemo, useState } from 'react';
import {
  Bell,
  BellRing,
  Check,
  CheckCheck,
  ExternalLink,
  SearchCheck,
  Trash2,
  Volume2,
  VolumeX,
  X,
} from 'lucide-react';
import type { ProtectionSettings, RealtimeAlertItem } from '../types/security';
import { playCriticalAlertSound } from '../utils/alertSound';
import { SeverityText } from './SeverityLabel';

interface AlertCenterDrawerProps {
  open: boolean;
  onClose: () => void;
  alerts: RealtimeAlertItem[];
  settings: ProtectionSettings;
  onUpdateSettings: (next: ProtectionSettings) => void;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
  onClearRead: () => void;
  onDeleteAlert: (id: string) => void;
  onClearAll: () => void;
  onInspectAlert: (alert: RealtimeAlertItem) => void;
  onOpenScanner: () => void;
}

export const AlertCenterDrawer: React.FC<AlertCenterDrawerProps> = ({
  open,
  onClose,
  alerts,
  settings,
  onUpdateSettings,
  onMarkRead,
  onMarkAllRead,
  onClearRead,
  onDeleteAlert,
  onClearAll,
  onInspectAlert,
  onOpenScanner,
}) => {
  const [filter, setFilter] = useState<'all' | 'unread' | 'critical'>('all');
  const [pushPerm, setPushPerm] = useState<string>(() =>
    typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'
  );

  const unreadCount = useMemo(() => alerts.filter((a) => !a.read).length, [alerts]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (filter === 'unread') return !a.read;
      if (filter === 'critical') return a.severity === 'critical';
      return true;
    });
  }, [alerts, filter]);

  if (!open) return null;

  const requestPush = async () => {
    if (typeof Notification === 'undefined') {
      setPushPerm('unsupported');
      return;
    }
    try {
      const perm = await Notification.requestPermission();
      setPushPerm(perm);
      if (perm === 'granted' && !settings.realtimePushAlerts) {
        onUpdateSettings({ ...settings, realtimePushAlerts: true });
      }
    } catch {
      // Ignore permission rejection
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label="即時警報通知中心">
      <div className="fixed inset-0 bg-slate-950/50 backdrop-blur-[1px]" onClick={onClose} />

      <aside className="relative z-10 flex h-full w-full max-w-md flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-slate-900">
        {/* Drawer Header */}
        <div className="flex items-center justify-between gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div className="flex items-center gap-2.5 min-w-0">
            <BellRing className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-50 truncate">
              即時警報通知中心
            </h2>
            <span className="font-mono tabular-nums text-xs font-semibold text-blue-600 dark:text-blue-400">
              ({unreadCount} 未讀)
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="關閉即時警報通知中心"
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800 cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Quick Real-Time Notification & Audio Controls */}
        <div className="border-b border-slate-200 bg-slate-50/80 px-5 py-3.5 dark:border-slate-800 dark:bg-slate-950/60 space-y-2.5">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <button
              type="button"
              onClick={() =>
                onUpdateSettings({
                  ...settings,
                  realtimePushAlerts: !settings.realtimePushAlerts,
                })
              }
              className={`flex items-center justify-between rounded-lg border px-3 py-2 font-medium transition-colors cursor-pointer ${
                settings.realtimePushAlerts
                  ? 'border-blue-200 bg-blue-50 text-blue-800 dark:border-blue-900/70 dark:bg-blue-950/50 dark:text-blue-300'
                  : 'border-slate-200 bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400'
              }`}
            >
              <span className="flex items-center gap-1.5 truncate">
                <Bell className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span className="truncate">即時推播</span>
              </span>
              <span className="font-mono text-[11px]">{settings.realtimePushAlerts ? 'ON' : 'OFF'}</span>
            </button>

            <button
              type="button"
              onClick={() =>
                onUpdateSettings({
                  ...settings,
                  alertSoundEnabled: !settings.alertSoundEnabled,
                })
              }
              className={`flex items-center justify-between rounded-lg border px-3 py-2 font-medium transition-colors cursor-pointer ${
                settings.alertSoundEnabled
                  ? 'border-blue-200 bg-blue-50 text-blue-800 dark:border-blue-900/70 dark:bg-blue-950/50 dark:text-blue-300'
                  : 'border-slate-200 bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400'
              }`}
            >
              <span className="flex items-center gap-1.5 truncate">
                {settings.alertSoundEnabled ? (
                  <Volume2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                ) : (
                  <VolumeX className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                )}
                <span className="truncate">警示音效</span>
              </span>
              <span className="font-mono text-[11px]">{settings.alertSoundEnabled ? 'ON' : 'OFF'}</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              {pushPerm !== 'granted' && pushPerm !== 'unsupported' && (
                <button
                  type="button"
                  onClick={requestPush}
                  className="rounded-md border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap"
                >
                  授權系統推播
                </button>
              )}
              <button
                type="button"
                onClick={() => void playCriticalAlertSound()}
                className="rounded-md border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap"
              >
                試聽警報音
              </button>
            </div>

            <button
              type="button"
              onClick={onOpenScanner}
              className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-blue-700 cursor-pointer whitespace-nowrap"
            >
              <SearchCheck className="h-3 w-3" aria-hidden="true" />
              <span>進入正式掃描</span>
            </button>
          </div>
        </div>

        {/* Filter Bar & Bulk Actions */}
        <div className="flex items-center justify-between gap-2 border-b border-slate-100 px-5 py-2.5 dark:border-slate-800">
          <div className="inline-flex rounded-lg bg-slate-100 p-0.5 dark:bg-slate-800 text-xs">
            {(
              [
                ['all', '全部'],
                ['unread', '未讀'],
                ['critical', '嚴重'],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setFilter(key)}
                className={`rounded-md px-2.5 py-1 font-medium transition-colors cursor-pointer ${
                  filter === key
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <button
              type="button"
              onClick={onMarkAllRead}
              disabled={unreadCount === 0}
              className="inline-flex items-center gap-1 text-slate-600 hover:text-blue-600 disabled:opacity-40 dark:text-slate-400 dark:hover:text-blue-400 cursor-pointer whitespace-nowrap"
            >
              <CheckCheck className="h-3.5 w-3.5" aria-hidden="true" />
              <span>全標已讀</span>
            </button>
            <button
              type="button"
              onClick={onClearRead}
              className="inline-flex items-center gap-1 text-slate-500 hover:text-red-600 dark:text-slate-400 dark:hover:text-red-400 cursor-pointer whitespace-nowrap"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span>清除已讀</span>
            </button>
            {alerts.length > 0 && (
              <button
                type="button"
                onClick={onClearAll}
                className="inline-flex items-center gap-1 text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 cursor-pointer whitespace-nowrap"
              >
                <span>清空全部</span>
              </button>
            )}
          </div>
        </div>

        {/* Alert Items List */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
          {filteredAlerts.length === 0 ? (
            <div className="flex h-56 flex-col items-center justify-center px-6 text-center text-xs text-slate-500 dark:text-slate-400">
              <Bell className="h-8 w-8 text-slate-300 dark:text-slate-700 mb-2" aria-hidden="true" />
              <div>目前篩選條件下沒有即時警報通知。</div>
            </div>
          ) : (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`px-5 py-4 transition-colors space-y-2 ${
                  alert.read
                    ? 'bg-white dark:bg-slate-900 opacity-80'
                    : 'bg-blue-50/40 dark:bg-blue-950/20'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityText severity={alert.severity} />
                    {!alert.read && (
                      <span className="text-[11px] font-semibold text-blue-600 dark:text-blue-400">
                        · 未讀
                      </span>
                    )}
                  </div>
                  <span className="font-mono tabular-nums text-[11px] text-slate-500 dark:text-slate-400">
                    {new Date(alert.timestamp).toLocaleTimeString('zh-TW', {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </span>
                </div>

                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                  {alert.title}
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {alert.message}
                </p>

                {alert.target && (
                  <div className="truncate rounded border border-slate-100 bg-slate-50 px-2 py-1 font-mono text-[11px] text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                    {alert.target}
                  </div>
                )}

                <div className="flex items-center justify-between gap-2 pt-1 text-[11px]">
                  <span className="text-slate-500 dark:text-slate-400 truncate">
                    通道：{alert.channels.length > 0 ? alert.channels.join(' · ') : 'BrowserPush'}
                  </span>

                  <div className="flex items-center gap-2 shrink-0">
                    {!alert.read && (
                      <button
                        type="button"
                        onClick={() => onMarkRead(alert.id)}
                        className="inline-flex items-center gap-1 rounded border border-slate-200 bg-white px-2 py-1 font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 cursor-pointer"
                      >
                        <Check className="h-3 w-3" aria-hidden="true" />
                        <span>已讀</span>
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onDeleteAlert(alert.id)}
                      aria-label={`刪除此警報 ${alert.title}`}
                      title="刪除此警報"
                      className="rounded border border-slate-200 bg-white p-1 text-slate-400 hover:border-red-200 hover:bg-red-50 hover:text-red-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400 dark:hover:text-red-400 cursor-pointer"
                    >
                      <Trash2 className="h-3 w-3" aria-hidden="true" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onInspectAlert(alert)}
                      className="inline-flex items-center gap-1 rounded bg-slate-900 px-2.5 py-1 font-medium text-white hover:bg-slate-800 dark:bg-blue-600 dark:hover:bg-blue-500 cursor-pointer"
                    >
                      <span>查看溯源</span>
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </aside>
    </div>
  );
};
