import React, { useMemo, useState } from 'react';
import { TrendingUp } from 'lucide-react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceDot,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { ThreatLogEntry } from '../types/security';

interface ThreatTrendChartProps {
  logs: ThreatLogEntry[];
  onNavigateLogs: () => void;
}

interface DailyTrendPoint {
  dateKey: string;
  dateLabel: string;
  totalBlocked: number;
  criticalHigh: number;
  phishingTrojan: number;
  walletDrainer: number;
}

function toLocalDateKey(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

export const ThreatTrendChart: React.FC<ThreatTrendChartProps> = ({
  logs,
  onNavigateLogs,
}) => {
  const [seriesMode, setSeriesMode] = useState<'overview' | 'breakdown'>('overview');

  const { chartData, peakDay, peakHourRange, total7Days } = useMemo(() => {
    const now = new Date();
    const daySlots: DailyTrendPoint[] = [];
    const slotMap = new Map<string, DailyTrendPoint>();

    for (let offset = 6; offset >= 0; offset--) {
      const dt = new Date(now.getFullYear(), now.getMonth(), now.getDate() - offset);
      const dateKey = toLocalDateKey(dt);
      const dateLabel = `${dt.getMonth() + 1}/${dt.getDate()}`;
      const point: DailyTrendPoint = {
        dateKey,
        dateLabel,
        totalBlocked: 0,
        criticalHigh: 0,
        phishingTrojan: 0,
        walletDrainer: 0,
      };
      daySlots.push(point);
      slotMap.set(dateKey, point);
    }

    const hourBuckets = [0, 0, 0, 0, 0, 0]; // 4-hour intervals: 00-04, 04-08, 08-12, 12-16, 16-20, 20-24
    let count7Days = 0;

    for (const log of logs) {
      if (log.action === 'allowed') continue;
      const dt = new Date(log.timestamp);
      if (Number.isNaN(dt.getTime())) continue;
      const key = toLocalDateKey(dt);
      const slot = slotMap.get(key);
      if (!slot) continue;

      slot.totalBlocked += 1;
      count7Days += 1;
      if (log.severity === 'critical' || log.severity === 'high') {
        slot.criticalHigh += 1;
      }
      if (log.category === 'wallet_drainer') {
        slot.walletDrainer += 1;
      } else if (log.category === 'phishing' || log.category === 'trojan' || log.category === 'ransomware_c2') {
        slot.phishingTrojan += 1;
      }

      const bucketIdx = Math.min(5, Math.floor(dt.getHours() / 4));
      hourBuckets[bucketIdx] += 1;
    }

    let topDay = daySlots[daySlots.length - 1];
    for (const d of daySlots) {
      if (d.totalBlocked > topDay.totalBlocked) {
        topDay = d;
      }
    }

    let topHourIdx = 0;
    for (let i = 1; i < hourBuckets.length; i++) {
      if (hourBuckets[i] > hourBuckets[topHourIdx]) {
        topHourIdx = i;
      }
    }
    const startH = String(topHourIdx * 4).padStart(2, '0');
    const endH = String(topHourIdx * 4 + 4).padStart(2, '0');

    return {
      chartData: daySlots,
      peakDay: topDay,
      peakHourRange: `${startH}:00–${endH}:00`,
      total7Days: count7Days,
    };
  }, [logs]);

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 lg:col-span-2">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              過去 7 天威脅攔截頻率趨勢
            </h2>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span className="font-mono tabular-nums">7 日累計攔截 {total7Days} 次</span>
            {total7Days > 0 ? (
              <>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">
                  高峰日：{peakDay?.dateLabel} ({peakDay?.totalBlocked ?? 0} 次)
                </span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">攻擊高峰時段：{peakHourRange}</span>
              </>
            ) : (
              <>
                <span aria-hidden="true">·</span>
                <span>尚無異常高峰紀錄</span>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 self-start sm:self-auto">
          <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
            <button
              type="button"
              onClick={() => setSeriesMode('overview')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                seriesMode === 'overview'
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
              }`}
            >
              攔截總量對比
            </button>
            <button
              type="button"
              onClick={() => setSeriesMode('breakdown')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                seriesMode === 'breakdown'
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
              }`}
            >
              威脅類型分佈
            </button>
          </div>

          <button
            type="button"
            onClick={onNavigateLogs}
            className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400 whitespace-nowrap shrink-0 cursor-pointer"
          >
            檢視完整日誌
          </button>
        </div>
      </div>

      <div className="mt-5 h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 10, right: 16, left: -16, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#94A3B8" strokeOpacity={0.22} vertical={false} />
            <XAxis
              dataKey="dateLabel"
              tick={{ fontSize: 12, fill: '#64748B' }}
              axisLine={false}
              tickLine={false}
              dy={8}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fontSize: 12, fill: '#64748B' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (!active || !payload || payload.length === 0) return null;
                return (
                  <div className="rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 shadow-md dark:border-slate-700 dark:bg-slate-900 text-xs">
                    <div className="font-mono font-semibold text-slate-900 dark:text-slate-100 mb-1.5">
                      日期：{label}
                    </div>
                    <div className="space-y-1">
                      {payload.map((entry) => (
                        <div key={String(entry.dataKey)} className="flex items-center justify-between gap-4">
                          <span className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
                            <span
                              className="h-2 w-2 rounded-full shrink-0"
                              style={{ backgroundColor: entry.color }}
                              aria-hidden="true"
                            />
                            <span>{entry.name}</span>
                          </span>
                          <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                            {entry.value} 次
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              }}
            />

            {seriesMode === 'overview' ? (
              <>
                <Line
                  type="monotone"
                  dataKey="totalBlocked"
                  name="總攔截次數"
                  stroke="#2563EB"
                  strokeWidth={2.5}
                  dot={{ r: 3.5, fill: '#2563EB', strokeWidth: 0 }}
                  activeDot={{ r: 5.5 }}
                />
                <Line
                  type="monotone"
                  dataKey="criticalHigh"
                  name="高危 / 嚴重威脅"
                  stroke="#DC2626"
                  strokeWidth={2}
                  strokeDasharray="4 4"
                  dot={{ r: 3, fill: '#DC2626', strokeWidth: 0 }}
                  activeDot={{ r: 5 }}
                />
                {peakDay && peakDay.totalBlocked > 0 && (
                  <ReferenceDot
                    x={peakDay.dateLabel}
                    y={peakDay.totalBlocked}
                    r={6}
                    fill="#2563EB"
                    stroke="#FFFFFF"
                    strokeWidth={2}
                  />
                )}
              </>
            ) : (
              <>
                <Line
                  type="monotone"
                  dataKey="phishingTrojan"
                  name="釣魚與木馬攔截"
                  stroke="#D97706"
                  strokeWidth={2.5}
                  dot={{ r: 3.5, fill: '#D97706', strokeWidth: 0 }}
                  activeDot={{ r: 5.5 }}
                />
                <Line
                  type="monotone"
                  dataKey="walletDrainer"
                  name="錢包授權詐騙"
                  stroke="#4F46E5"
                  strokeWidth={2.5}
                  dot={{ r: 3.5, fill: '#4F46E5', strokeWidth: 0 }}
                  activeDot={{ r: 5.5 }}
                />
              </>
            )}
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3 text-xs text-slate-600 dark:border-slate-800 dark:text-slate-400">
        {seriesMode === 'overview' ? (
          <div className="flex flex-wrap items-center gap-4">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 bg-blue-600" aria-hidden="true" />
              <span>總攔截次數</span>
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 border-t-2 border-dashed border-red-600" aria-hidden="true" />
              <span>高危 / 嚴重威脅</span>
            </span>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-4">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 bg-amber-600" aria-hidden="true" />
              <span>釣魚與木馬攔截</span>
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 bg-indigo-600" aria-hidden="true" />
              <span>錢包授權詐騙</span>
            </span>
          </div>
        )}
        <span className="text-[11px] text-slate-500 dark:text-slate-400">
          即時連線掃描事件將自動計入當日趨勢曲線
        </span>
      </div>
    </section>
  );
};
