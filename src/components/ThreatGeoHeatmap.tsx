import React, { useMemo, useState } from 'react';
import { ChevronRight, Globe2, MapPin } from 'lucide-react';
import type { ThreatGeoInfo, ThreatLogEntry } from '../types/security';
import { getCategoryLabel, SeverityText } from './SeverityLabel';

interface ThreatGeoHeatmapProps {
  logs: ThreatLogEntry[];
  onInspectLog: (log: ThreatLogEntry) => void;
}

interface GeoCluster {
  key: string;
  countryCode: string;
  countryName: string;
  city: string;
  region: string;
  lat: number;
  lng: number;
  count: number;
  maxRisk: number;
  avgRisk: number;
  criticalCount: number;
  ips: string[];
  latestLog: ThreatLogEntry;
}

const FALLBACK_GEO_POINTS: ThreatGeoInfo[] = [
  { countryCode: 'NL', countryName: '荷蘭', city: '阿姆斯特丹', region: '歐洲', lat: 52.37, lng: 4.9 },
  { countryCode: 'RU', countryName: '俄羅斯', city: '莫斯科', region: '東歐', lat: 55.75, lng: 37.62 },
  { countryCode: 'US', countryName: '美國', city: '阿什本', region: '北美', lat: 39.04, lng: -77.49 },
  { countryCode: 'SG', countryName: '新加坡', city: '新加坡', region: '東南亞', lat: 1.35, lng: 103.82 },
  { countryCode: 'HK', countryName: '香港', city: '香港', region: '東亞', lat: 22.32, lng: 114.17 },
  { countryCode: 'BR', countryName: '巴西', city: '聖保羅', region: '南美', lat: -23.55, lng: -46.63 },
];

function resolveGeo(log: ThreatLogEntry): ThreatGeoInfo {
  if (log.geo && typeof log.geo.lat === 'number' && typeof log.geo.lng === 'number') {
    return log.geo;
  }
  const sum = log.sourceIp.split('').reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  return FALLBACK_GEO_POINTS[sum % FALLBACK_GEO_POINTS.length];
}

// Equirectangular projection into 800x380 SVG viewBox
function projectCoords(lat: number, lng: number): { x: number; y: number } {
  const x = ((lng + 180) / 360) * 800;
  const y = ((90 - lat) / 180) * 380;
  return { x, y };
}

// Simplified clean world continent vector paths (800x380 equirectangular)
const CONTINENT_PATHS = [
  // North America
  'M 75,68 L 125,52 L 195,55 L 245,78 L 235,105 L 210,122 L 196,148 L 168,162 L 154,182 L 136,174 L 116,144 L 84,116 L 68,88 Z',
  // Greenland
  'M 250,30 L 305,24 L 326,48 L 288,70 L 254,58 Z',
  // South America
  'M 206,198 L 246,204 L 284,232 L 274,274 L 248,318 L 222,344 L 208,312 L 204,258 L 192,226 Z',
  // Europe
  'M 372,62 L 424,52 L 474,58 L 486,88 L 456,108 L 418,112 L 382,114 L 368,94 Z',
  // Africa
  'M 376,130 L 434,126 L 472,148 L 486,188 L 466,246 L 442,286 L 414,276 L 396,226 L 368,192 L 364,156 Z',
  // Asia
  'M 484,56 L 568,46 L 664,54 L 722,74 L 704,104 L 666,130 L 642,158 L 604,174 L 564,168 L 528,176 L 496,154 L 474,122 L 482,88 Z',
  // Southeast Asia / Maritime Islands
  'M 612,184 L 648,186 L 664,206 L 636,214 L 608,202 Z',
  // Japan / East Asia Islands
  'M 688,108 L 706,102 L 712,124 L 692,130 Z',
  // Australia / Oceania
  'M 648,242 L 712,238 L 732,272 L 708,306 L 656,298 L 638,268 Z',
];

export const ThreatGeoHeatmap: React.FC<ThreatGeoHeatmapProps> = ({ logs, onInspectLog }) => {
  const [filterMode, setFilterMode] = useState<'blocked' | 'critical' | 'wallet'>('blocked');
  const [selectedClusterKey, setSelectedClusterKey] = useState<string | null>(null);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (filterMode === 'critical') {
        return log.severity === 'critical' || log.severity === 'high';
      }
      if (filterMode === 'wallet') {
        return log.category === 'wallet_drainer';
      }
      return log.action !== 'allowed';
    });
  }, [logs, filterMode]);

  const clusters = useMemo(() => {
    const map = new Map<string, { items: ThreatLogEntry[]; geo: ThreatGeoInfo }>();
    for (const log of filteredLogs) {
      const geo = resolveGeo(log);
      const key = `${geo.countryCode}-${geo.city}`;
      const existing = map.get(key);
      if (existing) {
        existing.items.push(log);
      } else {
        map.set(key, { items: [log], geo });
      }
    }

    const result: GeoCluster[] = [];
    for (const [key, { items, geo }] of map.entries()) {
      const maxRisk = Math.max(...items.map((i) => i.riskScore));
      const avgRisk = Math.round(items.reduce((s, i) => s + i.riskScore, 0) / items.length);
      const criticalCount = items.filter((i) => i.severity === 'critical' || i.severity === 'high').length;
      const ips = Array.from(new Set(items.map((i) => i.sourceIp)));
      result.push({
        key,
        countryCode: geo.countryCode,
        countryName: geo.countryName,
        city: geo.city,
        region: geo.region,
        lat: geo.lat,
        lng: geo.lng,
        count: items.length,
        maxRisk,
        avgRisk,
        criticalCount,
        ips,
        latestLog: items[0],
      });
    }

    return result.sort((a, b) => b.count - a.count || b.maxRisk - a.maxRisk);
  }, [filteredLogs]);

  const activeCluster =
    clusters.find((c) => c.key === selectedClusterKey) || clusters[0] || null;

  const maxCount = Math.max(1, ...clusters.map((c) => c.count));

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 lg:col-span-2">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              威脅地理分佈熱力圖
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            視覺化近期攔截攻擊的來源 IP 地理熱區與風險密度 · 離線支援同步渲染
          </p>
        </div>

        <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80 self-start">
          {(
            [
              ['blocked', '全部攔截熱區'],
              ['critical', '高危以上威脅'],
              ['wallet', '錢包授權詐騙'],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setFilterMode(id)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                filterMode === id
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {clusters.length === 0 ? (
        <div className="mt-5 rounded-lg border border-slate-100 bg-slate-50 py-12 text-center text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
          {logs.length === 0
            ? '尚無地理熱區事件，執行正式掃描後將即時定位來源 IP 熱區。'
            : '目前篩選條件下尚無地理熱區事件。'}
        </div>
      ) : (
        <div className="mt-5 grid gap-5 lg:grid-cols-12 items-stretch">
          {/* Interactive SVG Heatmap Canvas */}
          <div className="lg:col-span-8 flex flex-col justify-between rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-950">
            <div className="relative w-full overflow-hidden">
              <svg
                viewBox="0 0 800 380"
                role="img"
                aria-label="全球惡意來源 IP 地理熱力分佈圖"
                className="w-full h-auto block select-none"
              >
                <defs>
                  <radialGradient id="heat-critical" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#DC2626" stopOpacity="0.65" />
                    <stop offset="45%" stopColor="#EA580C" stopOpacity="0.28" />
                    <stop offset="100%" stopColor="#DC2626" stopOpacity="0" />
                  </radialGradient>
                  <radialGradient id="heat-high" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#D97706" stopOpacity="0.6" />
                    <stop offset="50%" stopColor="#F59E0B" stopOpacity="0.24" />
                    <stop offset="100%" stopColor="#D97706" stopOpacity="0" />
                  </radialGradient>
                  <radialGradient id="heat-medium" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#2563EB" stopOpacity="0.55" />
                    <stop offset="55%" stopColor="#3B82F6" stopOpacity="0.2" />
                    <stop offset="100%" stopColor="#2563EB" stopOpacity="0" />
                  </radialGradient>
                </defs>

                {/* Subtle Lat/Lng Graticule */}
                <g className="stroke-slate-200/80 dark:stroke-slate-800/80" strokeWidth="0.75" strokeDasharray="3 3">
                  {[95, 190, 285].map((y) => (
                    <line key={`lat-${y}`} x1="0" y1={y} x2="800" y2={y} />
                  ))}
                  {[160, 320, 480, 640].map((x) => (
                    <line key={`lng-${x}`} x1={x} y1="0" x2={x} y2="380" />
                  ))}
                </g>

                {/* Continent Silhouettes */}
                <g className="fill-slate-200/85 stroke-slate-300 dark:fill-slate-800/90 dark:stroke-slate-700" strokeWidth="1">
                  {CONTINENT_PATHS.map((d, i) => (
                    <path key={i} d={d} strokeLinejoin="round" />
                  ))}
                </g>

                {/* Heat Plumes + Interactive Markers */}
                {clusters.map((cluster) => {
                  const { x, y } = projectCoords(cluster.lat, cluster.lng);
                  const intensityRatio = cluster.count / maxCount;
                  const heatRadius = 28 + intensityRatio * 34;
                  const isSelected = activeCluster?.key === cluster.key;
                  const gradientId =
                    cluster.maxRisk >= 80
                      ? 'url(#heat-critical)'
                      : cluster.maxRisk >= 60
                      ? 'url(#heat-high)'
                      : 'url(#heat-medium)';
                  const dotColor =
                    cluster.maxRisk >= 80
                      ? '#DC2626'
                      : cluster.maxRisk >= 60
                      ? '#D97706'
                      : '#2563EB';

                  return (
                    <g
                      key={cluster.key}
                      onClick={() => setSelectedClusterKey(cluster.key)}
                      className="cursor-pointer"
                    >
                      <title>
                        {`${cluster.countryName} · ${cluster.city} (${cluster.count} 次攔截，最高風險 ${cluster.maxRisk}/100)`}
                      </title>
                      <circle cx={x} cy={y} r={heatRadius} fill={gradientId} />
                      {isSelected && (
                        <circle
                          cx={x}
                          cy={y}
                          r={14}
                          fill="none"
                          stroke={dotColor}
                          strokeWidth="1.5"
                          strokeOpacity="0.85"
                        />
                      )}
                      <circle
                        cx={x}
                        cy={y}
                        r={isSelected ? 6.5 : 5}
                        fill={dotColor}
                        stroke="#FFFFFF"
                        strokeWidth="1.5"
                      />
                      <text
                        x={x + 9}
                        y={y + 4}
                        className="fill-slate-800 dark:fill-slate-200 text-[10px] font-medium"
                      >
                        {cluster.city} ({cluster.count})
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Heat Intensity Legend */}
            <div className="mt-2 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200/80 pt-2.5 text-xs text-slate-600 dark:border-slate-800 dark:text-slate-400">
              <div className="flex flex-wrap items-center gap-4">
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-600" aria-hidden="true" />
                  <span>極高風險熱區 (≥ 80)</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-600" aria-hidden="true" />
                  <span>高度警戒熱區 (60–79)</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-blue-600" aria-hidden="true" />
                  <span>一般異常觀察 (&lt; 60)</span>
                </span>
              </div>
              <span className="font-mono tabular-nums text-[11px] text-slate-500 dark:text-slate-400">
                涵蓋 {clusters.length} 個地理熱區 · 共 {filteredLogs.length} 筆來源紀錄
              </span>
            </div>
          </div>

          {/* Right Panel: Hotspot Ranking & Selected Region Drilldown */}
          <div className="lg:col-span-4 flex flex-col justify-between gap-4">
            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                惡意活動高發區域排行
              </div>
              <div className="divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800 max-h-[210px] overflow-y-auto">
                {clusters.map((cluster) => {
                  const selected = activeCluster?.key === cluster.key;
                  const pct = Math.round((cluster.count / maxCount) * 100);
                  return (
                    <button
                      key={cluster.key}
                      type="button"
                      onClick={() => setSelectedClusterKey(cluster.key)}
                      className={`w-full px-3 py-2.5 text-left transition-colors cursor-pointer ${
                        selected
                          ? 'bg-blue-50/70 dark:bg-blue-950/30'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="font-medium text-slate-900 dark:text-slate-100 truncate">
                          {cluster.countryName} · {cluster.city}
                        </span>
                        <span className="font-mono tabular-nums text-slate-600 dark:text-slate-300 shrink-0">
                          {cluster.count} 次 · 峰值 {cluster.maxRisk}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                        <div
                          className={`h-full rounded-full ${
                            cluster.maxRisk >= 80
                              ? 'bg-red-600'
                              : cluster.maxRisk >= 60
                              ? 'bg-amber-500'
                              : 'bg-blue-600'
                          }`}
                          style={{ width: `${Math.max(12, pct)}%` }}
                        />
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {activeCluster && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 dark:border-slate-800 dark:bg-slate-950 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-900 dark:text-slate-100">
                    <MapPin className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
                    <span>
                      {activeCluster.countryName} ({activeCluster.region}) · {activeCluster.city}
                    </span>
                  </div>
                  <SeverityText severity={activeCluster.latestLog.severity} />
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">來源 IP</div>
                    <div className="font-mono text-slate-800 dark:text-slate-200 truncate">
                      {activeCluster.ips.join(', ')}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400">主要威脅類型</div>
                    <div className="text-slate-800 dark:text-slate-200 truncate">
                      {getCategoryLabel(activeCluster.latestLog.category)}
                    </div>
                  </div>
                </div>

                <div className="truncate font-mono text-[11px] text-slate-600 dark:text-slate-400">
                  最新攔截：{activeCluster.latestLog.target}
                </div>

                <button
                  type="button"
                  onClick={() => onInspectLog(activeCluster.latestLog)}
                  className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-800 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  <span>檢視該熱區溯源日誌</span>
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
};
