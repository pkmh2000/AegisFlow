import React, { useCallback, useEffect, useState } from 'react';
import { Activity, Cpu, MemoryStick, RefreshCw } from 'lucide-react';
import type { SystemMetricsSnapshot } from '../types/security';

interface SystemPerformanceWidgetProps {
  isOnline: boolean;
}

type HealthStatus = SystemMetricsSnapshot['status'];

function getHealthMeta(status: HealthStatus) {
  if (status === 'critical') {
    return {
      label: '資源吃緊',
      dotClass: 'bg-red-600 dark:bg-red-500',
      textClass: 'text-red-700 dark:text-red-400',
      barClass: 'bg-red-600 dark:bg-red-500',
      borderClass: 'border-red-200 dark:border-red-900/60',
    };
  }
  if (status === 'elevated') {
    return {
      label: '負載偏高',
      dotClass: 'bg-amber-500',
      textClass: 'text-amber-700 dark:text-amber-400',
      barClass: 'bg-amber-500',
      borderClass: 'border-amber-200 dark:border-amber-900/60',
    };
  }
  return {
    label: '運作流暢',
    dotClass: 'bg-emerald-600 dark:bg-emerald-400',
    textClass: 'text-emerald-700 dark:text-emerald-400',
    barClass: 'bg-emerald-600 dark:bg-emerald-500',
    borderClass: 'border-slate-200 dark:border-slate-800',
  };
}

async function sampleBrowserRuntimeMetrics(): Promise<SystemMetricsSnapshot> {
  const targetMs = 40;
  const start = performance.now();
  await new Promise((resolve) => setTimeout(resolve, targetMs));
  const actualMs = performance.now() - start;
  const eventLoopLagMs = Math.max(0, Math.round((actualMs - targetMs) * 10) / 10);

  const perfMem = (
    performance as unknown as {
      memory?: { usedJSHeapSize: number; totalJSHeapSize: number; jsHeapSizeLimit: number };
    }
  ).memory;

  const heapUsedMb = perfMem ? Math.round((perfMem.usedJSHeapSize / 1048576) * 10) / 10 : 0;
  const heapTotalMb = perfMem ? Math.round((perfMem.totalJSHeapSize / 1048576) * 10) / 10 : 0;
  const heapLimitMb = perfMem ? Math.round((perfMem.jsHeapSizeLimit / 1048576) * 10) / 10 : 0;
  const systemUsedPct =
    perfMem && heapLimitMb > 0 ? Math.round((heapUsedMb / heapLimitMb) * 1000) / 10 : 0;

  const cores = typeof navigator !== 'undefined' && navigator.hardwareConcurrency ? navigator.hardwareConcurrency : 4;
  // Derive main-thread responsiveness utilization from actual event-loop jitter
  const processPct = Math.min(100, Math.round((eventLoopLagMs / 100) * 1000) / 10);

  const memoryStatus: HealthStatus =
    systemUsedPct >= 85 || heapUsedMb >= 512
      ? 'critical'
      : systemUsedPct >= 65 || heapUsedMb >= 256
      ? 'elevated'
      : 'healthy';

  const cpuStatus: HealthStatus =
    processPct >= 85 || eventLoopLagMs >= 80
      ? 'critical'
      : processPct >= 60 || eventLoopLagMs >= 35
      ? 'elevated'
      : 'healthy';

  const status: HealthStatus =
    memoryStatus === 'critical' || cpuStatus === 'critical'
      ? 'critical'
      : memoryStatus === 'elevated' || cpuStatus === 'elevated'
      ? 'elevated'
      : 'healthy';

  return {
    source: 'browser_runtime',
    status,
    memory: {
      rssMb: heapUsedMb,
      heapUsedMb,
      heapTotalMb,
      systemUsedPct,
      status: memoryStatus,
    },
    cpu: {
      processPct,
      systemLoadPct: processPct,
      loadAvg1m: 0,
      cores,
      eventLoopLagMs,
      status: cpuStatus,
    },
    uptimeSeconds: Math.round(performance.now() / 1000),
    sampledAt: new Date().toISOString(),
  };
}

export const SystemPerformanceWidget: React.FC<SystemPerformanceWidgetProps> = ({ isOnline }) => {
  const [metrics, setMetrics] = useState<SystemMetricsSnapshot | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchMetrics = useCallback(async () => {
    setRefreshing(true);
    try {
      if (isOnline) {
        const resp = await fetch('/api/v1/system/metrics');
        const contentType = resp.headers.get('content-type') || '';
        if (resp.ok && contentType.includes('application/json')) {
          const data = (await resp.json()) as SystemMetricsSnapshot;
          setMetrics(data);
          return;
        }
      }
      const browserSnapshot = await sampleBrowserRuntimeMetrics();
      setMetrics(browserSnapshot);
    } catch {
      const browserSnapshot = await sampleBrowserRuntimeMetrics();
      setMetrics(browserSnapshot);
    } finally {
      setRefreshing(false);
    }
  }, [isOnline]);

  useEffect(() => {
    void fetchMetrics();
    const timer = setInterval(() => {
      void fetchMetrics();
    }, 5000);
    return () => clearInterval(timer);
  }, [fetchMetrics]);

  const overall = getHealthMeta(metrics?.status ?? 'healthy');
  const memHealth = getHealthMeta(metrics?.memory.status ?? 'healthy');
  const cpuHealth = getHealthMeta(metrics?.cpu.status ?? 'healthy');

  // Scale RSS against 512MB lightweight target budget when heap limit is N/A
  const memoryBarPct = metrics
    ? metrics.source === 'node_backend'
      ? Math.min(100, Math.max(4, Math.round((metrics.memory.rssMb / 768) * 100)))
      : metrics.memory.systemUsedPct > 0
      ? Math.min(100, Math.max(4, metrics.memory.systemUsedPct))
      : 4
    : 0;

  const cpuBarPct = metrics
    ? Math.min(100, Math.max(3, Math.round(Math.max(metrics.cpu.processPct, metrics.cpu.systemLoadPct))))
    : 0;

  return (
    <section
      className={`rounded-xl border bg-white p-5 dark:bg-slate-900 lg:col-span-2 ${overall.borderClass}`}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2.5">
            <Activity className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              輕量化系統效能監控
            </h2>
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${overall.textClass}`}>
              <span className={`h-2.5 w-2.5 rounded-full ${overall.dotClass}`} aria-hidden="true" />
              <span>{overall.label}</span>
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            即時監測 AegisFlow 核心記憶體佔用、CPU 負載與事件迴圈回應延遲
          </p>
        </div>

        <div className="flex items-center gap-3 self-start sm:self-auto">
          <div className="flex items-center gap-3 text-[11px] text-slate-500 dark:text-slate-400">
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-emerald-600" aria-hidden="true" />
              <span>健康</span>
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-amber-500" aria-hidden="true" />
              <span>警戒</span>
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-red-600" aria-hidden="true" />
              <span>過載</span>
            </span>
          </div>

          <button
            type="button"
            disabled={refreshing}
            onClick={() => void fetchMetrics()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>更新</span>
          </button>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        {/* Memory Usage Card */}
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300">
              <MemoryStick className="h-4 w-4 text-slate-500 shrink-0" aria-hidden="true" />
              <span>記憶體佔用 (Memory Footprint)</span>
            </div>
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${memHealth.textClass}`}>
              <span className={`h-2 w-2 rounded-full ${memHealth.dotClass}`} aria-hidden="true" />
              <span>{memHealth.label}</span>
            </span>
          </div>

          <div className="flex items-baseline justify-between gap-2">
            <span className="font-mono tabular-nums text-xl font-bold text-slate-900 dark:text-slate-50">
              {metrics
                ? metrics.memory.rssMb > 0
                  ? `${metrics.memory.rssMb} MB`
                  : '輕量運行'
                : '量測中...'}
            </span>
            <span className="font-mono tabular-nums text-xs text-slate-500 dark:text-slate-400">
              {metrics?.source === 'node_backend'
                ? `常駐集 RSS (系統已用 ${metrics.memory.systemUsedPct}%)`
                : metrics && metrics.memory.heapTotalMb > 0
                ? `JS Heap 配額已用 ${metrics.memory.systemUsedPct}%`
                : '瀏覽器沙箱記憶體受保護'}
            </span>
          </div>

          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-300 ${memHealth.barClass}`}
              style={{ width: `${memoryBarPct}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
            <span>
              {metrics && metrics.memory.heapUsedMb > 0
                ? `Heap: ${metrics.memory.heapUsedMb} / ${metrics.memory.heapTotalMb} MB`
                : '精簡核心 · 無常駐外部代理'}
            </span>
            <span>輕量基準 &lt; 512 MB</span>
          </div>
        </div>

        {/* CPU Load Card */}
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300">
              <Cpu className="h-4 w-4 text-slate-500 shrink-0" aria-hidden="true" />
              <span>CPU 負載與回應效率 (CPU Load)</span>
            </div>
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${cpuHealth.textClass}`}>
              <span className={`h-2 w-2 rounded-full ${cpuHealth.dotClass}`} aria-hidden="true" />
              <span>{cpuHealth.label}</span>
            </span>
          </div>

          <div className="flex items-baseline justify-between gap-2">
            <span className="font-mono tabular-nums text-xl font-bold text-slate-900 dark:text-slate-50">
              {metrics ? `${metrics.cpu.processPct}%` : '量測中...'}
            </span>
            <span className="font-mono tabular-nums text-xs text-slate-500 dark:text-slate-400">
              {metrics
                ? `${metrics.cpu.cores} 核心 · 系統負載 ${metrics.cpu.systemLoadPct}%`
                : '計算中...'}
            </span>
          </div>

          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-300 ${cpuHealth.barClass}`}
              style={{ width: `${cpuBarPct}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
            <span>
              Event Loop 延遲：{metrics ? `${metrics.cpu.eventLoopLagMs} ms` : '—'}
            </span>
            <span>
              {metrics?.source === 'node_backend'
                ? `LoadAvg 1m: ${metrics.cpu.loadAvg1m}`
                : '執行緒健康基準 < 60%'}
            </span>
          </div>
        </div>
      </div>

      {metrics && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
          <span>
            監測來源：
            {metrics.source === 'node_backend'
              ? 'Node.js 輕量防禦後端即時遙測'
              : '瀏覽器執行環境即時量測'}
          </span>
          <span className="font-mono tabular-nums">
            最後採樣：{new Date(metrics.sampledAt).toLocaleTimeString('zh-TW')}
          </span>
        </div>
      )}
    </section>
  );
};
