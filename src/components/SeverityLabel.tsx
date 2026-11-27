import React from 'react';
import { AlertOctagon, AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react';
import type { ThreatCategory, ThreatSeverity } from '../types/security';

const SEVERITY_MAP: Record<
  ThreatSeverity,
  { label: string; colorClass: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  critical: {
    label: '嚴重威脅',
    colorClass: 'text-red-700 dark:text-red-400',
    Icon: AlertOctagon,
  },
  high: {
    label: '高風險',
    colorClass: 'text-orange-700 dark:text-orange-400',
    Icon: ShieldAlert,
  },
  medium: {
    label: '中度警戒',
    colorClass: 'text-amber-700 dark:text-amber-400',
    Icon: AlertTriangle,
  },
  low: {
    label: '低風險',
    colorClass: 'text-slate-600 dark:text-slate-400',
    Icon: Info,
  },
  nominal: {
    label: '安全正常',
    colorClass: 'text-emerald-700 dark:text-emerald-400',
    Icon: CheckCircle2,
  },
};

const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  phishing: '釣魚詐騙',
  trojan: '木馬載荷',
  wallet_drainer: '錢包授權詐騙',
  ransomware_c2: '勒索通訊',
  suspicious_redirect: '異常轉址',
  safe: '正常流量',
};

export const SeverityText: React.FC<{ severity: ThreatSeverity }> = ({ severity }) => {
  const cfg = SEVERITY_MAP[severity] || SEVERITY_MAP.low;
  const Icon = cfg.Icon;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${cfg.colorClass}`}>
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{cfg.label}</span>
    </span>
  );
};

export function getCategoryLabel(category: ThreatCategory | string): string {
  return CATEGORY_LABELS[category as ThreatCategory] || category;
}

export function getActionLabel(action: string): string {
  switch (action) {
    case 'blocked':
      return '已阻擋';
    case 'quarantined':
      return '已隔離';
    case 'allowed':
      return '已放行';
    case 'alerted':
      return '已告警';
    default:
      return action;
  }
}
