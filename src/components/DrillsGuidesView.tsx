import React, { useState } from 'react';
import { BookOpen, CheckCircle2, GraduationCap, RotateCcw, XCircle } from 'lucide-react';
import { OFFLINE_RISK_GUIDES, SECURITY_DRILLS } from '../data/drillsAndGuides';
import { SeverityText } from './SeverityLabel';

interface DrillsGuidesViewProps {
  drillScores: Record<string, boolean>;
  onRecordDrillResult: (drillId: string, passed: boolean) => void;
  onResetDrills: () => void;
}

export const DrillsGuidesView: React.FC<DrillsGuidesViewProps> = ({
  drillScores,
  onRecordDrillResult,
  onResetDrills,
}) => {
  const [selectedAnswers, setSelectedAnswers] = useState<Record<string, string>>({});

  const completedCount = Object.keys(drillScores).length;
  const passedCount = Object.values(drillScores).filter(Boolean).length;

  const handleSelectOption = (drillId: string, optionId: string, isCorrect: boolean) => {
    setSelectedAnswers((prev) => ({ ...prev, [drillId]: optionId }));
    onRecordDrillResult(drillId, isCorrect);
  };

  return (
    <div className="space-y-8">
      {/* Section 1: Interactive Security Drills */}
      <section className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span>定期資安演練模擬</span>
              <span aria-hidden="true">·</span>
              <span>離線可完整互動執行</span>
            </div>
            <h1 className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-50">
              實戰威脅應變演練與防禦訓練
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-xs font-mono tabular-nums text-slate-700 dark:text-slate-300">
              通過率：{passedCount} / {SECURITY_DRILLS.length}（已完成 {completedCount} 題）
            </div>
            <button
              type="button"
              onClick={() => {
                setSelectedAnswers({});
                onResetDrills();
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer whitespace-nowrap shrink-0"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>重置演練</span>
            </button>
          </div>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">
          {SECURITY_DRILLS.map((drill, idx) => {
            const pickedId = selectedAnswers[drill.id];
            const pickedOption = drill.options.find((o) => o.id === pickedId);
            return (
              <article
                key={drill.id}
                className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-3.5"
              >
                <div className="flex items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <span className="inline-flex items-center gap-1.5 font-medium text-blue-700 dark:text-blue-400">
                    <GraduationCap className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>演練 0{idx + 1} · {drill.difficulty}</span>
                  </span>
                  {drill.id in drillScores && (
                    <span
                      className={`font-medium ${
                        drillScores[drill.id]
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-red-700 dark:text-red-400'
                      }`}
                    >
                      {drillScores[drill.id] ? '處置正確' : '需加強警戒'}
                    </span>
                  )}
                </div>

                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                  {drill.title}
                </h2>
                <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  {drill.prompt}
                </p>

                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-950">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    {drill.artifactLabel}
                  </div>
                  <div className="mt-1 break-all font-mono text-xs text-slate-900 dark:text-slate-100">
                    {drill.artifactContent}
                  </div>
                </div>

                <div className="space-y-2">
                  {drill.options.map((opt) => {
                    const selected = pickedId === opt.id;
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => handleSelectOption(drill.id, opt.id, opt.isCorrect)}
                        className={`w-full rounded-lg border px-3.5 py-2.5 text-left text-xs transition-colors cursor-pointer ${
                          selected
                            ? opt.isCorrect
                              ? 'border-emerald-500 bg-emerald-50 text-emerald-950 dark:border-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-100'
                              : 'border-red-500 bg-red-50 text-red-950 dark:border-red-700 dark:bg-red-950/40 dark:text-red-100'
                            : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800'
                        }`}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>

                {pickedOption && (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs space-y-1 dark:border-slate-800 dark:bg-slate-950">
                    <div className="flex items-center gap-1.5 font-semibold text-slate-900 dark:text-slate-100">
                      {pickedOption.isCorrect ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 text-red-600" />
                      )}
                      <span>演練解析</span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
                      {pickedOption.explanation}
                    </p>
                    <p className="text-blue-700 dark:text-blue-400">
                      防禦落地建議：{drill.remediationTip}
                    </p>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </section>

      {/* Section 2: Offline Risk Assessment & Remediation Guides */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
          <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
            離線風險評估與修復指南 (斷網仍可查閱)
          </h2>
        </div>

        <div className="grid gap-5 lg:grid-cols-3">
          {OFFLINE_RISK_GUIDES.map((guide) => (
            <div
              key={guide.id}
              className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-3"
            >
              <SeverityText severity={guide.severity} />
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                {guide.title}
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                {guide.summary}
              </p>

              <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
                <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 mb-1">
                  威脅識別指標：
                </div>
                <ul className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
                  {guide.indicators.map((ind, i) => (
                    <li key={i}>• {ind}</li>
                  ))}
                </ul>
              </div>

              <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
                <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 mb-1">
                  標準修復流程：
                </div>
                <ol className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
                  {guide.actions.map((act, i) => (
                    <li key={i}>{i + 1}. {act}</li>
                  ))}
                </ol>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
