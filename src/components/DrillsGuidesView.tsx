import React, { useEffect, useState } from 'react';
import {
  BookOpen,
  CheckCircle2,
  Compass,
  GraduationCap,
  HelpCircle,
  Lock,
  RotateCcw,
  ShieldCheck,
  Terminal,
  XCircle,
} from 'lucide-react';
import { DEVICE_LOG_GUIDES, OFFLINE_RISK_GUIDES, SECURITY_DRILLS } from '../data/drillsAndGuides';
import { SeverityText } from './SeverityLabel';

export type GuidesSectionId = 'guide' | 'drills' | 'risks';

interface DrillsGuidesViewProps {
  drillScores: Record<string, boolean>;
  onRecordDrillResult: (drillId: string, passed: boolean) => void;
  onResetDrills: () => void;
  activeSection?: GuidesSectionId;
  onChangeSection?: (section: GuidesSectionId) => void;
}

const FEATURE_MANUALS = [
  {
    name: '1. 防護總覽儀表板',
    purpose: '一眼掌握系統即時攔截次數、ML 信心指標、7 天威脅趨勢、來源 IP 地理熱力圖與系統 CPU / 記憶體輕量效能狀態。',
    steps: [
      '在頂部搜尋框貼上任意可疑網址，點擊「立即檢測」即可跳轉進行深度掃描。',
      '可點擊「自訂儀表板」隱藏或調整各模組卡片的顯示順序，設定會自動儲存在本機。',
      '依據個人需求切換「一般居家防護 / 嚴格零信任 / Web3 資產專護」三種預設防禦等級。',
    ],
  },
  {
    name: '2. 連結與錢包防護 (正式掃描)',
    purpose: '透過 6 維度機器學習流量特徵模型與 Web3 ABI 簽章解碼器，於實際點擊或錢包簽署前預先識別釣魚、木馬與盜幣合約。',
    steps: [
      '先選取並鎖定「監控端點平台」（Browser / Windows / macOS / iOS / Android），之後切換分頁或重整皆會固定該平台。',
      '於「可疑連結 & ML 流量分析」貼上網址進行靜態分析；或切換「加密貨幣錢包防護」檢查 dApp 網址、Spender 合約與 Calldata。',
      '若已連線並設定後端 Gemini API，可勾選「啟用 AI 建議修補」產出防火牆與處置建議。',
    ],
  },
  {
    name: '3. 深度日誌與網路日誌惡意行徑分析',
    purpose: '支援貼上或上傳原始網路日誌（HTTP / 防火牆 / DNS / Syslog / JSON）自動偵測惡意行為，並保留所有事件的溯源路徑與 AI 修補規則。',
    steps: [
      '於頂部「網路日誌惡意行徑批量分析」區塊貼上日誌文字或上傳 .log / .txt / .json 檔，點擊「分析日誌內惡意行徑」即可辨識 SQLi、RCE、C2 反連、密碼爆破與 DGA 異常。',
      '點選命中的事件可查看 6 維度風險特徵與來源 IP/ASN 溯源路徑。',
      '點擊「AI 生成主動修補方案」即可產出對應的 WAF / DNS / 防火牆阻斷規則並匯出 CSV / JSON 歸檔。',
    ],
  },
  {
    name: '4. 零信任存取控管 (Zero-Trust)',
    purpose: '落實「永不預設信任」原則，高風險防火牆規則修改與 API Token 發行前必須先完成裝置身分驗證。',
    steps: [
      '輸入端點裝置識別名稱，選擇 Passkey、HardwareKey 或 6 位數 TOTP 驗證碼完成 Step-Up 驗證。',
      '驗證簽發的 HMAC-SHA256 憑證僅保存於瀏覽器安全記憶體，不寫入 localStorage，關閉分頁即自動失效。',
      '取得憑證後即可即時開關或切換右側最小權限防禦原則的執行動作（自動阻斷／要求雙重驗證／沙箱隔離）。',
    ],
  },
  {
    name: '5. 抗勒索加密備份保險庫',
    purpose: '將防禦規則、設定檔與掃描日誌在本機進行軍規加密封裝，防止遭勒索軟體破壞後遺失關鍵資安設定。',
    steps: [
      '輸入自訂主保護密碼，系統將透過瀏覽器原生 Web Crypto API（PBKDF2 + AES-256-GCM）於本機完成加密。',
      '下載生成的加密快照檔（含 SHA-256 完整性雜湊校驗碼）並妥善保存於離線隨身碟或安全雲端。',
      '需要還原時上傳加密檔並輸入相同密碼，驗證雜湊無誤後即可一鍵還原全部設定與紀錄。',
    ],
  },
  {
    name: '6. 開源 API 與多平台告警設定',
    purpose: '管理瀏覽器推播、嚴重威脅警示音與外部通知渠道（LINE / Slack / Discord / Telegram），並供外部程式或擴充套件串接。',
    steps: [
      '可開啟「嚴重威脅自動播放警示音」，當偵測到 Critical 等級威脅時將透過 Web Audio API 立即發聲警示。',
      '完成零信任驗證後，可發行具到期時效的開源 API Token，讓外部系統呼叫 `/api/v1/scan/url`、`/api/v1/scan/wallet` 或 `/api/v1/logs/ingest`。',
      '支援即時 SSE 警報推播串流，右上角「警報通知」鈴鐺會即時同步顯示最新威脅。',
    ],
  },
];

const ARCHITECTURE_FAQS = [
  {
    question: '貼上可疑連結或 dApp 網址，會不會造成實際連線而遭釣魚或木馬病毒侵入？',
    answer:
      '不會。AegisFlow 的檢測流程全程採用「靜態沙箱分析」：無論是在前端本機 ML 引擎還是後端分析引擎，都只會針對您貼上的文字進行 URL 結構拆解（new URL）、字元熵值運算、Punycode 仿冒比對、ABI Calldata 解碼與 AI 語意評估。系統絕不會在背後開啟該網頁、執行遠端 JavaScript、下載檔案或觸發錢包簽章彈窗，因此不會因貼上連結而中毒。',
  },
  {
    question: '執行其他 App、未開啟本程式或電腦／手機關機期間，會自動偵測與攔截嗎？',
    answer:
      '不會在關機或純背景無連線時自動攔截其他 App。原因如下：(1) 關機期間所有程式與網路均已停止，無法進行任何偵測。(2) AegisFlow 屬於跨平台 Web / PWA 網頁應用程式，受限於瀏覽器與作業系統的安全沙箱隔離機制，網頁無法越權監聽或阻斷其他獨立 App（如 LINE、系統瀏覽器、遊戲或系統背景程序）的網路封包。(3) 若需要對其他程式或瀏覽器流量進行自動攔截，需將瀏覽器擴充套件、端點代理程式或企業閘道器透過本系統的「開源 API」串接至 AegisFlow 後端，由後端回傳即時攔截決策與警報推播。',
  },
  {
    question: '離線狀態（無網路）下哪些功能仍可使用？',
    answer:
      '得益於 PWA Service Worker 快取架構，您在斷網或純靜態部署環境下仍可查看歷史日誌、執行本機 6 維度 ML 網址／錢包靜態掃描、進行 AES-256-GCM 加密備份與還原、操作資安演練並查閱風險修復指南；僅即時 Gemini AI 深度修補與跨裝置伺服器同步功能需在連線後端時運作。',
  },
];

export const DrillsGuidesView: React.FC<DrillsGuidesViewProps> = ({
  drillScores,
  onRecordDrillResult,
  onResetDrills,
  activeSection,
  onChangeSection,
}) => {
  const [internalSection, setInternalSection] = useState<GuidesSectionId>(activeSection ?? 'guide');
  const [selectedAnswers, setSelectedAnswers] = useState<Record<string, string>>({});

  useEffect(() => {
    if (activeSection) {
      setInternalSection(activeSection);
    }
  }, [activeSection]);

  const currentSection = activeSection ?? internalSection;
  const setSection = (sec: GuidesSectionId) => {
    setInternalSection(sec);
    onChangeSection?.(sec);
  };

  const completedCount = Object.keys(drillScores).length;
  const passedCount = Object.values(drillScores).filter(Boolean).length;

  const handleSelectOption = (drillId: string, optionId: string, isCorrect: boolean) => {
    setSelectedAnswers((prev) => ({ ...prev, [drillId]: optionId }));
    onRecordDrillResult(drillId, isCorrect);
  };

  return (
    <div className="space-y-6">
      {/* Header + Section Switcher */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>操作手冊、安全邊界與實戰演練</span>
            <span aria-hidden="true">·</span>
            <span>離線可完整查閱與互動</span>
          </div>
          <h1 className="mt-1 text-xl font-bold text-slate-900 dark:text-slate-50">
            功能操作說明與資安應變演練
          </h1>
        </div>

        <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80 self-start">
          {(
            [
              ['guide', '功能說明與操作', Compass],
              ['drills', '實戰資安演練', GraduationCap],
              ['risks', '離線風險指南', BookOpen],
            ] as const
          ).map(([id, label, Icon]) => (
            <button
              key={id}
              type="button"
              onClick={() => setSection(id)}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                currentSection === id
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-900 dark:text-slate-100'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
              }`}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Section A: Feature Manual & Security Boundaries */}
      {currentSection === 'guide' && (
        <div className="space-y-6">
          {/* Architecture & Security Boundary FAQ */}
          <section className="rounded-xl border border-blue-200 bg-blue-50/50 p-5 dark:border-blue-900/60 dark:bg-blue-950/20 space-y-4">
            <div className="flex items-center gap-2">
              <HelpCircle className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                安全防護機制與運行邊界說明（必讀）
              </h2>
            </div>
            <div className="grid gap-4 lg:grid-cols-3">
              {ARCHITECTURE_FAQS.map((faq) => (
                <div
                  key={faq.question}
                  className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 space-y-2"
                >
                  <div className="flex items-start gap-2">
                    <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
                    <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100 leading-relaxed">
                      {faq.question}
                    </h3>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {faq.answer}
                  </p>
                </div>
              ))}
            </div>
          </section>

          {/* Module-by-Module Operating Manual */}
          <section className="space-y-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                各項功能操作指南
              </h2>
              <span className="inline-flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <Lock className="h-3.5 w-3.5" aria-hidden="true" />
                <span>支援桌機與手機跨平台瀏覽</span>
              </span>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              {FEATURE_MANUALS.map((item) => (
                <article
                  key={item.name}
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900 space-y-3"
                >
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    {item.name}
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {item.purpose}
                  </p>
                  <div className="border-t border-slate-100 pt-3 dark:border-slate-800">
                    <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 mb-1.5">
                      操作步驟：
                    </div>
                    <ol className="space-y-1.5 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                      {item.steps.map((step, i) => (
                        <li key={i}>{i + 1}. {step}</li>
                      ))}
                    </ol>
                  </div>
                </article>
              ))}
            </div>
          </section>

          {/* Per-device Network Log Retrieval Guide */}
          <section className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  各裝置網路日誌匯出取得指引
                </h2>
              </div>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                取得檔案後可至「深度日誌溯源」上傳或貼上分析（單檔上限 500 KB）
              </span>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {DEVICE_LOG_GUIDES.map((guide) => (
                <article
                  key={guide.id}
                  className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 space-y-2.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      {guide.device}
                    </h3>
                    <span className="font-mono text-[11px] text-blue-700 dark:text-blue-400">
                      {guide.format}
                    </span>
                  </div>
                  {guide.commandOrPath && (
                    <div className="rounded border border-slate-200 bg-slate-50 px-2.5 py-1.5 font-mono text-[11px] text-slate-800 break-all dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                      {guide.commandOrPath}
                    </div>
                  )}
                  <ol className="space-y-1.5 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {guide.steps.map((step, i) => (
                      <li key={i}>{i + 1}. {step}</li>
                    ))}
                  </ol>
                  <div className="border-t border-slate-100 pt-2 text-[11px] text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    {guide.note}
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>
      )}

      {/* Section B: Interactive Security Drills */}
      {currentSection === 'drills' && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900">
            <div className="text-xs font-mono tabular-nums text-slate-700 dark:text-slate-300">
              演練通過率：{passedCount} / {SECURITY_DRILLS.length}（已完成 {completedCount} 題）
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
      )}

      {/* Section C: Offline Risk Assessment & Remediation Guides */}
      {currentSection === 'risks' && (
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
      )}
    </div>
  );
};

