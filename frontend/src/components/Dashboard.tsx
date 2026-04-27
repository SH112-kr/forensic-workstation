import { useEffect, useState } from 'react';
import { get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';
import DependencyStatusPanel from './DependencyStatusPanel';

const KILL_CHAIN_PHASES = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const LANE_ORDER = ['ingress_access', 'execution_impact', 'persistence_cleanup'] as const;
const LANE_LABELS: Record<(typeof LANE_ORDER)[number], string> = {
  ingress_access: 'Ingress / Access',
  execution_impact: 'Execution / Impact',
  persistence_cleanup: 'Persistence / Cleanup',
};
const LANE_STATE_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  confirmed: { bg: 'var(--low-bg)', color: 'var(--low)', border: 'var(--low)' },
  suggested: { bg: 'var(--medium-bg)', color: 'var(--medium)', border: 'var(--medium)' },
  unverified: { bg: 'var(--high-bg)', color: 'var(--high)', border: 'var(--high)' },
  not_seen: { bg: 'var(--surface)', color: 'var(--text-dim)', border: 'var(--border)' },
};

function formatFindingTitle(ruleName: string) {
  return String(ruleName || '').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
}

function findingTier(finding: any) {
  return finding?.priority_tier || finding?.severity || 'info';
}

function findingText(finding: any) {
  return finding?.display_text || finding?.query_description || finding?.description || '';
}

function downgradeRiskLevel(level: string | null, allowStrongConclusion: boolean) {
  if (!level || allowStrongConclusion) return level;
  if (level === 'critical') return 'high';
  if (level === 'high') return 'medium';
  return level;
}

export default function Dashboard() {
  const {
    caseInfo,
    detection,
    mitre,
    laneStateBoard,
    detectionLoading,
    setDetection,
    setDetectionLoading,
    setLaneStateBoard,
    setActiveView,
    setLastAction,
    kapeDiagnostics,
    setKapeDiagnostics,
  } = useStore();
  const [coverageSummary, setCoverageSummary] = useState<{ searched: number; available_not_loaded: number; structurally_unavailable: number; case_format: string } | null>(null);
  const [antiForensics, setAntiForensics] = useState<any>(null);
  const [caseCount, setCaseCount] = useState(1);

  useEffect(() => {
    get('/api/cases/list').then((d) => setCaseCount((d.cases || []).length || 1)).catch(() => {});
  }, [caseInfo]);

  const isDirectMode = !!caseInfo?.case_mode; // e01 / memory — no AXIOM connector

  useEffect(() => {
    if (!caseInfo) return;
    if (isDirectMode) return; // skip all AXIOM-specific calls for image-only cases

    const shouldLoadDetection = !detection;
    const shouldLoadLaneState = laneStateBoard === null;
    if (shouldLoadDetection) {
      setDetectionLoading(true);
    }
    if (shouldLoadDetection || shouldLoadLaneState) {
      const t0 = performance.now();
      Promise.all([
        shouldLoadDetection ? post('/api/detection/run', {}).catch(() => null) : Promise.resolve(detection),
        shouldLoadDetection ? get('/api/detection/mitre').catch(() => null) : Promise.resolve(mitre),
        shouldLoadLaneState ? get('/api/triage/lane-state').catch(() => ({})) : Promise.resolve({ lane_state_board: laneStateBoard }),
      ]).then(([det, mit, lane]) => {
        if (shouldLoadDetection && det) {
          setDetection(det, mit);
          const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
          const count = det?.total_findings ?? 0;
          setLastAction(`Detection completed: ${count} findings (${elapsed}s)`);
        }
        if (shouldLoadLaneState) {
          setLaneStateBoard(lane?.lane_state_board ?? {});
        }
      }).finally(() => {
        if (shouldLoadDetection) setDetectionLoading(false);
      });
    }

    get('/api/cases/coverage').then((d) => {
      if (d && d.summary) {
        setCoverageSummary({
          searched: d.summary.searched,
          available_not_loaded: d.summary.available_not_loaded,
          structurally_unavailable: d.summary.structurally_unavailable,
          case_format: d.case_context?.case_format || '',
        });
      }
    }).catch(() => {});

    get('/api/detection/anti-forensics').then((d) => {
      if (d && d.rules_fired > 0) setAntiForensics(d);
      else setAntiForensics(null);
    }).catch(() => {});

    if (!kapeDiagnostics) {
      get('/api/cases/summary').then((data) => {
        if (data.kape_diagnostics) setKapeDiagnostics(data.kape_diagnostics);
      }).catch(() => {});
    }
  }, [
    caseInfo,
    detection,
    mitre,
    laneStateBoard,
    kapeDiagnostics,
    setDetection,
    setDetectionLoading,
    setLaneStateBoard,
    setLastAction,
    setKapeDiagnostics,
  ]);

  if (!caseInfo) return null;

  // E01 / memory direct-analysis mode — no AXIOM artifacts available
  if (isDirectMode) {
    const isE01 = caseInfo.case_mode === 'e01';
    const modeLabel = isE01 ? 'Disk Image (E01)' : 'Memory Dump';
    const quickActions: { label: string; view: string; desc: string }[] = isE01
      ? [
          { label: 'Binary Analysis', view: 'binary', desc: 'Extract & Ghidra-analyze files from image' },
          { label: 'Registry Analysis', view: 'registry', desc: 'Browse NTFS registry hives' },
          { label: 'Auto Triage', view: 'settings', desc: 'Run KAPE on mounted image to unlock full analysis' },
        ]
      : [
          { label: 'Memory Analysis', view: 'memory', desc: 'Run Volatility plugins against this dump' },
        ];
    return (
      <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
        <DependencyStatusPanel compact />

        <div style={{
          padding: '16px 20px', borderRadius: 10, marginBottom: 20,
          background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)',
        }}>
          <div style={{ fontWeight: 700, fontSize: 15, color: '#f59e0b', marginBottom: 6 }}>
            Direct Image Analysis — {modeLabel}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
            {isE01
              ? 'The E01 image is mounted via dissect. Artifact-level detection (Prefetch, SRUM, Event Logs) requires KAPE output. Use Binary Analysis to extract and examine individual files, or run Auto Triage to generate a full KAPE-parsed case.'
              : 'Memory dump loaded. Use Memory Analysis for Volatility-based process and artifact extraction.'}
          </div>
        </div>

        <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
          Available actions
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10, marginBottom: 24 }}>
          {quickActions.map((a) => (
            <div
              key={a.view}
              onClick={() => setActiveView(a.view)}
              style={{
                padding: '16px 18px', borderRadius: 10, cursor: 'pointer',
                background: 'var(--surface)', border: '1px solid var(--border)',
                transition: 'border-color 0.15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; }}
            >
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{a.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{a.desc}</div>
            </div>
          ))}
        </div>

        {isE01 && (
          <>
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              To enable full artifact detection
            </h3>
            <div style={{
              padding: '14px 18px', borderRadius: 10,
              background: 'var(--surface)', border: '1px solid var(--border)',
              fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7,
            }}>
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>1.</span> Mount the E01 with Arsenal Image Mounter or similar — obtain a drive letter (e.g. <code style={{ fontFamily: 'monospace' }}>G:</code>)
              </div>
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>2.</span> Go to <span
                  onClick={() => setActiveView('settings')}
                  style={{ color: 'var(--accent)', cursor: 'pointer', fontWeight: 600 }}
                >Settings → Auto Triage</span> and enter that drive letter
              </div>
              <div>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>3.</span> KAPE collects + parses artifacts → full detection, MITRE, timeline become available
              </div>
            </div>
          </>
        )}
      </div>
    );
  }

  const findings = detection?.findings || [];
  const keyFindings = detection?.alert_summary?.key_findings || findings.slice(0, 10);
  const balanceWarnings = detection?.alert_summary?.balance?.warnings || [];
  const autonomousAssessment = detection?.autonomous_assessment || null;
  const loading = detectionLoading;
  const laneBoard = laneStateBoard || null;
  const laneError = laneBoard?.error || '';
  const hasLaneBoard = !!laneBoard && LANE_ORDER.some((lane) => lane in laneBoard);
  const allowStrongConclusion = hasLaneBoard ? laneBoard?.allow_strong_conclusion !== false : true;
  const blockedLaneLabels = (laneBoard?.blocked_lanes || []).map((lane: string) => LANE_LABELS[lane as keyof typeof LANE_LABELS] || lane);

  const hasCritical = keyFindings.some((f: any) => findingTier(f) === 'critical');
  const hasHigh = keyFindings.some((f: any) => findingTier(f) === 'high');
  const rawRiskLevel = loading ? null : hasCritical ? 'critical' : hasHigh ? 'high' : keyFindings.length ? 'medium' : 'low';
  const riskLevel = downgradeRiskLevel(rawRiskLevel, allowStrongConclusion);
  const riskDowngraded = rawRiskLevel !== null && rawRiskLevel !== riskLevel;
  const riskLabels: Record<string, string> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
  };

  const phases = mitre?.narrative || [];
  const activePhases = new Set(phases.map((p: any) => p.tactic));
  const criticalCount = findings.filter((f: any) => findingTier(f) === 'critical').length;
  const severityCounts = {
    critical: criticalCount,
    high: findings.filter((f: any) => findingTier(f) === 'high').length,
    medium: findings.filter((f: any) => findingTier(f) === 'medium').length,
    low: findings.filter((f: any) => findingTier(f) === 'low').length,
  };
  const maxSeverityCount = Math.max(1, ...Object.values(severityCounts));
  const nextSteps: { text: string; cta: string; onClick: () => void }[] = [];
  if (criticalCount > 0) {
    nextSteps.push({
      text: `Detection includes ${criticalCount} critical findings that need review.`,
      cta: 'Detection',
      onClick: () => setActiveView('detection'),
    });
  }
  if (coverageSummary && coverageSummary.structurally_unavailable > 0) {
    nextSteps.push({
      text: `${coverageSummary.structurally_unavailable} artifact families are structurally unavailable in this case format.`,
      cta: 'Coverage',
      onClick: () => setActiveView('coverage'),
    });
  }
  if (antiForensics && antiForensics.rules_fired > 0) {
    const firedNames = (antiForensics.rules || [])
      .filter((r: any) => r.ok && r.count)
      .map((r: any) => r.rule_name)
      .slice(0, 3)
      .join(', ');
    nextSteps.push({
      text: `Anti-forensics fired: ${firedNames}`,
      cta: 'Detection',
      onClick: () => setActiveView('detection'),
    });
  }
  if (nextSteps.length === 0 && caseCount >= 2) {
    nextSteps.push({
      text: 'No urgent signals surfaced. Validate by pivoting across loaded cases.',
      cta: 'Pivot',
      onClick: () => setActiveView('pivot'),
    });
  }

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      {antiForensics && antiForensics.rules_fired > 0 && (
        <div
          onClick={() => setActiveView('detection')}
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            marginBottom: 12,
            background: 'var(--critical-bg)',
            border: '1px solid var(--critical)',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            cursor: 'pointer',
          }}
          title="Review the full anti-forensics findings in Detection"
        >
          <div style={{ flex: 1, fontSize: 12 }}>
            <div style={{ fontWeight: 700, color: 'var(--critical)' }}>
              Anti-forensic activity detected
            </div>
            <div style={{ color: 'var(--text-dim)' }}>
              {antiForensics.rules_fired} rule{antiForensics.rules_fired > 1 ? 's' : ''} fired, {antiForensics.total_hits} total hit{antiForensics.total_hits === 1 ? '' : 's'}
            </div>
          </div>
          <span style={{ color: 'var(--critical)', fontSize: 12, fontWeight: 600 }}>Review</span>
        </div>
      )}

      {autonomousAssessment && !autonomousAssessment.error && (
        <div
          onClick={() => setActiveView('detection')}
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            marginBottom: 12,
            background: autonomousAssessment.investigation_incomplete ? 'var(--high-bg)' : 'var(--accent-light)',
            border: `1px solid ${autonomousAssessment.investigation_incomplete ? 'var(--high)' : 'var(--accent)'}`,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            cursor: 'pointer',
          }}
          title="Review autonomous assessment details in Detection"
        >
          <div style={{ flex: 1, fontSize: 12 }}>
            <div style={{
              fontWeight: 700,
              color: autonomousAssessment.investigation_incomplete ? 'var(--high)' : 'var(--accent)',
            }}>
              Autonomous decision: {String(autonomousAssessment.decision || 'unknown').replace(/_/g, ' ')}
            </div>
            <div style={{ color: 'var(--text-dim)' }}>
              Verdict {String(autonomousAssessment.verdict || 'unknown').replace(/_/g, ' ')}
              {' '}| confidence {autonomousAssessment.confidence || 'unknown'}
              {autonomousAssessment.blocked_lanes?.length ? ` | blocked: ${autonomousAssessment.blocked_lanes.join(', ')}` : ''}
            </div>
          </div>
          <span style={{
            color: autonomousAssessment.investigation_incomplete ? 'var(--high)' : 'var(--accent)',
            fontSize: 12,
            fontWeight: 600,
          }}>Details</span>
        </div>
      )}

      {hasLaneBoard && allowStrongConclusion === false && (
        <div
          onClick={() => setActiveView('detection')}
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            marginBottom: 12,
            background: 'var(--high-bg)',
            border: '1px solid var(--high)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--high)', marginBottom: 4 }}>
            Investigation incomplete
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            Lanes unverified: {blockedLaneLabels.join(', ') || 'unknown'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            Do not issue strong end-to-end conclusions.
          </div>
        </div>
      )}

      {laneError && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 10,
          marginBottom: 12,
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          fontSize: 12,
          color: 'var(--text-dim)',
        }}>
          <strong style={{ color: 'var(--text)' }}>Lane state unavailable.</strong> {laneError}
        </div>
      )}

      {balanceWarnings.length > 0 && (
        <div
          onClick={() => setActiveView('detection')}
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            marginBottom: 12,
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
            Balance warning
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            {balanceWarnings[0]}
          </div>
        </div>
      )}

      {nextSteps.length > 0 && (
        <div style={{
          padding: '10px 14px',
          borderRadius: 10,
          marginBottom: 12,
          background: 'var(--surface)',
          border: '1px solid var(--border)',
        }}>
          <div style={{
            fontSize: 11,
            color: 'var(--text-dim)',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
            marginBottom: 6,
          }}>
            Suggested next steps
          </div>
          {nextSteps.map((step, index) => (
            <div
              key={index}
              onClick={step.onClick}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '6px 0',
                cursor: 'pointer',
                fontSize: 12,
                borderTop: index > 0 ? '1px solid var(--border-light)' : 'none',
              }}
            >
              <span style={{ flex: 1 }}>{step.text}</span>
              <span style={{ color: 'var(--accent)', fontSize: 11, fontWeight: 600 }}>{step.cta}</span>
            </div>
          ))}
        </div>
      )}

      {coverageSummary && (coverageSummary.structurally_unavailable > 0 || coverageSummary.available_not_loaded > 0) && (
        <div
          onClick={() => setActiveView('coverage')}
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            marginBottom: 12,
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            cursor: 'pointer',
          }}
          title="Open full coverage view"
        >
          <div style={{ flex: 1, fontSize: 12 }}>
            <div style={{ fontWeight: 700, color: 'var(--text)' }}>Evidence coverage</div>
            <div style={{ color: 'var(--text-dim)' }}>
              <span style={{ color: '#4ade80' }}>{coverageSummary.searched} searchable</span>
              {coverageSummary.available_not_loaded > 0 && <> | <span style={{ color: '#f59e0b' }}>{coverageSummary.available_not_loaded} with zero records</span></>}
              {coverageSummary.structurally_unavailable > 0 && <> | <span style={{ color: '#ef4444' }}>{coverageSummary.structurally_unavailable} structurally unavailable</span></>}
              {coverageSummary.case_format === 'kape' && <> | KAPE-only case</>}
            </div>
          </div>
          <span style={{ color: 'var(--accent)', fontSize: 12, fontWeight: 600 }}>Details</span>
        </div>
      )}

      {kapeDiagnostics && kapeDiagnostics.modules_failed > 0 && (
        <div style={{
          padding: '14px 18px',
          borderRadius: 10,
          marginBottom: 16,
          background: 'rgba(245,158,11,0.08)',
          border: '1px solid rgba(245,158,11,0.25)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <span style={{ fontWeight: 700, fontSize: 13, color: '#f59e0b' }}>
              KAPE parsing incomplete: {kapeDiagnostics.modules_failed} module{kapeDiagnostics.modules_failed > 1 ? 's' : ''} failed
            </span>
            <div style={{ flex: 1 }} />
            <span
              onClick={() => setKapeDiagnostics(null)}
              style={{ cursor: 'pointer', color: 'var(--text-dim)', fontSize: 18, lineHeight: 1 }}
            >
              x
            </span>
          </div>

          {kapeDiagnostics.dotnet_errors > 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
              <span style={{ color: '#ef4444', fontWeight: 600 }}>.NET runtimeconfig missing:</span>{' '}
              {[...new Set((kapeDiagnostics.failed_modules || [])
                .filter((m: any) => m.reason?.includes('runtimeconfig'))
                .map((m: any) => m.module))].join(', ') || `${kapeDiagnostics.dotnet_errors} modules`}
            </div>
          )}

          {kapeDiagnostics.missing_modules?.length > 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
              <span style={{ color: '#ef4444', fontWeight: 600 }}>Missing modules:</span>{' '}
              {kapeDiagnostics.missing_modules.join(', ')}
            </div>
          )}

          {kapeDiagnostics.recovered_modules?.length > 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
              <span style={{ color: '#4ade80', fontWeight: 600 }}>Recovered:</span>{' '}
              {kapeDiagnostics.recovered_modules.join(', ')}
            </div>
          )}

          {caseInfo && Object.keys(caseInfo.artifact_types || {}).length > 0 && (
            <div style={{ fontSize: 12, marginBottom: 6 }}>
              <span style={{ color: '#4ade80', fontWeight: 600 }}>Loaded:</span>{' '}
              <span style={{ color: 'var(--text-dim)' }}>
                {Object.entries(caseInfo.artifact_types)
                  .map(([name, count]) => `${name} (${(count as number).toLocaleString()})`)
                  .join(', ')}
              </span>
            </div>
          )}

          {kapeDiagnostics.recommendations?.map((recommendation: string, index: number) => (
            <div
              key={index}
              style={{
                fontSize: 11,
                color: '#60a5fa',
                marginTop: 4,
                padding: '4px 8px',
                borderRadius: 4,
                background: 'rgba(96,165,250,0.08)',
              }}
            >
              {recommendation}
            </div>
          ))}

          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button
              onClick={() => setActiveView('settings')}
              style={{
                padding: '5px 14px',
                borderRadius: 5,
                border: 'none',
                fontSize: 11,
                background: '#f59e0b',
                color: '#000',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Run KAPE health check
            </button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <div className="card" style={{ width: 190, flexShrink: 0 }}>
          <div className="card-label">Risk Level</div>
          {loading ? (
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 10 }}>
              <span className="spinner" />
              <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Running detection</span>
            </div>
          ) : riskLevel ? (
            <>
              <div style={{
                fontFamily: 'var(--mono)',
                fontSize: 28,
                lineHeight: 1.1,
                fontWeight: 800,
                color: `var(--${riskLevel})`,
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
                marginTop: 6,
              }}>
                {riskLabels[riskLevel]}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-subtle)', marginTop: 4 }}>
                {riskDowngraded ? 'Strong conclusion blocked by lane state' : `${findings.length} detection rules triggered`}
              </div>
            </>
          ) : (
            <div style={{ color: 'var(--text-muted)', marginTop: 10 }}>Not assessed</div>
          )}
        </div>

        <div className="card" style={{ flex: 1, minWidth: 260 }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 8 }}>
            <div className="card-label">Finding Distribution</div>
            <div style={{ flex: 1 }} />
            <button className="btn btn-sm" onClick={() => setActiveView('detection')}>
              View all {findings.length}
            </button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, height: 58, alignItems: 'end' }}>
            {(['critical', 'high', 'medium', 'low'] as const).map(level => (
              <div key={level} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                <div style={{
                  width: '100%',
                  height: Math.max(4, (severityCounts[level] / maxSeverityCount) * 30),
                  background: `var(--${level})`,
                  opacity: 0.75,
                  borderRadius: 2,
                }} />
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text)' }}>{severityCounts[level]}</div>
                <div style={{ fontSize: 10, color: 'var(--text-subtle)', textTransform: 'uppercase' }}>{level}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card" style={{ width: 230, flexShrink: 0 }}>
          <div className="card-label" style={{ marginBottom: 6 }}>Case Metadata</div>
          {[
            ['Source', caseInfo.source_type || caseInfo.case_mode || 'case'],
            ['Artifacts', (caseInfo.total_hits || 0).toLocaleString()],
            ['Types', String(caseInfo.artifact_type_count || 0)],
            ['Opened', (caseInfo.date_range_start || '?').slice(0, 10)],
            ['Status', allowStrongConclusion ? 'reviewable' : 'incomplete'],
          ].map(([label, value]) => (
            <div key={label} style={{
              display: 'flex',
              justifyContent: 'space-between',
              gap: 10,
              padding: '4px 0',
              borderBottom: '1px solid var(--border-muted)',
              fontSize: 11,
            }}>
              <span style={{ color: 'var(--text-subtle)' }}>{label}</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {value}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
          <div className="card-label">MITRE ATT&CK Kill Chain Coverage</div>
          <div style={{ flex: 1 }} />
          <LegendDot color="var(--high)" label="seen" />
          <LegendDot color="var(--text-subtle)" label="not seen" />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, minmax(84px, 1fr))', gap: 4 }}>
          {KILL_CHAIN_PHASES.map((phase, index) => {
            const isHit = activePhases.has(phase);
            return (
              <div
                key={phase}
                style={{
                  minHeight: 48,
                  padding: '5px 4px',
                  borderRadius: 3,
                  border: `1px solid ${isHit ? 'var(--high-border)' : 'var(--border-muted)'}`,
                  background: isHit ? 'var(--high-bg)' : 'transparent',
                  textAlign: 'center',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  gap: 2,
                }}
              >
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: isHit ? 'var(--high)' : 'var(--text-subtle)' }}>
                  {String(index + 1).padStart(2, '0')}
                </div>
                <div style={{ fontSize: 10, fontWeight: isHit ? 700 : 600, color: isHit ? 'var(--text)' : 'var(--text-muted)' }}>
                  {phase.replace('Command and Control', 'C2').replace('Resource Development', 'Resource Dev.')}
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: isHit ? 'var(--high)' : 'var(--text-subtle)' }}>
                  {isHit ? 'SEEN' : ''}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {hasLaneBoard && !laneError && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-label" style={{ marginBottom: 10 }}>Investigative Lanes</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
            {LANE_ORDER.map((lane) => {
              const entry = laneBoard?.[lane] || {};
              const state = entry.state || 'not_seen';
              const style = LANE_STATE_STYLES[state] || LANE_STATE_STYLES.not_seen;
              const basis = (entry.basis || []).slice(0, 2).join(', ') || 'No supporting signals surfaced';
              return (
                <div
                  key={lane}
                  onClick={() => setActiveView('detection')}
                  style={{
                    padding: '12px 12px 10px',
                    borderRadius: '0 4px 4px 0',
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    borderLeft: `3px solid ${style.color}`,
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <div style={{ fontWeight: 700, fontSize: 13, flex: 1 }}>{LANE_LABELS[lane]}</div>
                    <span style={{
                      fontFamily: 'var(--mono)',
                      fontSize: 9,
                      fontWeight: 700,
                      letterSpacing: '0.06em',
                      color: style.color,
                      border: `1px solid ${style.color}`,
                      borderRadius: 3,
                      padding: '1px 5px',
                    }}>
                      {String(state).toUpperCase()}
                    </span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 3, marginBottom: 8 }}>
                    {[0, 1, 2, 3].map((slot) => (
                      <div key={slot} style={{
                        height: 3,
                        borderRadius: 2,
                        background: slot === 0 ? style.color : 'rgba(139,148,158,0.25)',
                      }} />
                    ))}
                  </div>
                  <div style={{ borderTop: '1px solid var(--border-muted)', paddingTop: 8, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    {basis}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <h3 style={{ fontSize: 13, fontWeight: 600, margin: '24px 0 10px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        Key findings (balanced)
      </h3>
      {keyFindings.slice(0, 10).map((finding: any, index: number) => (
        <div
          key={index}
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border-light)',
            borderRadius: 8,
            padding: '12px 16px',
            marginBottom: 8,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 12,
            cursor: 'pointer',
          }}
          onClick={() => setActiveView('detection')}
        >
          <span className={`badge badge-${findingTier(finding)}`}>{String(findingTier(finding)).toUpperCase()}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>
              {formatFindingTitle(finding.rule_name)}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{findingText(finding)}</div>
            <div style={{ marginTop: 4 }}>
              {(finding.mitre_techniques || []).map((technique: string) => (
                <span
                  key={technique}
                  style={{
                    display: 'inline-block',
                    padding: '0 5px',
                    margin: '2px 3px 0 0',
                    background: 'var(--accent-light)',
                    borderRadius: 3,
                    fontSize: 10,
                    fontFamily: 'var(--mono)',
                  }}
                >
                  {technique}
                </span>
              ))}
            </div>
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-dim)' }}>
            {(finding.matching_count || 0).toLocaleString()}
          </div>
        </div>
      ))}

      {!loading && keyFindings.length === 0 && findings.length > 0 && (
        <div style={{ color: 'var(--text-dim)', fontSize: 13, fontStyle: 'italic' }}>
          Balanced selection returned 0 findings. Review Detection for the full legacy list.
        </div>
      )}

      {!loading && findings.length === 0 && (
        <div style={{ color: 'var(--text-dim)', fontSize: 13, fontStyle: 'italic' }}>
          No findings detected.
        </div>
      )}
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, marginLeft: 10, fontSize: 10, color: 'var(--text-subtle)', textTransform: 'uppercase' }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
      {label}
    </span>
  );
}
