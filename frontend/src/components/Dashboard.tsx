import { useEffect, useState } from 'react';
import { get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

export default function Dashboard() {
  const { caseInfo, detection, mitre, detectionLoading, setDetection, setDetectionLoading, setActiveView, setLastAction, kapeDiagnostics, setKapeDiagnostics } = useStore();
  const [topTypes, setTopTypes] = useState<any[]>([]);
  const [coverageSummary, setCoverageSummary] = useState<{ searched: number; available_not_loaded: number; structurally_unavailable: number; case_format: string } | null>(null);
  const [antiForensics, setAntiForensics] = useState<any>(null);

  useEffect(() => {
    // Only fetch if not already cached
    if (!caseInfo || detection) return;
    setDetectionLoading(true);
    const t0 = performance.now();
    Promise.all([
      post('/api/detection/run', {}).catch(() => null),
      get('/api/detection/mitre').catch(() => null),
    ]).then(([det, mit]) => {
      setDetection(det, mit);
      const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
      const count = det?.total_findings ?? 0;
      setLastAction(`Detection completed: ${count} findings (${elapsed}s)`);
    }).finally(() => setDetectionLoading(false));

    // Fetch top artifact types for bar chart
    get('/api/cases/types').then(data => setTopTypes((data.artifact_types || []).slice(0, 10))).catch(() => {});

    // Coverage summary — gives the analyst an at-a-glance hint that some
    // families are structurally unavailable before they chase empty searches.
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

    // Anti-forensics — runs against the active case and surfaces at the top
    // of the Dashboard when any rule fires so log-tamper / shadow-deletion is
    // impossible to miss.
    get('/api/detection/anti-forensics').then((d) => {
      if (d && d.rules_fired > 0) setAntiForensics(d);
    }).catch(() => {});

    // Fetch KAPE diagnostics if not already loaded
    if (!kapeDiagnostics) {
      get('/api/cases/summary').then(data => {
        if (data.kape_diagnostics) setKapeDiagnostics(data.kape_diagnostics);
      }).catch(() => {});
    }
  }, [caseInfo, detection]);

  if (!caseInfo) return null;

  const findings = detection?.findings || [];
  const loading = detectionLoading;

  // Don't show risk level until detection is complete
  const hasCritical = findings.some((f: any) => f.severity === 'critical');
  const hasHigh = findings.some((f: any) => f.severity === 'high');
  const riskLevel = loading ? null : hasCritical ? 'critical' : hasHigh ? 'high' : findings.length ? 'medium' : 'low';
  const riskLabels: Record<string, string> = {
    critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW',
  };

  const phases = mitre?.narrative || [];
  const killChainPhases = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
  ];
  const activePhases = new Set(phases.map((p: any) => p.tactic));

  const clickableCardStyle: React.CSSProperties = { cursor: 'pointer', transition: 'transform 0.1s' };

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      {/* Anti-forensics alert — renders first so log tamper / snapshot
          deletion is never buried. Only appears when rules actually fired. */}
      {antiForensics && antiForensics.rules_fired > 0 && (
        <div
          onClick={() => setActiveView('detection')}
          style={{
            padding: '12px 16px', borderRadius: 10, marginBottom: 12,
            background: 'var(--critical-bg)', border: '1px solid var(--critical)',
            display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer',
          }}
          title="Review the full anti-forensics findings in Detection"
        >
          <span style={{ fontSize: 18 }}>⚠</span>
          <div style={{ flex: 1, fontSize: 12 }}>
            <div style={{ fontWeight: 700, color: 'var(--critical)' }}>
              Anti-forensic activity detected
            </div>
            <div style={{ color: 'var(--text-dim)' }}>
              {antiForensics.rules_fired} rule{antiForensics.rules_fired > 1 ? 's' : ''} fired ·
              {' '}{antiForensics.total_hits} total hit{antiForensics.total_hits === 1 ? '' : 's'} ·
              {' '}{(antiForensics.rules || []).filter((r: any) => r.ok && r.count).map((r: any) => r.rule_name).join(', ')}
            </div>
          </div>
          <span style={{ color: 'var(--critical)', fontSize: 12, fontWeight: 600 }}>Review →</span>
        </div>
      )}

      {/* Evidence Coverage — compact summary with a jump to the full view. Hides
          when no hints are actionable (everything searched, nothing structural). */}
      {coverageSummary && (coverageSummary.structurally_unavailable > 0 || coverageSummary.available_not_loaded > 0) && (
        <div
          onClick={() => setActiveView('coverage')}
          style={{
            padding: '12px 16px', borderRadius: 10, marginBottom: 12,
            background: 'var(--surface)', border: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer',
          }}
          title="Open full coverage view"
        >
          <span style={{ fontSize: 16 }}>🧾</span>
          <div style={{ flex: 1, fontSize: 12 }}>
            <div style={{ fontWeight: 700, color: 'var(--text)' }}>Evidence Coverage</div>
            <div style={{ color: 'var(--text-dim)' }}>
              <span style={{ color: '#4ade80' }}>{coverageSummary.searched} searchable</span>
              {coverageSummary.available_not_loaded > 0 && (
                <> · <span style={{ color: '#f59e0b' }}>{coverageSummary.available_not_loaded} with zero records</span></>
              )}
              {coverageSummary.structurally_unavailable > 0 && (
                <> · <span style={{ color: '#ef4444' }}>{coverageSummary.structurally_unavailable} structurally unavailable</span></>
              )}
              {coverageSummary.case_format === 'kape' && (
                <> — KAPE-only case; AXIOM-only families cannot be searched here.</>
              )}
            </div>
          </div>
          <span style={{ color: 'var(--accent)', fontSize: 12, fontWeight: 600 }}>Details →</span>
        </div>
      )}

      {/* KAPE Diagnostics Banner */}
      {kapeDiagnostics && kapeDiagnostics.modules_failed > 0 && (
        <div style={{
          padding: '14px 18px', borderRadius: 10, marginBottom: 16,
          background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <span style={{ fontSize: 16 }}>{'\u26A0'}</span>
            <span style={{ fontWeight: 700, fontSize: 13, color: '#f59e0b' }}>
              KAPE Parsing Incomplete — {kapeDiagnostics.modules_failed} module{kapeDiagnostics.modules_failed > 1 ? 's' : ''} failed
            </span>
            <div style={{ flex: 1 }} />
            <span onClick={() => setKapeDiagnostics(null)}
              style={{ cursor: 'pointer', color: 'var(--text-dim)', fontSize: 18, lineHeight: 1 }}>{'\u00D7'}</span>
          </div>

          {/* Failed modules grouped by reason */}
          {kapeDiagnostics.dotnet_errors > 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
              <span style={{ color: '#ef4444', fontWeight: 600 }}>.NET runtimeconfig missing:</span>{' '}
              {[...new Set((kapeDiagnostics.failed_modules || [])
                .filter((m: any) => m.reason?.includes('runtimeconfig'))
                .map((m: any) => m.module))]
                .join(', ') || `${kapeDiagnostics.dotnet_errors} modules`}
            </div>
          )}

          {kapeDiagnostics.missing_modules?.length > 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
              <span style={{ color: '#ef4444', fontWeight: 600 }}>Missing modules:</span>{' '}
              {kapeDiagnostics.missing_modules.join(', ')}
            </div>
          )}

          {/* Recovered modules */}
          {kapeDiagnostics.recovered_modules?.length > 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
              <span style={{ color: '#4ade80', fontWeight: 600 }}>Recovered (re-parsed):</span>{' '}
              {kapeDiagnostics.recovered_modules.join(', ')}
            </div>
          )}

          {/* Loaded artifact types */}
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

          {/* Recommendations */}
          {kapeDiagnostics.recommendations?.map((r: string, i: number) => (
            <div key={i} style={{
              fontSize: 11, color: '#60a5fa', marginTop: 4,
              padding: '4px 8px', borderRadius: 4, background: 'rgba(96,165,250,0.08)',
            }}>
              {r}
            </div>
          ))}

          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button onClick={() => setActiveView('settings')} style={{
              padding: '5px 14px', borderRadius: 5, border: 'none', fontSize: 11,
              background: '#f59e0b', color: '#000', fontWeight: 600, cursor: 'pointer',
            }}>
              Run KAPE Health Check
            </button>
          </div>
        </div>
      )}

      {/* Risk Banner */}
      {loading ? (
        <div style={{
          padding: '16px 20px', borderRadius: 10, marginBottom: 20,
          background: 'var(--surface)', border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <div style={{
            width: 18, height: 18, border: '3px solid var(--border)',
            borderTopColor: 'var(--accent)', borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
          }} />
          <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>Running threat detection...</span>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      ) : riskLevel && (
        <div style={{
          padding: '16px 20px', borderRadius: 10, marginBottom: 20,
          display: 'flex', alignItems: 'center', gap: 16,
          background: `var(--${riskLevel}-bg)`,
          border: `1px solid var(--${riskLevel})`,
        }}>
          <span style={{ fontSize: 28, fontWeight: 800, color: `var(--${riskLevel})` }}>
            {riskLabels[riskLevel]}
          </span>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            <strong style={{ color: 'var(--text)' }}>Risk Assessment</strong>
            <br />
            {findings.length} detection rules triggered, {findings.reduce((s: number, f: any) => s + f.matching_count, 0).toLocaleString()} total evidence hits
          </div>
        </div>
      )}

      {/* Cards */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
        gap: 10, marginBottom: 24,
      }}>
        <div className="card" onClick={() => setActiveView('artifacts')} style={clickableCardStyle}
          onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
          onMouseLeave={e => (e.currentTarget.style.transform = 'none')}>
          <div className="card-label">Artifacts</div>
          <div className="card-value">{caseInfo.total_hits?.toLocaleString()}</div>
        </div>
        <div className="card" onClick={() => setActiveView('artifacts')} style={clickableCardStyle}
          onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
          onMouseLeave={e => (e.currentTarget.style.transform = 'none')}>
          <div className="card-label">Types</div>
          <div className="card-value">{caseInfo.artifact_type_count}</div>
        </div>
        <div className="card" onClick={() => setActiveView('detection')} style={clickableCardStyle}
          onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
          onMouseLeave={e => (e.currentTarget.style.transform = 'none')}>
          <div className="card-label">Findings</div>
          <div className="card-value" style={{ color: 'var(--critical)' }}>
            {loading ? '...' : detection?.total_findings ?? '0'}
          </div>
        </div>
        <div className="card" onClick={() => setActiveView('detection')} style={clickableCardStyle}
          onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
          onMouseLeave={e => (e.currentTarget.style.transform = 'none')}>
          <div className="card-label">ATT&CK</div>
          <div className="card-value" style={{ color: 'var(--high)' }}>
            {loading ? '...' : mitre?.attack_phases ?? '0'}
          </div>
        </div>
        <div className="card" onClick={() => setActiveView('timeline')} style={clickableCardStyle}
          onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
          onMouseLeave={e => (e.currentTarget.style.transform = 'none')}>
          <div className="card-label">Period</div>
          <div className="card-value" style={{ fontSize: 13 }}>
            {(caseInfo.date_range_start || '?').slice(0, 10)} ~ {(caseInfo.date_range_end || '?').slice(0, 10)}
          </div>
        </div>
      </div>

      {/* Kill Chain */}
      <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        Attack Kill Chain
      </h3>
      <div style={{
        display: 'flex', gap: 3, marginBottom: 24, overflowX: 'auto', paddingBottom: 4,
      }}>
        {killChainPhases.map((phase, i) => {
          const isHit = activePhases.has(phase);
          return (
            <div key={phase} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
              <div style={{
                flex: '1 0 80px', minWidth: 80, padding: '8px 6px', borderRadius: 6,
                textAlign: 'center', fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                border: `1px solid ${isHit ? 'var(--high)' : 'var(--border-light)'}`,
                background: isHit ? 'var(--high-bg)' : 'var(--surface)',
                color: isHit ? 'var(--high)' : 'var(--text-dim)',
              }}>
                <div style={{ fontSize: 8, opacity: 0.6 }}>{i + 1}</div>
                {phase.replace('Command and Control', 'C2')}
              </div>
              {i < killChainPhases.length - 1 && (
                <span style={{ color: 'var(--border)', fontSize: 8 }}>{'\u25B6'}</span>
              )}
            </div>
          );
        })}
      </div>

      {/* Top Artifact Types bar chart */}
      <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        Top Artifact Types
      </h3>
      {topTypes.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          {topTypes.map((t, i) => {
            const maxCount = topTypes[0]?.count || 1;
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ width: 180, fontSize: 11, color: 'var(--text-dim)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{t.artifact_type}</span>
                <div style={{ flex: 1, background: 'var(--surface)', borderRadius: 4, height: 16 }}>
                  <div style={{ width: `${(t.count / maxCount * 100)}%`, background: 'var(--accent)', height: '100%', borderRadius: 4, minWidth: 2 }} />
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-dim)', minWidth: 60, textAlign: 'right' }}>{t.count.toLocaleString()}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Key Findings */}
      <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        Key Findings
      </h3>
      {findings.filter((f: any) => f.severity === 'critical' || f.severity === 'high').map((f: any, i: number) => (
        <div key={i} style={{
          background: 'var(--surface)', border: '1px solid var(--border-light)',
          borderRadius: 8, padding: '12px 16px', marginBottom: 8,
          display: 'flex', alignItems: 'flex-start', gap: 12,
          cursor: 'pointer',
        }} onClick={() => setActiveView('detection')}>
          <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>
              {f.rule_name.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{f.description}</div>
            <div style={{ marginTop: 4 }}>
              {(f.mitre_techniques || []).map((t: string) => (
                <span key={t} style={{
                  display: 'inline-block', padding: '0 5px', margin: '2px 3px 0 0',
                  background: 'var(--accent-light)', borderRadius: 3, fontSize: 10,
                  fontFamily: 'var(--mono)',
                }}>{t}</span>
              ))}
            </div>
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-dim)' }}>
            {f.matching_count.toLocaleString()}
          </div>
        </div>
      ))}

      {!loading && findings.length === 0 && (
        <div style={{ color: 'var(--text-dim)', fontSize: 13, fontStyle: 'italic' }}>
          No findings detected.
        </div>
      )}
    </div>
  );
}
