import { useEffect, useState } from 'react';
import { post, get } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

type StrengthTier = 'confirmed' | 'strong' | 'moderate' | 'weak';

const STRENGTH_LABEL: Record<StrengthTier, string> = {
  confirmed: 'Confirmed',
  strong: 'Strong',
  moderate: 'Moderate',
  weak: 'Weak',
};

export default function DetectionPanel() {
  const { detection, mitre, setDetection, setLastAction } = useStore();
  const [findings, setFindings] = useState<any[]>(detection?.findings || []);
  const [strengthRollup, setStrengthRollup] = useState<Record<StrengthTier, number> | null>(detection?.strength_rollup || null);
  const [mitreData, setMitreData] = useState<any>(mitre);
  const [loading, setLoading] = useState(false);
  const [openIdx, setOpenIdx] = useState<number | null>(null);
  const [antiForensics, setAntiForensics] = useState<any>(null);
  const [afLoading, setAfLoading] = useState(false);
  const [afError, setAfError] = useState('');

  // Use cached data if available, otherwise fetch
  useEffect(() => {
    if (detection?.findings) {
      setFindings(detection.findings);
      setMitreData(mitre);
      setStrengthRollup(detection.strength_rollup || null);
    } else {
      runDetection();
    }
    // Anti-forensics is cheap to pull alongside.
    loadAntiForensics();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runDetection = async () => {
    setLoading(true);
    try {
      const t0 = performance.now();
      const [det, mit] = await Promise.all([
        post('/api/detection/run', {}),
        get('/api/detection/mitre'),
      ]);
      setFindings(det.findings || []);
      setMitreData(mit);
      setStrengthRollup(det.strength_rollup || null);
      setDetection(det, mit);
      const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
      setLastAction(`Detection completed: ${det.total_findings ?? 0} findings (${elapsed}s)`);
    } catch (e) {
      console.error('Detection error:', e);
    } finally { setLoading(false); }
  };

  const loadAntiForensics = async () => {
    setAfLoading(true);
    setAfError('');
    try {
      const r = await get('/api/detection/anti-forensics');
      setAntiForensics(r);
    } catch (e: any) {
      setAfError(e?.message || 'Failed to run anti-forensics detection');
    } finally {
      setAfLoading(false);
    }
  };

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600 }}>Threat Detection</h2>
        <button className="btn btn-primary btn-sm" onClick={runDetection} disabled={loading}>
          {loading ? 'Running...' : 'Re-run Detection'}
        </button>
      </div>

      {loading && (
        <div style={{ padding: 20, display: 'flex', alignItems: 'center', gap: 12, color: 'var(--accent)' }}>
          <div style={{ width: 18, height: 18, border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
          <span style={{ fontSize: 13 }}>Running structured detection rules...</span>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {/* Evidence strength rollup — CLAUDE.md tiers for quick triage. */}
      {strengthRollup && (
        <div style={{
          display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center',
        }}>
          <span style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>
            Evidence strength
          </span>
          {(['confirmed', 'strong', 'moderate', 'weak'] as StrengthTier[]).map((tier) => (
            <span key={tier} className={`badge-strength badge-strength-${tier}`} title={
              tier === 'confirmed' ? 'Prefetch+SRUM, MFT, definitive EIDs' :
              tier === 'strong' ? 'Prefetch Last Run, Sysmon / ScriptBlock' :
              tier === 'moderate' ? 'AmCache, UserAssist, Scheduled Tasks' :
              'Shim Cache, Link Date — NOT execution proof'
            }>
              {strengthRollup[tier] ?? 0} {STRENGTH_LABEL[tier]}
            </span>
          ))}
        </div>
      )}

      {/* Anti-forensics — visible only when rules fired so empty cases stay clean. */}
      {antiForensics && antiForensics.rules_fired > 0 && (
        <div style={{
          marginBottom: 20, padding: '12px 16px', borderRadius: 10,
          background: 'var(--critical-bg)', border: '1px solid var(--critical)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{ fontSize: 15 }}>⚠</span>
            <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--critical)' }}>
              Anti-forensic activity detected — {antiForensics.rules_fired} rule{antiForensics.rules_fired > 1 ? 's' : ''} fired,
              {' '}{antiForensics.total_hits} total hit{antiForensics.total_hits === 1 ? '' : 's'}
            </span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            {(antiForensics.rules || []).filter((r: any) => r.ok && r.count).map((r: any) => (
              <div key={r.rule_name} style={{ padding: '2px 0' }}>
                <span style={{ fontWeight: 600, color: 'var(--text)' }}>{r.rule_name}</span>
                <span style={{ marginLeft: 6, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--critical)' }}>
                  {r.mitre_technique}
                </span>
                <span style={{ marginLeft: 6 }}>· {r.count} hit{r.count === 1 ? '' : 's'}</span>
                <span style={{ marginLeft: 8, color: 'var(--text-dim)' }}>{r.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {afLoading && <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 12 }}>Checking anti-forensics…</div>}
      {afError && <div style={{ fontSize: 11, color: 'var(--critical)', marginBottom: 12 }}>{afError}</div>}

      {/* MITRE Matrix */}
      {mitreData?.narrative?.length > 0 && (
        <>
          <h3 style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 10 }}>
            MITRE ATT&CK Coverage
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8, marginBottom: 24 }}>
            {mitreData.narrative.map((phase: any) => (
              <div key={phase.tactic} className="card" style={{ padding: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 6 }}>
                  {phase.tactic}
                </div>
                {phase.techniques.map((t: any) => (
                  <div key={t.id} style={{ fontSize: 11, padding: '2px 0', borderTop: '1px solid var(--border-light)' }}>
                    <span style={{ color: 'var(--high)', fontWeight: 600, fontFamily: 'var(--mono)', fontSize: 10 }}>{t.id}</span>{' '}
                    {t.name} <span style={{ color: 'var(--text-light)', fontSize: 10 }}>({t.evidence_count})</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </>
      )}

      {/* Findings */}
      {!loading && (
        <>
          <h3 style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 10 }}>
            Findings ({findings.length})
          </h3>
          {findings.map((f, i) => (
            <div key={i} className="card" style={{ marginBottom: 8, padding: 0, overflow: 'hidden' }}>
              <div
                onClick={() => setOpenIdx(openIdx === i ? null : i)}
                style={{
                  padding: '12px 16px', cursor: 'pointer', display: 'flex', alignItems: 'flex-start', gap: 12,
                }}
              >
                <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
                {f.overall_strength && (
                  <span className={`badge-strength badge-strength-${f.overall_strength}`}
                    title="Best evidence strength across this finding's details">
                    {STRENGTH_LABEL[f.overall_strength as StrengthTier]}
                  </span>
                )}
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>
                    {f.rule_name.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{f.description}</div>
                  <div style={{ marginTop: 4 }}>
                    {(f.mitre_techniques || []).map((t: string) => (
                      <span key={t} style={{
                        display: 'inline-block', padding: '0 5px', margin: '2px 3px 0 0',
                        background: 'var(--accent-light)', borderRadius: 3, fontSize: 10, fontFamily: 'var(--mono)',
                      }}>{t}</span>
                    ))}
                  </div>
                </div>
                <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-dim)' }}>
                  {f.matching_count.toLocaleString()}
                </div>
              </div>

              {openIdx === i && (
                <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border-light)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, margin: '10px 0 6px', textTransform: 'uppercase' }}>
                    Detection Evidence
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
                    {Object.entries(f.matched_patterns || {}).sort((a: any, b: any) => b[1] - a[1]).slice(0, 10).map(([p, c]: any) => (
                      <span key={p} style={{
                        padding: '2px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--mono)',
                        background: 'var(--surface2)', border: '1px solid var(--border-light)',
                      }}>
                        {p} <span style={{ color: 'var(--text-light)', fontSize: 10 }}>x{c}</span>
                      </span>
                    ))}
                  </div>
                  {(f.details || []).slice(0, 5).map((d: any, j: number) => (
                    <div key={j} style={{
                      background: 'var(--surface2)', border: '1px solid var(--border-light)',
                      borderRadius: 6, padding: 10, marginTop: 6, fontSize: 11,
                    }}>
                      <div style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'center' }}>
                        <span style={{ fontWeight: 600, color: 'var(--accent)', fontSize: 10 }}>{d.artifact_type}</span>
                        {d.strength && (
                          <span className={`badge-strength badge-strength-${d.strength}`} title={d.strength_reason}>
                            {STRENGTH_LABEL[d.strength as StrengthTier]}
                          </span>
                        )}
                        <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)', fontSize: 10 }}>{d.timestamp}</span>
                      </div>
                      {d.matched_value && (
                        <div style={{
                          fontFamily: 'var(--mono)', fontSize: 11, padding: '4px 6px',
                          background: 'var(--critical-bg)', borderRadius: 4, marginTop: 4, wordBreak: 'break-all',
                        }}>
                          {d.matched_value.slice(0, 300)}
                        </div>
                      )}
                      {d.evidence && (
                        <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>{d.evidence}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          {findings.length === 0 && (
            <div style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>No findings detected.</div>
          )}
        </>
      )}
    </div>
  );
}
