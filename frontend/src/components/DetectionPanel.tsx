import { useEffect, useState } from 'react';
import { get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

type StrengthTier = 'confirmed' | 'strong' | 'moderate' | 'weak';
type DetectionTab = 'key' | 'axes' | 'legacy';

const STRENGTH_LABEL: Record<StrengthTier, string> = {
  confirmed: 'Confirmed',
  strong: 'Strong',
  moderate: 'Moderate',
  weak: 'Weak',
};
const TAB_LABELS: Record<DetectionTab, string> = {
  key: 'Key findings (balanced)',
  axes: 'Candidate axes',
  legacy: 'All (legacy)',
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

function renderSignalLabel(signal: any) {
  if (!signal || typeof signal !== 'object') return String(signal || 'signal');
  return signal.rule_name || signal.artifact_type || signal.kind || 'signal';
}

export default function DetectionPanel() {
  const { detection, mitre, laneStateBoard, setDetection, setLastAction } = useStore();
  const [findings, setFindings] = useState<any[]>(detection?.findings || []);
  const [strengthRollup, setStrengthRollup] = useState<Record<StrengthTier, number> | null>(detection?.strength_rollup || null);
  const [minStrength, setMinStrength] = useState<StrengthTier | ''>('');
  const [mitreData, setMitreData] = useState<any>(mitre);
  const [loading, setLoading] = useState(false);
  const [openRow, setOpenRow] = useState<string | null>(null);
  const [antiForensics, setAntiForensics] = useState<any>(null);
  const [afLoading, setAfLoading] = useState(false);
  const [afError, setAfError] = useState('');
  const [activeTab, setActiveTab] = useState<DetectionTab>('key');

  useEffect(() => {
    if (detection?.findings) {
      setFindings(detection.findings);
      setMitreData(mitre);
      setStrengthRollup(detection.strength_rollup || null);
    } else {
      runDetection();
    }
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
    } finally {
      setLoading(false);
    }
  };

  const loadAntiForensics = async () => {
    setAfLoading(true);
    setAfError('');
    try {
      const payload = await get('/api/detection/anti-forensics');
      setAntiForensics(payload);
    } catch (e: any) {
      setAfError(e?.message || 'Failed to run anti-forensics detection');
    } finally {
      setAfLoading(false);
    }
  };

  const balanceWarnings = detection?.alert_summary?.balance?.warnings || [];
  const keyFindings = detection?.alert_summary?.key_findings || findings.slice(0, 10);
  const candidateAxes = detection?.candidate_axes?.candidate_axes || [];
  const laneBoard = detection?.lane_state_board || laneStateBoard || null;
  const laneError = laneBoard?.error || '';
  const autonomousAssessment = detection?.autonomous_assessment || null;

  const passesStrength = (finding: any) => {
    if (!minStrength) return true;
    const order = { confirmed: 4, strong: 3, moderate: 2, weak: 1 } as const;
    const actual = (order as any)[finding?.overall_strength || 'moderate'] || 2;
    const required = (order as any)[minStrength] || 1;
    return actual >= required;
  };

  const filteredKeyFindings = keyFindings.filter(passesStrength);
  const filteredLegacyFindings = findings.filter(passesStrength);

  const renderFindingRows = (rows: any[], scope: DetectionTab) => rows.map((finding: any, index: number) => {
    const rowId = `${scope}-${index}`;
    return (
      <div key={rowId} className="card" style={{ marginBottom: 8, padding: 0, overflow: 'hidden' }}>
        <div
          onClick={() => setOpenRow(openRow === rowId ? null : rowId)}
          style={{
            padding: '12px 16px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'flex-start',
            gap: 12,
          }}
        >
          <span className={`badge badge-${findingTier(finding)}`}>{String(findingTier(finding)).toUpperCase()}</span>
          {finding.overall_strength && (
            <span className={`badge-strength badge-strength-${finding.overall_strength}`} title="Best evidence strength across this finding's details">
              {STRENGTH_LABEL[finding.overall_strength as StrengthTier] || finding.overall_strength}
            </span>
          )}
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 13 }}>
              {formatFindingTitle(finding.rule_name)}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{findingText(finding)}</div>
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

        {openRow === rowId && (
          <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border-light)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, margin: '10px 0 6px', textTransform: 'uppercase' }}>
              Detection evidence
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
              {Object.entries(finding.matched_patterns || {}).sort((a: any, b: any) => b[1] - a[1]).slice(0, 10).map(([pattern, count]: any) => (
                <span
                  key={pattern}
                  style={{
                    padding: '2px 8px',
                    borderRadius: 4,
                    fontSize: 11,
                    fontFamily: 'var(--mono)',
                    background: 'var(--surface2)',
                    border: '1px solid var(--border-light)',
                  }}
                >
                  {pattern} <span style={{ color: 'var(--text-light)', fontSize: 10 }}>x{count}</span>
                </span>
              ))}
            </div>
            {(finding.details || []).slice(0, 5).map((detail: any, detailIndex: number) => (
              <div
                key={detailIndex}
                style={{
                  background: 'var(--surface2)',
                  border: '1px solid var(--border-light)',
                  borderRadius: 6,
                  padding: 10,
                  marginTop: 6,
                  fontSize: 11,
                }}
              >
                <div style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 600, color: 'var(--accent)', fontSize: 10 }}>{detail.artifact_type}</span>
                  {detail.strength && (
                    <span className={`badge-strength badge-strength-${detail.strength}`} title={detail.strength_reason}>
                      {STRENGTH_LABEL[detail.strength as StrengthTier] || detail.strength}
                    </span>
                  )}
                  <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)', fontSize: 10 }}>{detail.timestamp}</span>
                </div>
                {detail.matched_value && (
                  <div
                    style={{
                      fontFamily: 'var(--mono)',
                      fontSize: 11,
                      padding: '4px 6px',
                      background: 'var(--critical-bg)',
                      borderRadius: 4,
                      marginTop: 4,
                      wordBreak: 'break-all',
                    }}
                  >
                    {String(detail.matched_value).slice(0, 300)}
                  </div>
                )}
                {detail.evidence && (
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>{detail.evidence}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  });

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
          <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
        </div>
      )}

      {laneError && (
        <div style={{
          marginBottom: 16,
          padding: '12px 16px',
          borderRadius: 10,
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          fontSize: 12,
          color: 'var(--text-dim)',
        }}>
          <strong style={{ color: 'var(--text)' }}>Lane state unavailable.</strong> {laneError}
        </div>
      )}

      {strengthRollup && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>
            Evidence strength
          </span>
          {(['confirmed', 'strong', 'moderate', 'weak'] as StrengthTier[]).map((tier) => (
            <span
              key={tier}
              className={`badge-strength badge-strength-${tier}`}
              title={
                tier === 'confirmed' ? 'Prefetch+SRUM, MFT, definitive EIDs' :
                tier === 'strong' ? 'Prefetch Last Run, Sysmon / ScriptBlock' :
                tier === 'moderate' ? 'AmCache, UserAssist, Scheduled Tasks' :
                'Shim Cache and link-date artifacts are not execution proof'
              }
            >
              {strengthRollup[tier] ?? 0} {STRENGTH_LABEL[tier]}
            </span>
          ))}
        </div>
      )}

      {autonomousAssessment && !autonomousAssessment.error && (
        <div style={{
          marginBottom: 16,
          padding: '12px 16px',
          borderRadius: 10,
          background: autonomousAssessment.investigation_incomplete ? 'var(--high-bg)' : 'var(--accent-light)',
          border: `1px solid ${autonomousAssessment.investigation_incomplete ? 'var(--high)' : 'var(--accent)'}`,
          fontSize: 12,
        }}>
          <div style={{ fontWeight: 700, color: autonomousAssessment.investigation_incomplete ? 'var(--high)' : 'var(--accent)', marginBottom: 4 }}>
            Autonomous assessment: {String(autonomousAssessment.verdict || 'unknown').replace(/_/g, ' ')}
          </div>
          <div style={{ color: 'var(--text-dim)' }}>
            Decision: {String(autonomousAssessment.decision || 'unknown').replace(/_/g, ' ')}
            {' '}| confidence: {autonomousAssessment.confidence || 'unknown'}
            {autonomousAssessment.blocked_lanes?.length ? ` | blocked lanes: ${autonomousAssessment.blocked_lanes.join(', ')}` : ''}
          </div>
          {(autonomousAssessment.basis || []).length > 0 && (
            <div style={{ color: 'var(--text-dim)', marginTop: 6 }}>
              Basis: {(autonomousAssessment.basis || []).slice(0, 3).join('; ')}
            </div>
          )}
        </div>
      )}

      {antiForensics && antiForensics.rules_fired > 0 && (
        <div style={{
          marginBottom: 20,
          padding: '12px 16px',
          borderRadius: 10,
          background: 'var(--critical-bg)',
          border: '1px solid var(--critical)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--critical)' }}>
              Anti-forensic activity detected: {antiForensics.rules_fired} rule{antiForensics.rules_fired > 1 ? 's' : ''} fired, {antiForensics.total_hits} total hit{antiForensics.total_hits === 1 ? '' : 's'}
            </span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            {(antiForensics.rules || []).filter((rule: any) => rule.ok && rule.count).map((rule: any) => (
              <div key={rule.rule_name} style={{ padding: '2px 0' }}>
                <span style={{ fontWeight: 600, color: 'var(--text)' }}>{rule.rule_name}</span>
                <span style={{ marginLeft: 6, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--critical)' }}>
                  {rule.mitre_technique}
                </span>
                <span style={{ marginLeft: 6 }}>| {rule.count} hit{rule.count === 1 ? '' : 's'}</span>
                <span style={{ marginLeft: 8, color: 'var(--text-dim)' }}>{rule.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {afLoading && <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 12 }}>Checking anti-forensics...</div>}
      {afError && <div style={{ fontSize: 11, color: 'var(--critical)', marginBottom: 12 }}>{afError}</div>}

      {balanceWarnings.length > 0 && (
        <div style={{
          marginBottom: 16,
          padding: '12px 16px',
          borderRadius: 10,
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          fontSize: 12,
        }}>
          <div style={{ fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
            Balance warning
          </div>
          <div style={{ color: 'var(--text-dim)' }}>{balanceWarnings[0]}</div>
        </div>
      )}

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
                {phase.techniques.map((technique: any) => (
                  <div key={technique.id} style={{ fontSize: 11, padding: '2px 0', borderTop: '1px solid var(--border-light)' }}>
                    <span style={{ color: 'var(--high)', fontWeight: 600, fontFamily: 'var(--mono)', fontSize: 10 }}>{technique.id}</span>{' '}
                    {technique.name} <span style={{ color: 'var(--text-light)', fontSize: 10 }}>({technique.evidence_count})</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        {(Object.keys(TAB_LABELS) as DetectionTab[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '8px 12px',
              borderRadius: 8,
              border: `1px solid ${activeTab === tab ? 'var(--accent)' : 'var(--border)'}`,
              background: activeTab === tab ? 'var(--accent-light)' : 'var(--surface)',
              color: activeTab === tab ? 'var(--accent)' : 'var(--text)',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            {TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      {activeTab !== 'axes' && (
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 10 }}>
          <h3 style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', margin: 0 }}>
            {activeTab === 'key'
              ? `Key findings (${filteredKeyFindings.length}/${keyFindings.length})`
              : `All findings (${filteredLegacyFindings.length}/${findings.length})`}
          </h3>
          <div style={{ flex: 1 }} />
          <label className="label" style={{ margin: 0 }}>Min strength</label>
          <select
            value={minStrength}
            onChange={(e) => setMinStrength(e.target.value as StrengthTier | '')}
            className="input input-sm"
            style={{ width: 140 }}
          >
            <option value="">Any</option>
            <option value="weak">Weak or above</option>
            <option value="moderate">Moderate or above</option>
            <option value="strong">Strong or above</option>
            <option value="confirmed">Confirmed only</option>
          </select>
        </div>
      )}

      {activeTab === 'key' && (
        <>
          {filteredKeyFindings.length > 0 && renderFindingRows(filteredKeyFindings.slice(0, 10), 'key')}
          {!loading && filteredKeyFindings.length === 0 && (
            <div style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>
              Balanced prioritization returned 0 rows. Review All (legacy) for the full list.
            </div>
          )}
        </>
      )}

      {activeTab === 'axes' && (
        <>
          {candidateAxes.length > 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
              {candidateAxes.map((axis: any, index: number) => (
                <div key={`${axis.axis_id || axis.label || 'axis'}-${index}`} className="card" style={{ padding: 14 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>
                    {axis.label || axis.axis_id || 'Candidate axis'}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
                    Verification: {axis.verification?.status || 'unknown'}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
                    Supporting signals:
                    <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {(axis.supporting_signals || []).slice(0, 3).map((signal: any, signalIndex: number) => (
                        <span
                          key={signalIndex}
                          style={{
                            padding: '2px 8px',
                            borderRadius: 999,
                            fontSize: 10,
                            background: 'var(--surface2)',
                            border: '1px solid var(--border-light)',
                            color: 'var(--text-dim)',
                          }}
                        >
                          {renderSignalLabel(signal)}
                          {typeof signal?.count === 'number' ? ` (${signal.count})` : ''}
                        </span>
                      ))}
                    </div>
                  </div>
                  {(axis.unknowns || []).length > 0 && (
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                      Unknowns:
                      <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                        {(axis.unknowns || []).slice(0, 3).map((unknown: string, unknownIndex: number) => (
                          <li key={unknownIndex}>{unknown}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>
              No candidate axes surfaced from the current evidence set.
            </div>
          )}
        </>
      )}

      {activeTab === 'legacy' && (
        <>
          {filteredLegacyFindings.length > 0 && renderFindingRows(filteredLegacyFindings, 'legacy')}
          {!loading && filteredLegacyFindings.length === 0 && (
            <div style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>No findings detected.</div>
          )}
        </>
      )}
    </div>
  );
}
