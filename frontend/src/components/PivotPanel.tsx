import { useState } from 'react';
import { post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

const ENTITY_TYPES: { value: string; label: string; example: string }[] = [
  { value: 'keyword', label: 'Keyword', example: 'e.g. admin, task.vbs' },
  { value: 'hash', label: 'Hash (MD5/SHA1/SHA256)', example: 'exact hash value' },
  { value: 'ip', label: 'IP address', example: 'e.g. 10.0.1.5' },
  { value: 'username', label: 'Username', example: 'e.g. Administrator' },
  { value: 'filename', label: 'Filename', example: 'e.g. powershell.exe' },
  { value: 'path', label: 'Path', example: 'substring of the path' },
];

interface PivotResponse {
  ok: boolean;
  error?: string;
  entity?: { type: string; value: string };
  case_count?: number;
  per_case_counts?: Record<string, number>;
  total?: number;
  first_seen?: { case_id: string; timestamp: string; hit_id?: number } | null;
  last_seen?: { case_id: string; timestamp: string; hit_id?: number } | null;
  hits?: any[];
  warnings?: string[];
}

export default function PivotPanel() {
  const { caseInfo } = useStore();
  const [entityType, setEntityType] = useState('keyword');
  const [entityValue, setEntityValue] = useState('');
  const [limitPerCase, setLimitPerCase] = useState(100);
  const [data, setData] = useState<PivotResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const run = async () => {
    const v = entityValue.trim();
    if (!v) return;
    setLoading(true);
    setError('');
    try {
      const res = await post('/api/cases/pivot', {
        entity_type: entityType,
        entity_value: v,
        limit_per_case: limitPerCase,
      });
      setData(res);
      if (!res.ok) setError(res.error || 'Pivot failed');
    } catch (e: any) {
      setError(e.message || 'Pivot failed');
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  if (!caseInfo) return null;

  const current = ENTITY_TYPES.find((t) => t.value === entityType);

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, margin: '0 0 4px' }}>Pivot Across Cases</h2>
        <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          Search every loaded case for the same entity and merge the results by timestamp.
          Each hit carries its case_id so you can see which case first surfaced the IOC and
          whether it recurs across incidents. Fully offline — no external lookup.
        </div>
      </div>

      {/* Form */}
      <div style={{
        padding: 16, borderRadius: 8, background: 'var(--surface)',
        border: '1px solid var(--border)', marginBottom: 16,
      }}>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
          <select
            value={entityType}
            onChange={(e) => setEntityType(e.target.value)}
            style={{
              padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg)', color: 'var(--text)', fontSize: 12,
            }}
          >
            {ENTITY_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
          <input
            type="text"
            value={entityValue}
            onChange={(e) => setEntityValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
            placeholder={current?.example || 'Entity value…'}
            style={{
              flex: 1, minWidth: 260, padding: '6px 10px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)',
            }}
          />
          <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: 6 }}>
            Limit per case
            <input
              type="number"
              value={limitPerCase}
              min={10}
              max={500}
              onChange={(e) => setLimitPerCase(Math.max(10, Math.min(500, parseInt(e.target.value) || 100)))}
              style={{
                width: 70, padding: '6px 8px', borderRadius: 6,
                border: '1px solid var(--border)', background: 'var(--bg)',
                color: 'var(--text)', fontSize: 12,
              }}
            />
          </label>
          <button className="btn btn-primary btn-sm" onClick={run} disabled={loading || !entityValue.trim()}>
            {loading ? 'Pivoting…' : 'Pivot'}
          </button>
        </div>
        {error && (
          <div style={{ padding: '8px 12px', background: 'rgba(239,68,68,0.08)',
            border: '1px solid rgba(239,68,68,0.25)', borderRadius: 6,
            color: '#ef4444', fontSize: 12 }}>
            {error}
          </div>
        )}
      </div>

      {/* Results */}
      {data && data.ok && (
        <>
          {/* Summary strip */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
            <SummaryPill label="Total hits" value={(data.total ?? 0).toLocaleString()} />
            <SummaryPill label="Cases" value={`${data.case_count ?? 0}`} />
            {data.first_seen && (
              <SummaryPill
                label="First seen"
                value={`${data.first_seen.case_id} · ${data.first_seen.timestamp.slice(0, 19)}`}
              />
            )}
            {data.last_seen && (
              <SummaryPill
                label="Last seen"
                value={`${data.last_seen.case_id} · ${data.last_seen.timestamp.slice(0, 19)}`}
              />
            )}
          </div>

          {/* Per-case breakdown */}
          {data.per_case_counts && Object.keys(data.per_case_counts).length > 0 && (
            <div style={{
              padding: '10px 14px', borderRadius: 8, marginBottom: 12,
              background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12,
            }}>
              <div style={{ fontWeight: 700, marginBottom: 6 }}>By case</div>
              {Object.entries(data.per_case_counts).map(([cid, n]) => (
                <div key={cid} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0' }}>
                  <span style={{ color: '#60a5fa', fontWeight: 600 }}>{cid}</span>
                  <span style={{ fontFamily: 'var(--mono)' }}>{n}</span>
                </div>
              ))}
            </div>
          )}

          {/* Warnings */}
          {data.warnings && data.warnings.length > 0 && (
            <div style={{
              padding: '10px 14px', borderRadius: 8, marginBottom: 12,
              background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
              color: '#f59e0b', fontSize: 12,
            }}>
              {data.warnings.map((w, i) => <div key={i}>• {w}</div>)}
            </div>
          )}

          {/* Hit list */}
          {data.hits && data.hits.length > 0 && (
            <div style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              {data.hits.map((h, i) => (
                <div
                  key={`${h.case_id}-${h.hit_id}-${i}`}
                  style={{
                    padding: '8px 14px', borderBottom: '1px solid var(--border-light)',
                    display: 'grid',
                    gridTemplateColumns: '170px 110px 180px 1fr',
                    gap: 10, fontSize: 12, alignItems: 'start',
                  }}
                >
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' }}>
                    {(h.timestamp || '').slice(0, 23) || '—'}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 600, color: '#60a5fa' }} title={h.source_path}>
                    {h.case_id}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)' }}>
                    {h.artifact_type || '—'}
                  </span>
                  <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {summarize(h)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {data.total === 0 && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
              No hits matched this entity across any loaded case.
            </div>
          )}
        </>
      )}
    </div>
  );
}

function SummaryPill({ label, value }: { label: string; value: string }) {
  return (
    <div style={{
      padding: '8px 14px', borderRadius: 8, background: 'var(--surface)',
      border: '1px solid var(--border)', fontSize: 12, minWidth: 120,
    }}>
      <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
      <div style={{ fontWeight: 700, color: 'var(--text)', marginTop: 2 }}>{value}</div>
    </div>
  );
}

function summarize(hit: any): string {
  if (hit.hash) return `hash=${hit.hash.slice(0, 16)}…`;
  const f = hit.fields || {};
  const parts = Object.entries(f).slice(0, 3).map(([k, v]) => `${k}=${String(v).slice(0, 40)}`);
  return parts.join(' · ') || '—';
}
