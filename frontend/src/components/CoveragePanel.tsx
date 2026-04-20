import { useEffect, useState } from 'react';
import { get } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

interface CoverageItem {
  artifact_type: string;
  status: 'searched' | 'available_not_loaded' | 'structurally_unavailable';
  record_count: number;
  cases: string[];
  reason: string | null;
}

interface CoverageResponse {
  ok: boolean;
  case_context: {
    case_format: string;
    kinds: string[];
    cases: string[];
    has_mfdb: boolean;
    has_kape: boolean;
  };
  coverage: CoverageItem[];
  summary: {
    total_reported: number;
    searched: number;
    available_not_loaded: number;
    structurally_unavailable: number;
    axiom_only_family_count: number;
  };
  notes: string[];
}

const STATUS_META: Record<string, { label: string; color: string; bg: string; hint: string }> = {
  searched: {
    label: 'Searched',
    color: '#4ade80',
    bg: 'rgba(74,222,128,0.08)',
    hint: 'These families have records in at least one loaded case and return results from queries.',
  },
  available_not_loaded: {
    label: 'Available, no records',
    color: '#f59e0b',
    bg: 'rgba(245,158,11,0.08)',
    hint: 'Supported by the current case format but parsed zero records. Absence may be real, or a parser/collection gap — verify raw evidence before concluding "no activity".',
  },
  structurally_unavailable: {
    label: 'Structurally unavailable',
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.08)',
    hint: 'The current case format cannot expose these families at all (e.g. AXIOM-only carving on a KAPE-only case). Their absence is not evidence of absence in reality.',
  },
};

export default function CoveragePanel() {
  const { caseInfo } = useStore();
  const [data, setData] = useState<CoverageResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    searched: false,
    available_not_loaded: true,
    structurally_unavailable: true,
  });

  useEffect(() => {
    if (!caseInfo) return;
    setLoading(true);
    setError('');
    get('/api/cases/coverage')
      .then((d) => setData(d))
      .catch((e) => setError(e.message || 'Failed to load coverage'))
      .finally(() => setLoading(false));
  }, [caseInfo]);

  if (!caseInfo) return null;

  const toggle = (key: string) => setExpanded((p) => ({ ...p, [key]: !p[key] }));

  const groups: Array<CoverageItem['status']> = [
    'searched',
    'available_not_loaded',
    'structurally_unavailable',
  ];

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, margin: '0 0 4px' }}>Evidence Coverage</h2>
        <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          What the loaded cases can and cannot answer. Use this view whenever a search returns
          zero hits — "no records" and "source cannot exist under this format" are different facts.
        </div>
      </div>

      {loading && (
        <div style={{ padding: 24, color: 'var(--text-dim)', fontSize: 12 }}>Loading coverage…</div>
      )}

      {error && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: 8,
            background: 'rgba(239,68,68,0.08)',
            border: '1px solid rgba(239,68,68,0.25)',
            color: '#ef4444',
            fontSize: 12,
            marginBottom: 12,
          }}
        >
          {error}
        </div>
      )}

      {data && (
        <>
          {/* Case-format context */}
          <div
            style={{
              padding: '12px 16px',
              borderRadius: 8,
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              marginBottom: 12,
              fontSize: 12,
            }}
          >
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontWeight: 700, color: 'var(--text)' }}>Case format:</span>
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'rgba(96,165,250,0.15)',
                  color: '#60a5fa',
                  textTransform: 'uppercase',
                }}
              >
                {data.case_context.case_format}
              </span>
              <span style={{ color: 'var(--text-dim)' }}>
                {data.case_context.cases.length} case
                {data.case_context.cases.length === 1 ? '' : 's'} loaded
              </span>
            </div>
            {data.case_context.cases.length > 0 && (
              <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>
                {data.case_context.cases.join(', ')}
              </div>
            )}
          </div>

          {/* Summary pills */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            {groups.map((g) => {
              const meta = STATUS_META[g];
              const count =
                g === 'searched'
                  ? data.summary.searched
                  : g === 'available_not_loaded'
                  ? data.summary.available_not_loaded
                  : data.summary.structurally_unavailable;
              return (
                <div
                  key={g}
                  style={{
                    padding: '8px 14px',
                    borderRadius: 6,
                    background: meta.bg,
                    border: `1px solid ${meta.color}33`,
                    fontSize: 12,
                  }}
                >
                  <div style={{ fontWeight: 700, color: meta.color, fontSize: 18 }}>{count}</div>
                  <div style={{ color: 'var(--text-dim)' }}>{meta.label}</div>
                </div>
              );
            })}
          </div>

          {/* Group sections */}
          {groups.map((g) => {
            const meta = STATUS_META[g];
            const items = data.coverage.filter((c) => c.status === g);
            if (items.length === 0) return null;
            const isExpanded = !!expanded[g];
            return (
              <div
                key={g}
                style={{
                  marginBottom: 10,
                  border: '1px solid var(--border)',
                  borderRadius: 8,
                  overflow: 'hidden',
                }}
              >
                <div
                  onClick={() => toggle(g)}
                  style={{
                    padding: '10px 14px',
                    cursor: 'pointer',
                    background: meta.bg,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    userSelect: 'none',
                  }}
                >
                  <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                    {isExpanded ? '▾' : '▸'}
                  </span>
                  <span style={{ fontWeight: 700, color: meta.color }}>{meta.label}</span>
                  <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>
                    ({items.length})
                  </span>
                  <div style={{ flex: 1 }} />
                </div>
                {isExpanded && (
                  <>
                    <div
                      style={{
                        padding: '8px 14px',
                        background: 'var(--bg)',
                        fontSize: 11,
                        color: 'var(--text-dim)',
                        borderBottom: '1px solid var(--border)',
                      }}
                    >
                      {meta.hint}
                    </div>
                    {items.map((it) => (
                      <div
                        key={it.artifact_type}
                        style={{
                          padding: '10px 14px',
                          borderBottom: '1px solid var(--border-light)',
                          fontSize: 12,
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontWeight: 600 }}>{it.artifact_type}</span>
                          {it.record_count > 0 && (
                            <span
                              style={{
                                fontSize: 11,
                                color: 'var(--text-dim)',
                                fontFamily: 'var(--mono)',
                              }}
                            >
                              {it.record_count.toLocaleString()} records
                            </span>
                          )}
                          {it.cases.length > 0 && (
                            <span
                              style={{
                                fontSize: 10,
                                padding: '1px 6px',
                                borderRadius: 3,
                                background: 'rgba(96,165,250,0.12)',
                                color: '#60a5fa',
                              }}
                            >
                              {it.cases.join(', ')}
                            </span>
                          )}
                        </div>
                        {it.reason && (
                          <div
                            style={{
                              marginTop: 4,
                              color: 'var(--text-dim)',
                              fontSize: 11,
                            }}
                          >
                            {it.reason}
                          </div>
                        )}
                      </div>
                    ))}
                  </>
                )}
              </div>
            );
          })}

          {/* Notes */}
          {data.notes.length > 0 && (
            <div
              style={{
                marginTop: 14,
                padding: '10px 14px',
                borderRadius: 8,
                background: 'rgba(96,165,250,0.06)',
                border: '1px solid rgba(96,165,250,0.2)',
                fontSize: 12,
                color: 'var(--text-dim)',
              }}
            >
              {data.notes.map((n, i) => (
                <div key={i} style={{ marginBottom: i < data.notes.length - 1 ? 4 : 0 }}>
                  • {n}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
