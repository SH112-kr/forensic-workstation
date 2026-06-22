import { useEffect, useRef, useState } from 'react';
import { post } from '../hooks/useApi';
import IOCGraph from './IOCGraph';

export default function IOCTable() {
  const [iocs, setIocs] = useState<any[]>([]);
  const [byType, setByType] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [excludePrivate, setExcludePrivate] = useState(true);
  const [excludeKnownGood, setExcludeKnownGood] = useState(true);
  const [sortField, setSortField] = useState('count');
  const [sortAsc, setSortAsc] = useState(false);
  const didAutoExtract = useRef(false);

  const extract = async () => {
    setLoading(true);
    try {
      const data = await post('/api/ioc/extract', {
        ioc_types: '', exclude_private_ips: excludePrivate, exclude_known_good: excludeKnownGood,
      });
      setIocs(data.iocs || []);
      setByType(data.by_type || {});
      setTotal(data.total_iocs || 0);
    } catch {} finally { setLoading(false); }
  };

  // Auto-extract hash only (fast) on mount, full extract on button click
  useEffect(() => {
    if (!didAutoExtract.current) {
      didAutoExtract.current = true;
      extractFast();
    }
  }, []);

  const extractFast = async () => {
    setLoading(true);
    try {
      const data = await post('/api/ioc/extract', {
        ioc_types: 'hash', exclude_private_ips: true, exclude_known_good: true,
      });
      setIocs(data.iocs || []);
      setByType(data.by_type || {});
      setTotal(data.total_iocs || 0);
    } catch {} finally { setLoading(false); }
  };

  const sort = (field: string) => {
    if (sortField === field) setSortAsc(!sortAsc);
    else { setSortField(field); setSortAsc(true); }
  };

  let filtered = iocs;
  if (filter) filtered = filtered.filter(i => i.value.toLowerCase().includes(filter.toLowerCase()));
  if (typeFilter) filtered = filtered.filter(i => i.ioc_type === typeFilter);
  filtered = [...filtered].sort((a, b) => {
    const av = a[sortField], bv = b[sortField];
    const cmp = typeof av === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return sortAsc ? cmp : -cmp;
  });

  const typeLabels: Record<string, string> = {
    ipv4: 'IP', md5: 'MD5', sha1: 'SHA1', sha256: 'SHA256',
    domain: 'Domain', url: 'URL', email: 'Email',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Controls */}
      <div style={{
        padding: '10px 16px', display: 'flex', gap: 8, borderBottom: '1px solid var(--border)',
        background: 'var(--surface)', alignItems: 'center', flexWrap: 'wrap',
      }}>
        <button className="btn btn-primary btn-sm" onClick={extract} disabled={loading}>
          {loading ? 'Extracting...' : 'Extract IOCs'}
        </button>
        <label style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-dim)' }}>
          <input type="checkbox" checked={excludePrivate} onChange={e => setExcludePrivate(e.target.checked)} />
          Exclude private IPs
        </label>
        <label style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-dim)' }}>
          <input type="checkbox" checked={excludeKnownGood} onChange={e => setExcludeKnownGood(e.target.checked)} />
          Exclude known good
        </label>
        <div style={{ flex: 1 }} />
        <input type="text" placeholder="Filter IOCs..." value={filter} onChange={e => setFilter(e.target.value)}
          style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, width: 200 }} />
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          style={{ padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12 }}>
          <option value="">All Types</option>
          {Object.keys(byType).map(t => <option key={t} value={t}>{typeLabels[t] || t} ({byType[t]})</option>)}
        </select>
      </div>

      {/* Stats bar */}
      {total > 0 && (
        <div style={{
          padding: '8px 16px', display: 'flex', gap: 12, borderBottom: '1px solid var(--border-light)',
          fontSize: 11, color: 'var(--text-dim)',
        }}>
          <span>Total: <strong>{total}</strong></span>
          {Object.entries(byType).map(([t, c]) => (
            <span key={t}><span className="badge badge-info">{typeLabels[t] || t}</span> {c}</span>
          ))}
          <span>Showing: {filtered.length}</span>
        </div>
      )}

      <IOCGraph />

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {iocs.length === 0 && !loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            No IOCs found. Click "Extract IOCs" to re-scan.
          </div>
        )}
        {loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            <div style={{ width: 20, height: 20, border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 12px' }} />
            Extracting IOCs...
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}
        {iocs.length > 0 && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr>
                <th onClick={() => sort('ioc_type')} style={thStyle}>Type {sortField === 'ioc_type' ? (sortAsc ? '\u25B2' : '\u25BC') : ''}</th>
                <th onClick={() => sort('value')} style={thStyle}>Value {sortField === 'value' ? (sortAsc ? '\u25B2' : '\u25BC') : ''}</th>
                <th onClick={() => sort('count')} style={{ ...thStyle, width: 70 }}>Count {sortField === 'count' ? (sortAsc ? '\u25B2' : '\u25BC') : ''}</th>
                <th style={thStyle}>Sources</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 500).map((ioc, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={tdStyle}><span className="badge badge-info">{ioc.ioc_type}</span></td>
                  <td style={{ ...tdStyle, fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>{ioc.value}</td>
                  <td style={{ ...tdStyle, textAlign: 'right' }}>{ioc.count}</td>
                  <td style={{ ...tdStyle, color: 'var(--text-dim)', fontSize: 11 }}>{(ioc.source_artifact_types || []).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11,
  textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)',
  borderBottom: '2px solid var(--border)', cursor: 'pointer', position: 'sticky', top: 0,
};
const tdStyle: React.CSSProperties = { padding: '6px 12px' };
