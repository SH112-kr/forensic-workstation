import { useState } from 'react';
import { post } from '../hooks/useApi';

export default function ReportExport() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [showPreview, setShowPreview] = useState(false);

  const generate = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await post('/api/report/generate', {});
      setResult(data);
    } catch (e: any) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  return (
    <div style={{ padding: 40, maxWidth: 600, margin: '0 auto' }}>
      <h2 style={{ fontSize: 18, marginBottom: 8 }}>Report Export</h2>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 13 }}>
        Generate an interactive HTML investigation report with executive summary,
        findings, IOC table, timeline, and MITRE ATT&CK mapping.
      </p>

      <button className="btn btn-primary" onClick={generate} disabled={loading}
        style={{ padding: '12px 32px', fontSize: 14 }}>
        {loading ? 'Generating Report...' : 'Generate Report'}
      </button>

      {loading && (
        <div style={{ marginTop: 20, display: 'flex', alignItems: 'center', gap: 12, color: 'var(--accent)' }}>
          <div style={{ width: 18, height: 18, border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
          <span style={{ fontSize: 13 }}>Running detection + extracting IOCs + building report...</span>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 16, padding: 12, borderRadius: 8, background: 'var(--critical-bg)', color: 'var(--critical)', fontSize: 12 }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 24 }}>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-label">Report Generated</div>
            <div style={{ marginTop: 8, fontSize: 13 }}>
              <div><strong>Path:</strong> <span style={{ fontFamily: 'var(--mono)' }}>{result.path}</span></div>
              <div><strong>Size:</strong> {result.size_kb} KB</div>
              <div><strong>Tabs:</strong> {(result.tabs || []).join(', ')}</div>
            </div>
          </div>
          <a
            href={`/api/report/download?path=${encodeURIComponent(result.path)}`}
            download
            className="btn btn-primary"
            style={{ padding: '10px 24px', fontSize: 13, textDecoration: 'none', display: 'inline-block' }}
          >
            Download Report
          </a>
          <button className="btn" onClick={() => window.open(result.path)} style={{ marginLeft: 8, padding: '10px 24px', fontSize: 13 }}>
            Open in Browser
          </button>
          <button className="btn" onClick={() => setShowPreview(!showPreview)} style={{ marginLeft: 8, padding: '10px 24px', fontSize: 13 }}>
            {showPreview ? 'Close Preview' : 'Preview'}
          </button>

          {showPreview && (
            <div style={{ marginTop: 16, border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              <iframe
                src={`/api/report/download?path=${encodeURIComponent(result.path)}`}
                style={{ width: '100%', height: 500, border: 'none' }}
                title="Report Preview"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
