import { useEffect, useState } from 'react';
import { get, post } from '../hooks/useApi';
import DependencyStatusPanel from './DependencyStatusPanel';
import { useI18n } from '../i18n/useI18n';

interface ToolStatus {
  key: string;
  name: string;
  description: string;
  required: boolean;
  is_api_key: boolean;
  path: string;
  status: string;
  display_value?: string;
  auto_path?: string;
}

const TRIAGE_LANE_ORDER = ['ingress_access', 'execution_impact', 'persistence_cleanup'] as const;
const TRIAGE_LANE_LABELS: Record<(typeof TRIAGE_LANE_ORDER)[number], string> = {
  ingress_access: 'Ingress / Access',
  execution_impact: 'Execution / Impact',
  persistence_cleanup: 'Persistence / Cleanup',
};
const TRIAGE_LANE_COLORS: Record<string, { bg: string; color: string }> = {
  confirmed: { bg: 'var(--low-bg)', color: 'var(--low)' },
  suggested: { bg: 'var(--medium-bg)', color: 'var(--medium)' },
  unverified: { bg: 'var(--high-bg)', color: 'var(--high)' },
  not_seen: { bg: 'var(--surface2)', color: 'var(--text-dim)' },
};

export default function Settings() {
  const { t } = useI18n();
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [scanDir, setScanDir] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [editValues, setEditValues] = useState<Record<string, string>>({});
  const [message, setMessage] = useState('');

  // Auto Triage state
  const [triageSource, setTriageSource] = useState('');
  const [triageCaseName, setTriageCaseName] = useState('');
  const [triageRunning, setTriageRunning] = useState(false);
  const [triageResult, setTriageResult] = useState<any>(null);
  const [triageProgress, setTriageProgress] = useState<any[]>([]);
  const [triageStats, setTriageStats] = useState<any>(null);
  const [triagePhase, setTriagePhase] = useState('');

  const fetchSettings = async () => {
    try {
      const data = await get('/api/settings');
      setTools(data.tools || []);
      const vals: Record<string, string> = {};
      (data.tools || []).forEach((t: ToolStatus) => {
        vals[t.key] = t.path || '';
      });
      setEditValues(vals);
    } catch (e: any) {
      setMessage('Failed to load settings: ' + e.message);
    }
  };

  useEffect(() => { fetchSettings(); }, []);

  const handleScan = async () => {
    if (!scanDir.trim()) return;
    setScanning(true);
    setScanResult(null);
    setMessage('');
    try {
      const data = await post('/api/settings/scan-and-save', { directory: scanDir.trim() });
      setScanResult(data);
      setTools(data.tools || []);
      const vals: Record<string, string> = {};
      (data.tools || []).forEach((t: ToolStatus) => {
        vals[t.key] = t.path || '';
      });
      setEditValues(vals);
      const count = data.found?.length || 0;
      setMessage(count > 0 ? `${count} tools found and saved` : 'No tools found in this directory');
    } catch (e: any) {
      setMessage('Scan failed: ' + e.message);
    } finally {
      setScanning(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage('');
    try {
      const data = await post('/api/settings/save', { settings: editValues });
      setTools(data.tools || []);
      setMessage('Settings saved');
    } catch (e: any) {
      setMessage('Save failed: ' + e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleTriage = async () => {
    if (!triageSource.trim()) return;
    setTriageRunning(true);
    setTriageResult(null);
    setTriageProgress([]);
    setTriageStats(null);
    setTriagePhase('starting');
    try {
      await post('/api/triage/run', {
        source_drive: triageSource.trim(),
        case_name: triageCaseName.trim() || undefined,
      });
      // Start polling for progress
      const poll = setInterval(async () => {
        try {
          const status = await get('/api/triage/status');
          setTriageProgress(status.progress || []);
          setTriageStats(status.parsed_files || null);
          setTriagePhase(status.phase || '');
          if (!status.running) {
            clearInterval(poll);
            setTriageRunning(false);
            if (status.result) setTriageResult(status.result);
          }
        } catch { /* ignore poll errors */ }
      }, 2000);
    } catch (e: any) {
      setTriageResult({ error: e.message });
      setTriageRunning(false);
    }
  };

  const handleTriageStop = async () => {
    try { await post('/api/triage/stop', {}); } catch { /* ignore */ }
  };

  const statusIcon = (status: string) => {
    switch (status) {
      case 'ok': return { icon: '\u2714', color: '#4ade80' };
      case 'configured': return { icon: '\u2714', color: '#4ade80' };
      case 'auto_detected': return { icon: '\u2714', color: '#60a5fa' };
      case 'path_not_found': return { icon: '\u2716', color: '#ef4444' };
      case 'not_configured': return { icon: '\u2500', color: 'var(--text-dim)' };
      default: return { icon: '?', color: 'var(--text-dim)' };
    }
  };

  const statusLabel = (status: string) => {
    switch (status) {
      case 'ok': return 'Configured';
      case 'configured': return 'Configured';
      case 'auto_detected': return 'Auto-detected';
      case 'path_not_found': return 'Path not found';
      case 'not_configured': return 'Not configured';
      default: return status;
    }
  };

  const sectionStyle: React.CSSProperties = {
    background: 'var(--surface)', border: '1px solid var(--border)',
    borderRadius: 8, padding: 20, marginBottom: 16,
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 12px', borderRadius: 6,
    border: '1px solid var(--border)', background: 'var(--bg)',
    color: 'var(--text)', fontSize: 13, fontFamily: 'monospace',
  };

  const btnStyle: React.CSSProperties = {
    padding: '8px 20px', borderRadius: 6, border: 'none',
    background: 'var(--accent)', color: '#fff', fontSize: 13,
    fontWeight: 600, cursor: 'pointer',
  };

  const btnSecondary: React.CSSProperties = {
    ...btnStyle, background: 'var(--border)', color: 'var(--text)',
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <h2 style={{ margin: '0 0 20px', fontSize: 20, fontWeight: 700 }}>{t('settings.title')}</h2>

      <DependencyStatusPanel />

      {message && (
        <div style={{
          padding: '10px 16px', borderRadius: 6, marginBottom: 16, fontSize: 13,
          background: message.includes('fail') || message.includes('No tools')
            ? 'rgba(239,68,68,0.1)' : 'rgba(74,222,128,0.1)',
          color: message.includes('fail') || message.includes('No tools')
            ? '#ef4444' : '#4ade80',
          border: `1px solid ${message.includes('fail') || message.includes('No tools') ? 'rgba(239,68,68,0.2)' : 'rgba(74,222,128,0.2)'}`,
        }}>
          {message}
        </div>
      )}

      {/* Auto Scan */}
      <div style={sectionStyle}>
        <h3 style={{ margin: '0 0 8px', fontSize: 15, fontWeight: 600 }}>
          {t('settings.toolAutoDetection')}
        </h3>
        <p style={{ margin: '0 0 12px', fontSize: 12, color: 'var(--text-dim)' }}>
          {t('settings.toolAutoDetectionDesc')}
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            style={{ ...inputStyle, flex: 1 }}
            placeholder="e.g. C:\Tools  or  C:\Users\fsec\Desktop\Tools"
            value={scanDir}
            onChange={e => setScanDir(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          <button style={btnStyle} onClick={handleScan} disabled={scanning}>
            {scanning ? t('settings.scanning') : t('settings.scan')}
          </button>
        </div>
        {scanResult?.found?.length > 0 && (
          <div style={{ marginTop: 12 }}>
            {scanResult.found.map((f: any) => (
              <div key={f.key} style={{
                padding: '6px 12px', fontSize: 12, color: '#4ade80',
                display: 'flex', gap: 8,
              }}>
                <span>{'\u2714'}</span>
                <span style={{ fontWeight: 600, minWidth: 80 }}>{f.name}</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text-dim)' }}>{f.path}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Tool Paths */}
      <div style={sectionStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600 }}>{t('settings.toolPaths')}</h3>
          <button style={btnSecondary} onClick={handleSave} disabled={saving}>
            {saving ? t('settings.saving') : t('settings.saveChanges')}
          </button>
        </div>

        {tools.map(tool => {
          const si = statusIcon(tool.status);
          return (
            <div key={tool.key} style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ color: si.color, fontSize: 14 }}>{si.icon}</span>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{tool.name}</span>
                <span style={{
                  fontSize: 10, padding: '2px 8px', borderRadius: 10,
                  background: tool.status === 'ok' || tool.status === 'configured'
                    ? 'rgba(74,222,128,0.15)' : 'rgba(255,255,255,0.05)',
                  color: si.color,
                }}>
                  {statusLabel(tool.status)}
                </span>
              </div>
              <p style={{ margin: '0 0 6px', fontSize: 11, color: 'var(--text-dim)' }}>
                {tool.description}
              </p>
              <input
                style={inputStyle}
                type={tool.is_api_key ? 'password' : 'text'}
                placeholder={tool.is_api_key ? t('settings.apiKeyPlaceholder') : t('settings.pathPlaceholder')}
                value={editValues[tool.key] || ''}
                onChange={e => setEditValues(prev => ({ ...prev, [tool.key]: e.target.value }))}
              />
              {tool.auto_path && (
                <div style={{ fontSize: 11, color: '#60a5fa', marginTop: 4 }}>
                  {t('settings.autoDetected')} {tool.auto_path}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Auto Triage */}
      <div style={sectionStyle}>
        <h3 style={{ margin: '0 0 8px', fontSize: 15, fontWeight: 600 }}>
          {t('settings.triage')}
        </h3>
        <p style={{ margin: '0 0 12px', fontSize: 12, color: 'var(--text-dim)' }}>
          {t('settings.triageDesc')}
        </p>

        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>
              {t('settings.sourceDrive')}
            </label>
            <input
              style={inputStyle}
              placeholder="e.g. G:"
              value={triageSource}
              onChange={e => setTriageSource(e.target.value)}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>
              {t('settings.caseName')}
            </label>
            <input
              style={inputStyle}
              placeholder="e.g. incident_2026"
              value={triageCaseName}
              onChange={e => setTriageCaseName(e.target.value)}
            />
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            style={{
              ...btnStyle,
              opacity: triageRunning || !triageSource.trim() ? 0.5 : 1,
              background: '#f59e0b',
            }}
            onClick={handleTriage}
            disabled={triageRunning || !triageSource.trim()}
          >
            {triageRunning ? t('settings.running') : t('settings.runTriage')}
          </button>
          {triageRunning && (
            <button style={{ ...btnSecondary }} onClick={handleTriageStop}>
              {t('settings.stopTriage')}
            </button>
          )}
        </div>

        {/* Live Progress */}
        {triageRunning && (
          <div style={{
            marginTop: 16, padding: 16, borderRadius: 6,
            background: 'rgba(96,165,250,0.05)', border: '1px solid rgba(96,165,250,0.2)',
            fontSize: 12,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <div style={{
                width: 16, height: 16, border: '2px solid var(--border)',
                borderTopColor: '#60a5fa', borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }} />
              <span style={{ fontWeight: 600, color: '#60a5fa' }}>
                {triagePhase.replace(/_/g, ' ').replace('kape ', 'KAPE ')}
              </span>
              {triageStats && (
                <span style={{ color: 'var(--text-dim)', marginLeft: 'auto' }}>
                  {t('settings.csvFiles', { count: triageStats.files, size: triageStats.size_mb })}
                </span>
              )}
            </div>

            {/* Progress log */}
            <div style={{
              maxHeight: 200, overflowY: 'auto', fontFamily: 'monospace', fontSize: 11,
              background: 'rgba(0,0,0,0.2)', borderRadius: 4, padding: 8,
            }}>
              {triageProgress.map((p: any, i: number) => (
                <div key={i} style={{
                  padding: '2px 0',
                  color: p.msg.includes('Warning') || p.msg.includes('Error') ? '#ef4444' :
                    p.msg.includes('Complete') || p.msg.includes('complete') ? '#4ade80' :
                    'var(--text-dim)',
                }}>
                  {p.msg}
                </div>
              ))}
            </div>

            {/* Parsed folders breakdown */}
            {triageStats?.folders && Object.keys(triageStats.folders).length > 0 && (
              <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {Object.entries(triageStats.folders).map(([folder, count]: [string, any]) => (
                  <span key={folder} style={{
                    fontSize: 10, padding: '2px 8px', borderRadius: 4,
                    background: 'rgba(255,255,255,0.05)', color: 'var(--text-dim)',
                  }}>
                    {folder}: {count}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {triageResult && (
          <div style={{
            marginTop: 16, padding: 16, borderRadius: 6,
            background: triageResult.error ? 'rgba(239,68,68,0.1)' : 'rgba(74,222,128,0.05)',
            border: `1px solid ${triageResult.error ? 'rgba(239,68,68,0.2)' : 'rgba(74,222,128,0.2)'}`,
            fontSize: 12,
          }}>
            {triageResult.error ? (
              <div style={{ color: '#ef4444' }}>{t('settings.error')} {triageResult.error}</div>
            ) : (
              <>
                <div style={{ fontWeight: 700, marginBottom: 8, color: '#4ade80' }}>
                  {t('settings.triageComplete', { seconds: triageResult.total_duration_s })}
                </div>
                {triageResult.lane_state_board?.error ? (
                  <div style={{
                    marginBottom: 12,
                    padding: '10px 12px',
                    borderRadius: 6,
                    background: 'var(--surface)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-dim)',
                  }}>
                    <strong style={{ color: 'var(--text)' }}>{t('settings.laneStateUnavailable')}</strong> {triageResult.lane_state_board.error}
                  </div>
                ) : triageResult.lane_state_board && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                      <span style={{ fontWeight: 600 }}>{t('settings.laneState')}</span>
                      {triageResult.lane_state_board.allow_strong_conclusion === false && (
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: 999,
                          fontSize: 10,
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          background: 'var(--high-bg)',
                          color: 'var(--high)',
                        }}>
                          incomplete
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {TRIAGE_LANE_ORDER.map((lane) => {
                        const entry = triageResult.lane_state_board?.[lane];
                        const state = entry?.state || 'not_seen';
                        const color = TRIAGE_LANE_COLORS[state] || TRIAGE_LANE_COLORS.not_seen;
                        return (
                          <div key={lane} style={{
                            padding: '8px 10px',
                            borderRadius: 8,
                            background: color.bg,
                            color: color.color,
                            fontSize: 11,
                            minWidth: 130,
                          }}>
                            <div style={{ fontWeight: 700, marginBottom: 4 }}>{TRIAGE_LANE_LABELS[lane]}</div>
                            <div>{String(state).toUpperCase()}</div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 16px' }}>
                  <span>{t('settings.totalArtifacts')}</span>
                  <span style={{ fontWeight: 600 }}>{triageResult.total_hits?.toLocaleString()}</span>
                  <span>{t('settings.suspiciousFindings')}</span>
                  <span style={{ fontWeight: 600, color: triageResult.summary?.suspicious_findings > 0 ? '#ef4444' : 'inherit' }}>
                    {triageResult.summary?.suspicious_findings}
                  </span>
                  <span>{t('settings.iocsExtracted')}</span>
                  <span style={{ fontWeight: 600 }}>{triageResult.summary?.iocs_extracted}</span>
                  <span>{t('settings.timelineEvents')}</span>
                  <span style={{ fontWeight: 600 }}>{triageResult.summary?.timeline_events?.toLocaleString()}</span>
                  <span>{t('settings.mitreTechniques')}</span>
                  <span style={{ fontWeight: 600 }}>{triageResult.summary?.mitre_techniques}</span>
                  <span>{t('settings.output')}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{triageResult.output_dir}</span>
                </div>
                {triageResult.autonomous_assessment && !triageResult.autonomous_assessment.error && (
                  <div style={{
                    marginTop: 12,
                    padding: 10,
                    borderRadius: 8,
                    background: triageResult.autonomous_assessment.investigation_incomplete ? 'rgba(245,158,11,0.12)' : 'rgba(59,130,246,0.12)',
                    border: '1px solid var(--border)',
                    fontSize: 12,
                  }}>
                    <div style={{ fontWeight: 700, marginBottom: 4 }}>
                      {t('settings.autonomousDecision')} {String(triageResult.autonomous_assessment.decision || 'unknown').replace(/_/g, ' ')}
                    </div>
                    <div style={{ color: 'var(--text-dim)' }}>
                      {String(triageResult.autonomous_assessment.verdict || 'unknown').replace(/_/g, ' ')}
                      {' '}| {t('settings.confidence')} {triageResult.autonomous_assessment.confidence || 'unknown'}
                    </div>
                  </div>
                )}
                {(triageResult.alert_summary?.key_findings || triageResult.top_findings || []).length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>{t('settings.keyFindings')}</div>
                    {(triageResult.alert_summary?.key_findings || triageResult.top_findings || []).map((f: any, i: number) => {
                      const tier = f.priority_tier || f.severity || 'info';
                      const label = f.rule_name || f.rule || 'finding';
                      const count = f.matching_count ?? f.count ?? 0;
                      return (
                      <div key={i} style={{ display: 'flex', gap: 8, padding: '2px 0' }}>
                        <span style={{
                          fontSize: 10, padding: '1px 6px', borderRadius: 4,
                          background: tier === 'critical' ? 'rgba(239,68,68,0.2)' :
                            tier === 'high' ? 'rgba(245,158,11,0.2)' : 'rgba(255,255,255,0.05)',
                          color: tier === 'critical' ? '#ef4444' :
                            tier === 'high' ? '#f59e0b' : 'var(--text-dim)',
                        }}>
                          {tier}
                        </span>
                        <span>{label}</span>
                        <span style={{ color: 'var(--text-dim)' }}>({count})</span>
                      </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
