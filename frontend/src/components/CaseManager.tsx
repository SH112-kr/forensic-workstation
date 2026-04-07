import { useEffect, useState } from 'react';
import { get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

interface EvidenceItem {
  type: string;
  path: string;
  label: string;
  size?: string;
  loaded?: boolean;
  status?: string;
}

interface SavedProject {
  name: string;
  description: string;
  hostname: string;
  incident_date: string;
  evidence_count: number;
  updated: string;
  path: string;
}

// ── Recent Cases (localStorage) ──

interface RecentCase {
  name: string;
  path: string;
  source: 'project' | 'axiom' | 'kape';
  totalHits?: number;
  openedAt: string; // ISO
}

const RECENT_KEY = 'fw_recent_cases';
const MAX_RECENT = 8;

function loadRecent(): RecentCase[] {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); } catch { return []; }
}

function saveRecent(entry: RecentCase) {
  const list = loadRecent().filter(r => r.path !== entry.path);
  list.unshift({ ...entry, openedAt: new Date().toISOString() });
  localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, MAX_RECENT)));
}

function removeRecent(path: string) {
  const list = loadRecent().filter(r => r.path !== path);
  localStorage.setItem(RECENT_KEY, JSON.stringify(list));
}

const TYPE_ICONS: Record<string, string> = {
  axiom: 'DB', kape: 'CSV', memory: 'MEM',
  disk_image: 'IMG', evtx: 'EVT', pcap: 'NET',
  logs: 'LOG', yara_rules: 'YAR', other: 'FILE',
};

const TYPE_LABELS: Record<string, string> = {
  axiom: 'AXIOM Case', kape: 'KAPE Output', memory: 'Memory Dump',
  disk_image: 'Disk Image', evtx: 'Event Logs', pcap: 'Network Capture',
  logs: 'Server Logs', yara_rules: 'YARA Rules', other: 'Other',
};

export default function CaseManager() {
  const { setCaseInfo, setActiveView, setEvidenceDir, setKapeDiagnostics } = useStore();

  // Tab: 'quick' (single file) or 'project'
  const [tab, setTab] = useState<'project' | 'quick'>('project');

  // Quick open
  const [quickPath, setQuickPath] = useState('');
  const [quickLoading, setQuickLoading] = useState(false);
  const [quickError, setQuickError] = useState('');

  // Project
  const [projectName, setProjectName] = useState('');
  const [projectDesc, setProjectDesc] = useState('');
  const [incidentDate, setIncidentDate] = useState('');
  const [timezone, setTimezone] = useState('Asia/Seoul');
  const [hostname, setHostname] = useState('');
  const [ipAddresses, setIpAddresses] = useState('');
  const [userAccounts, setUserAccounts] = useState('');
  const [knownIocs, setKnownIocs] = useState('');
  const [notes] = useState('');

  // Evidence scan
  const [scanDir, setScanDir] = useState('');
  const [scanning, setScanning] = useState(false);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState<Set<number>>(new Set());

  // Saved projects
  const [savedProjects, setSavedProjects] = useState<SavedProject[]>([]);

  // Recent cases
  const [recentCases, setRecentCases] = useState<RecentCase[]>(loadRecent());

  // Folder browser
  const [browserOpen, setBrowserOpen] = useState(false);
  const [browserPath, setBrowserPath] = useState('');
  const [browserItems, setBrowserItems] = useState<any[]>([]);
  const [browserLoading, setBrowserLoading] = useState(false);

  // Loading
  const [creating, setCreating] = useState(false);
  const [loadingPhase, setLoadingPhase] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    get('/api/project/list').then(d => setSavedProjects(d.projects || [])).catch(() => {});
  }, []);

  // Folder browser
  const browse = async (targetPath: string = '') => {
    setBrowserLoading(true);
    try {
      const data = await post('/api/files/browse', { path: targetPath, show_all: true });
      setBrowserPath(data.current || '');
      setBrowserItems((data.items || []).filter((i: any) => i.type === 'drive' || i.type === 'directory'));
    } catch { setBrowserItems([]); }
    finally { setBrowserLoading(false); }
  };

  const openFolderBrowser = () => {
    setBrowserOpen(true);
    browse('');
  };

  const selectFolder = (path: string) => {
    setScanDir(path);
    setEvidenceDir(path);
    setBrowserOpen(false);
    // Auto-scan after selecting
    setTimeout(async () => {
      setScanning(true);
      try {
        const data = await post('/api/project/scan-evidence', { directory: path });
        const found: EvidenceItem[] = data.found || [];
        setEvidence(found);
        setSelectedEvidence(new Set(found.map((_: any, i: number) => i)));
        if (!projectName) {
          const parts = path.replace(/\\/g, '/').split('/');
          setProjectName(parts[parts.length - 1] || parts[parts.length - 2] || '');
        }
      } catch (e: any) { setError('Scan failed: ' + e.message); }
      finally { setScanning(false); }
    }, 0);
  };

  // Evidence scan
  const handleScan = async () => {
    if (!scanDir.trim()) return;
    setScanning(true);
    try {
      const data = await post('/api/project/scan-evidence', { directory: scanDir.trim() });
      const found: EvidenceItem[] = data.found || [];
      setEvidence(found);
      setSelectedEvidence(new Set(found.map((_: any, i: number) => i)));
      if (!projectName && scanDir) {
        const parts = scanDir.replace(/\\/g, '/').split('/');
        setProjectName(parts[parts.length - 1] || parts[parts.length - 2] || '');
      }
    } catch (e: any) {
      setError('Scan failed: ' + e.message);
    } finally {
      setScanning(false);
    }
  };

  const toggleEvidence = (idx: number) => {
    setSelectedEvidence(prev => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

  // Create project & load
  const handleCreate = async () => {
    setCreating(true);
    setLoadingPhase('Creating project...');
    setError('');
    try {
      const selected = evidence.filter((_, i) => selectedEvidence.has(i));
      setLoadingPhase('Loading evidence files...');
      const data = await post('/api/project/create', {
        name: projectName || 'Untitled',
        description: projectDesc,
        incident_date: incidentDate,
        timezone,
        hostname,
        ip_addresses: ipAddresses,
        user_accounts: userAccounts,
        known_iocs: knownIocs,
        notes,
        evidence: selected,
      });

      // Check if any case data was loaded
      const loadResults = data.load_results || [];
      const loaded = loadResults.find((r: any) => r.status === 'loaded' && (r.type === 'axiom' || r.type === 'kape'));
      if (loaded) {
        // Fetch case info
        try {
          setLoadingPhase('Preparing dashboard...');
          const caseData = await get('/api/cases/summary');
          setCaseInfo({ ...caseData, case_name: projectName || caseData.case_name });
          setKapeDiagnostics(caseData.kape_diagnostics || null);
          const rc: RecentCase = { name: projectName || caseData.case_name, path: data.project_path || scanDir, source: 'project', totalHits: loaded.total_hits, openedAt: '' };
          saveRecent(rc); setRecentCases(loadRecent());
          setActiveView('dashboard');
        } catch {
          // Case loaded but summary failed — go to dashboard anyway
          setCaseInfo({
            case_name: projectName,
            total_hits: loaded.total_hits || 0,
            artifact_type_count: 0,
            date_range_start: '',
            date_range_end: '',
            evidence_sources: [],
            artifact_types: {},
          });
          const rc: RecentCase = { name: projectName, path: data.project_path || scanDir, source: 'project', totalHits: loaded.total_hits, openedAt: '' };
          saveRecent(rc); setRecentCases(loadRecent());
          setActiveView('dashboard');
        }
      } else {
        // No case data — just save project and stay (can use KAPE/Settings)
        setError('Project saved. No case data (AXIOM/KAPE) was loaded. Use KAPE to collect data first.');
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCreating(false);
      setLoadingPhase('');
    }
  };

  // Open saved project
  const handleOpenProject = async (proj: SavedProject) => {
    setCreating(true);
    setLoadingPhase(`Opening ${proj.name}...`);
    setError('');
    try {
      setLoadingPhase('Loading evidence files...');
      const data = await post('/api/project/open', { path: proj.path });
      const loadResults = data.load_results || [];
      const loaded = loadResults.find((r: any) => r.status === 'loaded' && (r.type === 'axiom' || r.type === 'kape'));
      if (loaded) {
        setLoadingPhase('Preparing dashboard...');
        const caseData = await get('/api/cases/summary');
        setCaseInfo({ ...caseData, case_name: proj.name || caseData.case_name });
        setKapeDiagnostics(caseData.kape_diagnostics || null);
        saveRecent({ name: proj.name, path: proj.path, source: 'project', totalHits: loaded.total_hits, openedAt: '' });
        setRecentCases(loadRecent());
        setActiveView('dashboard');
      } else {
        setError('Project opened but no case data loaded.');
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCreating(false);
      setLoadingPhase('');
    }
  };

  // Quick open
  const handleQuickOpen = async () => {
    if (!quickPath.trim()) return;
    setQuickLoading(true);
    setLoadingPhase('Opening case file...');
    setQuickError('');
    try {
      const data = await post('/api/cases/open', { path: quickPath.trim() });
      setCaseInfo(data);
      setKapeDiagnostics(data.kape_diagnostics || null);
      const src = quickPath.trim().endsWith('.mfdb') ? 'axiom' as const : 'kape' as const;
      saveRecent({ name: data.case_name || quickPath.trim().split(/[\\/]/).pop() || '', path: quickPath.trim(), source: src, totalHits: data.total_hits, openedAt: '' });
      setRecentCases(loadRecent());
      setActiveView('dashboard');
    } catch (e: any) {
      setQuickError(e.message);
    } finally {
      setQuickLoading(false);
    }
  };

  // Reopen a recent case
  const handleOpenRecent = async (rc: RecentCase) => {
    setQuickLoading(true);
    setLoadingPhase(`Opening ${rc.name}...`);
    setError('');
    try {
      if (rc.source === 'project') {
        const data = await post('/api/project/open', { path: rc.path });
        const loadResults = data.load_results || [];
        const loaded = loadResults.find((r: any) => r.status === 'loaded' && (r.type === 'axiom' || r.type === 'kape'));
        if (loaded) {
          const caseData = await get('/api/cases/summary');
          setCaseInfo({ ...caseData, case_name: rc.name || caseData.case_name });
          setKapeDiagnostics(caseData.kape_diagnostics || null);
          saveRecent({ ...rc, totalHits: loaded.total_hits }); setRecentCases(loadRecent());
          setActiveView('dashboard');
        } else {
          setError('Project opened but no case data loaded. Evidence files may have moved.');
        }
      } else {
        const data = await post('/api/cases/open', { path: rc.path });
        setCaseInfo(data);
        setKapeDiagnostics(data.kape_diagnostics || null);
        saveRecent({ ...rc, totalHits: data.total_hits }); setRecentCases(loadRecent());
        setActiveView('dashboard');
      }
    } catch (e: any) {
      setError(`Failed to open: ${e.message}`);
    } finally {
      setQuickLoading(false);
    }
  };

  const handleRemoveRecent = (e: React.MouseEvent, path: string) => {
    e.stopPropagation();
    removeRecent(path);
    setRecentCases(loadRecent());
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 12px', borderRadius: 6,
    border: '1px solid var(--border)', background: 'var(--bg)',
    color: 'var(--text)', fontSize: 13, fontFamily: 'monospace',
  };

  const sectionStyle: React.CSSProperties = {
    background: 'var(--surface)', border: '1px solid var(--border)',
    borderRadius: 12, padding: 20, marginBottom: 16,
  };

  return (
    <div style={{ maxWidth: 800, margin: '0 auto', padding: '40px 24px', height: '100vh', overflowY: 'auto' }}>
      {/* Title */}
      <div style={{ textAlign: 'center', marginBottom: 32 }}>
        <h1 style={{ fontSize: 28, fontWeight: 300, marginBottom: 4 }}>
          <strong>Forensic</strong> Workstation
        </h1>
        <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>
          Digital Forensics &amp; Incident Response Platform
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {([['project', 'New Project'], ['quick', 'Quick Open']] as const).map(([id, label]) => (
          <div key={id} onClick={() => setTab(id)}
            style={{
              padding: '10px 24px', cursor: 'pointer', fontSize: 13, fontWeight: 600,
              borderBottom: tab === id ? '2px solid var(--accent)' : '2px solid transparent',
              color: tab === id ? 'var(--accent)' : 'var(--text-dim)',
            }}>
            {label}
          </div>
        ))}
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span onClick={() => setActiveView('kape')}
            style={{ fontSize: 12, color: 'var(--text-dim)', cursor: 'pointer' }}
          >{'\u25B6'} KAPE</span>
          <span onClick={() => setActiveView('settings')}
            style={{ fontSize: 12, color: 'var(--text-dim)', cursor: 'pointer' }}
          >{'\u2699'} Settings</span>
        </div>
      </div>

      {error && (
        <div style={{
          padding: '10px 16px', borderRadius: 6, marginBottom: 16, fontSize: 12,
          background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)',
        }}>{error}</div>
      )}

      {/* ── RECENT CASES ── */}
      {recentCases.length > 0 && (
        <div style={{ ...sectionStyle, padding: 16, marginBottom: 20 }}>
          <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
            Recent Cases
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 8, marginTop: 8 }}>
            {recentCases.map((rc, i) => {
              const sourceTag = rc.source === 'project' ? 'PRJ' : rc.source === 'kape' ? 'KAPE' : 'AXIOM';
              const sourceColor = rc.source === 'project' ? '#a78bfa' : rc.source === 'kape' ? '#60a5fa' : '#4ade80';
              const timeAgo = (() => {
                const diff = Date.now() - new Date(rc.openedAt).getTime();
                const mins = Math.floor(diff / 60000);
                if (mins < 60) return `${mins}m ago`;
                const hrs = Math.floor(mins / 60);
                if (hrs < 24) return `${hrs}h ago`;
                const days = Math.floor(hrs / 24);
                return `${days}d ago`;
              })();
              return (
                <div key={i} onClick={() => handleOpenRecent(rc)}
                  style={{
                    padding: '10px 12px', borderRadius: 8, cursor: 'pointer',
                    border: '1px solid var(--border)', background: 'var(--bg)',
                    position: 'relative', transition: 'border-color 0.15s',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                      background: `${sourceColor}22`, color: sourceColor, fontFamily: 'monospace',
                    }}>{sourceTag}</span>
                    <span style={{ fontWeight: 600, fontSize: 13, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {rc.name}
                    </span>
                    <span onClick={(e) => handleRemoveRecent(e, rc.path)}
                      style={{ fontSize: 14, color: 'var(--text-dim)', cursor: 'pointer', lineHeight: 1, padding: '0 2px' }}
                      title="Remove from recent"
                    >{'\u00D7'}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: 'var(--text-dim)' }}>
                    <span>{timeAgo}</span>
                    {rc.totalHits != null && <span>{rc.totalHits.toLocaleString()} artifacts</span>}
                  </div>
                  <div style={{
                    fontSize: 10, color: 'var(--text-dim)', fontFamily: 'monospace', marginTop: 4,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {rc.path}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── PROJECT TAB ── */}
      {tab === 'project' && (
        <>
          {/* Saved Projects */}
          {savedProjects.length > 0 && (
            <div style={{ ...sectionStyle, padding: 16 }}>
              <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                Saved Projects
              </label>
              {savedProjects.map((p, i) => (
                <div key={i} onClick={() => handleOpenProject(p)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '8px 12px', borderRadius: 6, cursor: 'pointer', marginTop: 6,
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--accent-light)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</span>
                  {p.hostname && <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{p.hostname}</span>}
                  <div style={{ flex: 1 }} />
                  <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>{p.evidence_count} evidence</span>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>{p.updated?.slice(0, 10)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Evidence Scan */}
          <div style={sectionStyle}>
            <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block', marginBottom: 8 }}>
              Evidence Folder
            </label>
            <p style={{ fontSize: 12, color: 'var(--text-dim)', margin: '0 0 8px' }}>
              Select the case folder — evidence files will be auto-detected
            </p>
            <div style={{ display: 'flex', gap: 8 }}>
              <div style={{
                ...inputStyle, flex: 1, cursor: 'pointer', display: 'flex', alignItems: 'center',
                color: scanDir ? 'var(--text)' : 'var(--text-dim)',
              }} onClick={openFolderBrowser}>
                {scanDir || 'Click to browse...'}
              </div>
              <button className="btn" onClick={openFolderBrowser} style={{ padding: '8px 16px' }}>
                Browse
              </button>
              {scanDir && (
                <button className="btn btn-primary" onClick={handleScan} disabled={scanning}
                  style={{ padding: '8px 16px' }}>
                  {scanning ? '...' : 'Rescan'}
                </button>
              )}
            </div>

            {/* Detected Evidence */}
            {evidence.length > 0 && (
              <div style={{ marginTop: 12 }}>
                {evidence.map((ev, i) => (
                  <label key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 10, padding: '6px 8px',
                    borderRadius: 6, cursor: 'pointer',
                    background: selectedEvidence.has(i) ? 'rgba(74,222,128,0.06)' : 'transparent',
                  }}>
                    <input type="checkbox" checked={selectedEvidence.has(i)} onChange={() => toggleEvidence(i)} />
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                      background: 'rgba(96,165,250,0.15)', color: '#60a5fa', fontFamily: 'monospace',
                      minWidth: 28, textAlign: 'center',
                    }}>{TYPE_ICONS[ev.type] || 'FILE'}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, display: 'flex', gap: 8, alignItems: 'center' }}>
                        <span>{TYPE_LABELS[ev.type] || ev.type}</span>
                        <span style={{ fontWeight: 400, color: 'var(--text-dim)', fontSize: 11 }}>{ev.size}</span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ev.path}
                      </div>
                    </div>
                    <span style={{ color: '#4ade80', fontSize: 12, fontWeight: 700 }}>{'\u2713'}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Project Info */}
          <div style={sectionStyle}>
            <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>
              Project Info
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Project Name <span style={{ color: '#ef4444' }}>*</span></label>
                <input style={inputStyle} placeholder="e.g. Case_001" value={projectName} onChange={e => setProjectName(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Incident Date <span style={{ color: '#ef4444' }}>*</span></label>
                <input style={inputStyle} type="date" value={incidentDate} onChange={e => setIncidentDate(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Hostname <span style={{ color: '#ef4444' }}>*</span></label>
                <input style={inputStyle} placeholder="e.g. WORKSTATION-01" value={hostname} onChange={e => setHostname(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Timezone <span style={{ color: '#ef4444' }}>*</span></label>
                <input style={inputStyle} placeholder="Asia/Seoul" value={timezone} onChange={e => setTimezone(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>IP Addresses</label>
                <input style={inputStyle} placeholder="192.168.1.10, 10.0.0.5" value={ipAddresses} onChange={e => setIpAddresses(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>User Accounts</label>
                <input style={inputStyle} placeholder="admin, user01" value={userAccounts} onChange={e => setUserAccounts(e.target.value)} />
              </div>
            </div>

            <div style={{ marginTop: 10 }}>
              <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Known IOCs (IPs, hashes, domains)</label>
              <input style={inputStyle} placeholder="1.2.3.4, evil.exe, malware.com" value={knownIocs} onChange={e => setKnownIocs(e.target.value)} />
            </div>

            <div style={{ marginTop: 10 }}>
              <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Description / Notes</label>
              <textarea style={{ ...inputStyle, minHeight: 60, resize: 'vertical', fontFamily: 'inherit' }}
                placeholder="Incident background, scope, anything relevant..."
                value={projectDesc} onChange={e => setProjectDesc(e.target.value)}
              />
            </div>
          </div>

          {/* Create */}
          <button className="btn btn-primary"
            onClick={handleCreate}
            disabled={creating || (evidence.length === 0 && !projectName)}
            style={{ width: '100%', padding: '12px', fontSize: 14, fontWeight: 600, marginBottom: 24 }}>
            {creating ? 'Creating...' : 'Create Project & Load Evidence'}
          </button>
        </>
      )}

      {/* ── QUICK OPEN TAB ── */}
      {tab === 'quick' && (
        <div style={sectionStyle}>
          <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: 8 }}>
            Open a single case file (.mfdb or KAPE parsed directory)
          </label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input style={{ ...inputStyle, flex: 1 }}
              placeholder="Path to .mfdb file or KAPE parsed directory..."
              value={quickPath} onChange={e => setQuickPath(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleQuickOpen()}
            />
            <button className="btn btn-primary" onClick={handleQuickOpen}
              disabled={quickLoading || !quickPath.trim()}
              style={{ padding: '8px 24px' }}>
              {quickLoading ? 'Opening...' : 'Open'}
            </button>
          </div>
          {quickError && (
            <div style={{ marginTop: 8, fontSize: 12, color: '#ef4444' }}>{quickError}</div>
          )}
        </div>
      )}

      {/* Loading Overlay */}
      {(creating || quickLoading) && loadingPhase && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000,
        }}>
          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 12, padding: '32px 48px', textAlign: 'center',
            minWidth: 300,
          }}>
            <div style={{
              width: 32, height: 32, border: '3px solid var(--border)',
              borderTopColor: 'var(--accent)', borderRadius: '50%',
              animation: 'spin 0.8s linear infinite',
              margin: '0 auto 16px',
            }} />
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>
              {loadingPhase}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
              KAPE data may take 1-2 minutes to parse
            </div>
          </div>
        </div>
      )}

      {/* Folder Browser Modal */}
      {browserOpen && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
        }} onClick={() => setBrowserOpen(false)}>
          <div onClick={e => e.stopPropagation()} style={{
            width: 550, maxHeight: '65vh', background: 'var(--bg)',
            border: '1px solid var(--border)', borderRadius: 12,
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}>
            <div style={{
              padding: '12px 16px', borderBottom: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span style={{ fontWeight: 600, fontSize: 14 }}>Select Evidence Folder</span>
              <div style={{ flex: 1 }} />
              <button className="btn btn-sm" onClick={() => setBrowserOpen(false)}>Close</button>
            </div>
            <div style={{
              padding: '8px 16px', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
              fontFamily: 'monospace', fontSize: 12, color: 'var(--text-dim)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <button className="btn btn-sm" onClick={() => browse('')}>Drives</button>
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {browserPath || 'Select a drive'}
              </span>
              {browserPath && (
                <button className="btn btn-sm btn-primary" onClick={() => selectFolder(browserPath)}
                  style={{ fontSize: 11, padding: '4px 12px' }}>
                  Select This Folder
                </button>
              )}
              {browserLoading && <span style={{ color: 'var(--accent)', fontSize: 11 }}>Loading...</span>}
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {browserItems.map((item: any, i: number) => (
                <div key={i}
                  onClick={() => browse(item.path)}
                  onDoubleClick={() => selectFolder(item.path)}
                  style={{
                    padding: '8px 16px', cursor: 'pointer', display: 'flex',
                    alignItems: 'center', gap: 10, borderBottom: '1px solid var(--border-light)',
                    fontSize: 13,
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--accent-light)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                    {item.type === 'drive' ? '[D]' : '[F]'}
                  </span>
                  <span style={{ fontWeight: 600 }}>{item.name}</span>
                </div>
              ))}
              {browserItems.length === 0 && !browserLoading && (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
                  Empty directory
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
