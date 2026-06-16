import { useEffect, useState, useRef } from 'react';
import { get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';
import { useI18n } from '../i18n/useI18n';

interface KapeItem {
  name: string;
  category: string;
  description: string;
  is_compound: boolean;
  includes?: string[];
}

export default function KapeBuilder() {
  const { evidenceDir } = useStore();
  const { t } = useI18n();
  const [targets, setTargets] = useState<KapeItem[]>([]);
  const [modules, setModules] = useState<KapeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Selections
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set(['ForensicWorkstation']));
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set(['ForensicWorkstation']));
  const [source, setSource] = useState('');
  const [caseName, setCaseName] = useState('case');
  const [outputDir, setOutputDir] = useState('');
  const [vss, setVss] = useState(true);
  const [vd, setVd] = useState(true);

  // Run state
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<any[]>([]);
  const [phase, setPhase] = useState('');
  const [parsedStats, setParsedStats] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [filterTarget, setFilterTarget] = useState('');
  const [filterModule, setFilterModule] = useState('');
  const logRef = useRef<HTMLDivElement>(null);

  // Generate default output dir: evidenceDir/kape_output/YYYYMMDD_casename
  const genOutputDir = (base: string, name: string) => {
    const d = new Date();
    const stamp = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
    if (base) {
      return `${base.replace(/\\/g, '/')}/${stamp}_${name || 'case'}`;
    }
    return `export/${stamp}_${name || 'case'}`;
  };

  useEffect(() => {
    setOutputDir(genOutputDir(evidenceDir, caseName));
    get('/api/triage/kape-options').then(data => {
      if (data.error) { setError(data.error); return; }
      setTargets(data.targets || []);
      setModules(data.modules || []);
    }).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, []);

  // Sync when evidenceDir changes (user set it from project page)
  useEffect(() => {
    if (evidenceDir) setOutputDir(genOutputDir(evidenceDir, caseName));
  }, [evidenceDir]);

  // Update output dir when case name changes
  const handleCaseNameChange = (name: string) => {
    setCaseName(name);
    setOutputDir(genOutputDir(evidenceDir, name));
  };

  // Auto-scroll progress log
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [progress]);

  const toggleTarget = (name: string) => {
    setSelectedTargets(prev => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  const toggleModule = (name: string) => {
    setSelectedModules(prev => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  const buildCommand = () => {
    const parts = ['kape.exe'];
    const drv = source.trim() ? source.trim().replace(/[:\\/]+$/, '') + ':\\' : '<drive>:\\';
    parts.push('--tsource', drv);
    const outPath = outputDir.replace(/\//g, '\\');
    if (selectedTargets.size > 0 && outPath) {
      parts.push('--tdest', `"${outPath}\\collected"`);
      parts.push('--target', Array.from(selectedTargets).join(','));
    }
    if (selectedModules.size > 0 && outPath) {
      parts.push('--mdest', `"${outPath}\\parsed"`);
      parts.push('--module', Array.from(selectedModules).join(','));
      parts.push('--msource', `"${outPath}\\collected"`);
    }
    if (vss) parts.push('--vss');
    if (vd) parts.push('--vd');
    return parts.join(' ');
  };

  const handleRun = async () => {
    if (!source.trim() || !outputDir.trim()) {
      setResult({ error: t('kape.requiredError') });
      return;
    }
    setRunning(true);
    setResult(null);
    setProgress([]);
    setPhase('starting');
    try {
      await post('/api/triage/kape-run', {
        source: source.trim(),
        target_dest: outputDir.replace(/\\/g, '/') + '/collected',
        targets: Array.from(selectedTargets),
        module_dest: outputDir.replace(/\\/g, '/') + '/parsed',
        module_source: outputDir.replace(/\\/g, '/') + '/collected',
        modules: Array.from(selectedModules),
        vss, vd,
      });
      const poll = setInterval(async () => {
        try {
          const status = await get('/api/triage/status');
          setProgress(status.progress || []);
          setPhase(status.phase || '');
          setParsedStats(status.parsed_files || null);
          if (!status.running) {
            clearInterval(poll);
            setRunning(false);
            if (status.result) setResult(status.result);
          }
        } catch { /* ignore */ }
      }, 2000);
    } catch (e: any) {
      setResult({ error: e.message });
      setRunning(false);
    }
  };

  const handleStop = async () => {
    try { await post('/api/triage/stop', {}); } catch { /* ignore */ }
  };

  const filterItems = (items: KapeItem[], filter: string) => {
    if (!filter) return items;
    const f = filter.toLowerCase();
    return items.filter(i =>
      i.name.toLowerCase().includes(f) || i.description.toLowerCase().includes(f) || i.category.toLowerCase().includes(f)
    );
  };

  // Group items by category
  const groupByCategory = (items: KapeItem[]) => {
    const groups: Record<string, KapeItem[]> = {};
    items.forEach(item => {
      const cat = item.category || 'Other';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(item);
    });
    // Compound first
    const sorted: [string, KapeItem[]][] = [];
    if (groups['Compound']) { sorted.push(['Compound', groups['Compound']]); delete groups['Compound']; }
    Object.entries(groups).sort((a, b) => a[0].localeCompare(b[0])).forEach(e => sorted.push(e));
    return sorted;
  };

  const sectionStyle: React.CSSProperties = {
    background: 'var(--surface)', border: '1px solid var(--border)',
    borderRadius: 8, padding: 16, marginBottom: 16,
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

  if (loading) return <div style={{ padding: 24, color: 'var(--text-dim)' }}>{t('kape.loading')}</div>;
  if (error) return <div style={{ padding: 24, color: '#ef4444' }}>{t('kape.errorPrefix')} {error}</div>;

  // Collect all items included by selected compounds
  const includedByCompoundTargets = new Set<string>();
  targets.forEach(t => {
    if (t.is_compound && selectedTargets.has(t.name) && t.includes) {
      t.includes.forEach(inc => includedByCompoundTargets.add(inc));
    }
  });
  const includedByCompoundModules = new Set<string>();
  modules.forEach(m => {
    if (m.is_compound && selectedModules.has(m.name) && m.includes) {
      m.includes.forEach(inc => includedByCompoundModules.add(inc));
    }
  });

  const filteredTargets = filterItems(targets, filterTarget);
  const filteredModules = filterItems(modules, filterModule);

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <h2 style={{ margin: '0 0 20px', fontSize: 20, fontWeight: 700 }}>{t('kape.title')}</h2>

      {/* Source & Output */}
      <div style={sectionStyle}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>
              {t('kape.sourceDrive')}
            </label>
            <input style={inputStyle} placeholder="G:" value={source} onChange={e => setSource(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>
              {t('kape.caseName')}
            </label>
            <input style={inputStyle} placeholder="case" value={caseName} onChange={e => handleCaseNameChange(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>
              {t('kape.outputDirectory')}
            </label>
            <input style={inputStyle} value={outputDir} onChange={e => setOutputDir(e.target.value)} />
          </div>
        </div>
        <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={vss} onChange={e => setVss(e.target.checked)} /> {t('kape.vss')}
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={vd} onChange={e => setVd(e.target.checked)} /> {t('kape.deduplicate')}
          </label>
        </div>
      </div>

      {/* Targets & Modules side by side */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Targets */}
        <div style={sectionStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>
              {t('kape.targets')} <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}>({t('kape.selected', { count: selectedTargets.size })})</span>
            </h3>
          </div>
          <input
            style={{ ...inputStyle, marginBottom: 8 }}
            placeholder={t('kape.filterTargets')}
            value={filterTarget}
            onChange={e => setFilterTarget(e.target.value)}
          />
          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            {groupByCategory(filteredTargets).map(([category, items]) => (
              <div key={category}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-dim)', padding: '6px 4px 2px', textTransform: 'uppercase' }}>
                  {category}
                </div>
                {items.map(item => {
                  const selected = selectedTargets.has(item.name);
                  const includedByParent = includedByCompoundTargets.has(item.name);
                  const isChecked = selected || includedByParent;
                  return (
                    <label key={item.name} style={{
                      display: 'flex', alignItems: 'flex-start', gap: 8, padding: '4px 8px',
                      borderRadius: 4, cursor: includedByParent ? 'default' : 'pointer', fontSize: 12,
                      background: isChecked ? 'rgba(74,222,128,0.08)' : 'transparent',
                      opacity: includedByParent && !selected ? 0.7 : 1,
                    }}>
                      <input type="checkbox" checked={isChecked}
                        disabled={includedByParent && !selected}
                        onChange={() => !includedByParent && toggleTarget(item.name)}
                        style={{ marginTop: 2 }} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: isChecked ? 600 : 400, display: 'flex', alignItems: 'center', gap: 6 }}>
                          {item.name}
                          {item.is_compound && (
                            <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3,
                              background: 'rgba(96,165,250,0.15)', color: '#60a5fa' }}>{t('kape.compound')}</span>
                          )}
                          {includedByParent && !selected && (
                            <span style={{ fontSize: 9, color: '#4ade80' }}>{t('kape.included')}</span>
                          )}
                        </div>
                        {item.description && (
                          <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 1 }}>
                            {item.description.slice(0, 100)}
                          </div>
                        )}
                      </div>
                    </label>
                  );
                })}
              </div>
            ))}
          </div>
        </div>

        {/* Modules */}
        <div style={sectionStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>
              {t('kape.modules')} <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}>({t('kape.selected', { count: selectedModules.size })})</span>
            </h3>
          </div>
          <input
            style={{ ...inputStyle, marginBottom: 8 }}
            placeholder={t('kape.filterModules')}
            value={filterModule}
            onChange={e => setFilterModule(e.target.value)}
          />
          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            {groupByCategory(filteredModules).map(([category, items]) => (
              <div key={category}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-dim)', padding: '6px 4px 2px', textTransform: 'uppercase' }}>
                  {category}
                </div>
                {items.map(item => {
                  const selected = selectedModules.has(item.name);
                  const includedByParent = includedByCompoundModules.has(item.name);
                  const isChecked = selected || includedByParent;
                  return (
                    <label key={item.name} style={{
                      display: 'flex', alignItems: 'flex-start', gap: 8, padding: '4px 8px',
                      borderRadius: 4, cursor: includedByParent ? 'default' : 'pointer', fontSize: 12,
                      background: isChecked ? 'rgba(74,222,128,0.08)' : 'transparent',
                      opacity: includedByParent && !selected ? 0.7 : 1,
                    }}>
                      <input type="checkbox" checked={isChecked}
                        disabled={includedByParent && !selected}
                        onChange={() => !includedByParent && toggleModule(item.name)}
                        style={{ marginTop: 2 }} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: isChecked ? 600 : 400, display: 'flex', alignItems: 'center', gap: 6 }}>
                          {item.name}
                          {item.is_compound && (
                            <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3,
                              background: 'rgba(96,165,250,0.15)', color: '#60a5fa' }}>{t('kape.compound')}</span>
                          )}
                          {includedByParent && !selected && (
                            <span style={{ fontSize: 9, color: '#4ade80' }}>{t('kape.included')}</span>
                          )}
                        </div>
                        {item.description && (
                          <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 1 }}>
                            {item.description.slice(0, 100)}
                          </div>
                        )}
                      </div>
                    </label>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Generated Command Preview */}
      <div style={sectionStyle}>
        <h3 style={{ margin: '0 0 8px', fontSize: 14, fontWeight: 600 }}>{t('kape.commandPreview')}</h3>
        <div style={{
          padding: 12, borderRadius: 6, background: 'rgba(0,0,0,0.3)',
          fontFamily: 'monospace', fontSize: 12, color: '#4ade80',
          wordBreak: 'break-all', lineHeight: 1.6,
        }}>
          {buildCommand()}
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button
            style={{
              ...btnStyle,
              opacity: running || !source.trim() || !outputDir.trim() ? 0.5 : 1,
              background: '#f59e0b', fontSize: 14, padding: '10px 32px',
            }}
            onClick={handleRun}
            disabled={running || !source.trim() || !outputDir.trim()}
          >
            {running ? t('kape.running') : t('kape.execute')}
          </button>
          {running && (
            <button style={{ ...btnStyle, background: '#ef4444' }} onClick={handleStop}>
              {t('kape.stop')}
            </button>
          )}
          <button
            style={{ ...btnStyle, background: 'var(--border)', color: 'var(--text)' }}
            onClick={() => navigator.clipboard?.writeText(buildCommand())}
          >
            {t('kape.copyCommand')}
          </button>
        </div>
      </div>

      {/* Progress */}
      {(running || result) && (
        <div style={{
          ...sectionStyle,
          borderColor: running ? 'rgba(96,165,250,0.3)' : result?.error ? 'rgba(239,68,68,0.3)' : 'rgba(74,222,128,0.3)',
        }}>
          {running && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <div style={{
                width: 16, height: 16, border: '2px solid var(--border)',
                borderTopColor: '#60a5fa', borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }} />
              <span style={{ fontWeight: 600, color: '#60a5fa', fontSize: 13 }}>
                {phase.replace(/_/g, ' ')}
              </span>
              {parsedStats && (
                <span style={{ color: 'var(--text-dim)', marginLeft: 'auto', fontSize: 12 }}>
                  {t('kape.files', { count: parsedStats.files, size: parsedStats.size_mb })}
                </span>
              )}
            </div>
          )}

          {result && !running && (
            <div style={{
              padding: '8px 12px', borderRadius: 6, marginBottom: 12,
              background: result.error ? 'rgba(239,68,68,0.1)' : 'rgba(74,222,128,0.1)',
              color: result.error ? '#ef4444' : '#4ade80',
              fontWeight: 600, fontSize: 13,
            }}>
              {result.error ? `${t('kape.errorPrefix')} ${result.error}` : t('kape.complete', { seconds: result.duration_s })}
            </div>
          )}

          <div ref={logRef} style={{
            maxHeight: 250, overflowY: 'auto', fontFamily: 'monospace', fontSize: 11,
            background: 'rgba(0,0,0,0.2)', borderRadius: 4, padding: 8,
          }}>
            {progress.map((p: any, i: number) => (
              <div key={i} style={{
                padding: '2px 0',
                color: p.msg.includes('Error') ? '#ef4444' :
                  p.msg.includes('complete') || p.msg.includes('Complete') ? '#4ade80' :
                  p.msg.includes('Running:') ? '#60a5fa' : 'var(--text-dim)',
              }}>
                {p.msg}
              </div>
            ))}
          </div>

          {parsedStats?.folders && Object.keys(parsedStats.folders).length > 0 && (
            <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {Object.entries(parsedStats.folders).map(([folder, count]: [string, any]) => (
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

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
