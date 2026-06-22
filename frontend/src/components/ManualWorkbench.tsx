import { useEffect, useMemo, useState } from 'react';
import { get, post } from '../hooks/useApi';

type LaneId =
  | 'overview'
  | 'files'
  | 'vss'
  | 'ads_pe'
  | 'registry_evtx'
  | 'execution'
  | 'browser_recent'
  | 'jobs';

interface ManualStatus {
  analyst_only: boolean;
  llm_auto_ingest: boolean;
  mcp_event_log: boolean;
  auto_ioc_graph: boolean;
  selected_image: string;
  selected_image_source: string;
  connected: boolean;
  guardrails: string[];
  lanes: LaneId[];
}

interface AdsInfoResult {
  analyst_only?: boolean;
  source?: string;
  image_path?: string;
  internal_path?: string;
  host_path?: string;
  stream_name?: string;
  ads_path?: string;
  info?: Record<string, any>;
  hashes?: Record<string, string>;
  hash_status?: string;
  pe?: Record<string, any>;
  pe_status?: string;
  coverage_notes?: string[];
}

type FileInfoResult = AdsInfoResult;

interface VssSnapshotResult {
  ok?: boolean;
  source?: string;
  volume?: string;
  snapshot_count?: number;
  snapshots?: Array<Record<string, any>>;
  coverage_notes?: string[];
  guardrails?: string[];
  error?: string;
}

interface VssSearchResult {
  ok?: boolean;
  source?: string;
  snapshot_id?: string;
  volume?: string;
  searched?: Record<string, any>;
  returned?: number;
  files?: Array<Record<string, any>>;
  coverage?: Record<string, any>;
  coverage_notes?: string[];
}

interface FileSearchResult {
  ok?: boolean;
  source?: string;
  searched?: Record<string, any>;
  returned?: number;
  files?: Array<Record<string, any>>;
  coverage_notes?: string[];
}

interface RegistryEvtxDiscoveryResult {
  ok?: boolean;
  source?: string;
  returned?: number;
  files?: Array<Record<string, any>>;
  hives?: Array<Record<string, any>>;
  missing?: Array<Record<string, any>>;
  coverage_notes?: string[];
}

interface EvtxQueryResult {
  ok?: boolean;
  source?: string;
  input_source?: string;
  parsed_record_count?: number;
  event_id_counts_in_sample?: Record<string, number>;
  parser_backend?: string;
  filtered?: {
    total?: number;
    returned?: number;
    records?: Array<Record<string, any>>;
    summary?: Record<string, any>;
    truncated?: boolean;
  };
  coverage_notes?: string[];
  error?: string;
}

interface RegistryQueryResult {
  ok?: boolean;
  source?: string;
  query_mode?: string;
  resolved_key_path?: string;
  root_key_path?: string;
  returned?: number;
  total?: number;
  values?: Array<Record<string, any>>;
  entries?: Array<Record<string, any>>;
  subkeys?: string[];
  coverage_notes?: string[];
  query_semantics?: Record<string, any>;
  error?: string;
}

interface ExecutionSourceResult {
  ok?: boolean;
  source?: string;
  returned?: number;
  sources?: Array<Record<string, any>>;
  summary?: Record<string, any>;
  coverage_notes?: string[];
}

interface PrefetchQueryResult {
  ok?: boolean;
  source?: string;
  searched?: Record<string, any>;
  total?: number;
  returned?: number;
  entries?: Array<Record<string, any>>;
  parse_failure_count?: number;
  coverage_notes?: string[];
  error?: string;
}

interface BrowserRecentSourceResult {
  ok?: boolean;
  source?: string;
  returned?: number;
  sources?: Array<Record<string, any>>;
  summary?: Record<string, any>;
  coverage_notes?: string[];
}

interface JobsStatusResult {
  ok?: boolean;
  source?: string;
  mode?: string;
  active_job_count?: number;
  jobs?: Array<Record<string, any>>;
  coverage_notes?: string[];
}

const LANES: Array<{ id: LaneId; code: string; label: string; description: string }> = [
  { id: 'overview', code: 'OVR', label: 'Overview', description: 'Selected evidence and readiness' },
  { id: 'files', code: 'FILE', label: 'Files', description: 'Browse and search mounted image paths' },
  { id: 'vss', code: 'VSS', label: 'VSS', description: 'Snapshot catalog and historical file search' },
  { id: 'ads_pe', code: 'ADS', label: 'ADS / PE', description: 'Alternate streams and static PE triage' },
  { id: 'registry_evtx', code: 'REG', label: 'Registry / EVTX', description: 'Bounded hive and event-log queries' },
  { id: 'execution', code: 'EXEC', label: 'Execution', description: 'AmCache, BAM, UserAssist, ShimCache leads' },
  { id: 'browser_recent', code: 'USER', label: 'Browser / Recent', description: 'User activity context with privacy warnings' },
  { id: 'jobs', code: 'JOB', label: 'Jobs', description: 'Long-running manual work queue' },
];

const laneRailStyle: React.CSSProperties = {
  width: 220,
  minWidth: 220,
  borderRight: '1px solid var(--border)',
  background: 'var(--surface)',
  overflowY: 'auto',
  minHeight: 0,
};

const stableTextStyle: React.CSSProperties = {
  overflowWrap: 'anywhere',
  wordBreak: 'break-word',
};

const panelStyle: React.CSSProperties = {
  border: '1px solid var(--border)',
  borderRadius: 4,
  background: 'var(--surface)',
  minHeight: 0,
};

export default function ManualWorkbench() {
  const [status, setStatus] = useState<ManualStatus | null>(null);
  const [activeLane, setActiveLane] = useState<LaneId>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [hostPath, setHostPath] = useState('');
  const [streamName, setStreamName] = useState('Zone.Identifier');
  const [adsLoading, setAdsLoading] = useState(false);
  const [adsError, setAdsError] = useState('');
  const [adsResult, setAdsResult] = useState<AdsInfoResult | null>(null);
  const [fileInfoPath, setFileInfoPath] = useState('');
  const [fileInfoLoading, setFileInfoLoading] = useState(false);
  const [fileInfoResult, setFileInfoResult] = useState<FileInfoResult | null>(null);
  const [fileRoot, setFileRoot] = useState('/c:/');
  const [filePattern, setFilePattern] = useState('*');
  const [fileKeyword, setFileKeyword] = useState('');
  const [fileRecursive, setFileRecursive] = useState(true);
  const [fileLoading, setFileLoading] = useState('');
  const [fileError, setFileError] = useState('');
  const [fileResult, setFileResult] = useState<FileSearchResult | null>(null);
  const [registryEvtxLoading, setRegistryEvtxLoading] = useState('');
  const [registryEvtxError, setRegistryEvtxError] = useState('');
  const [evtxDiscovery, setEvtxDiscovery] = useState<RegistryEvtxDiscoveryResult | null>(null);
  const [registryDiscovery, setRegistryDiscovery] = useState<RegistryEvtxDiscoveryResult | null>(null);
  const [evtxQueryPath, setEvtxQueryPath] = useState('/c:/Windows/System32/winevt/Logs/Security.evtx');
  const [evtxEventIds, setEvtxEventIds] = useState('7045,1102');
  const [evtxKeyword, setEvtxKeyword] = useState('');
  const [evtxQueryResult, setEvtxQueryResult] = useState<EvtxQueryResult | null>(null);
  const [registryHivePath, setRegistryHivePath] = useState('/c:/Windows/System32/config/SYSTEM');
  const [registryKeyPath, setRegistryKeyPath] = useState('\\ControlSet001\\Services');
  const [registryKeyword, setRegistryKeyword] = useState('');
  const [registrySearchRoot, setRegistrySearchRoot] = useState('\\ControlSet001\\Services');
  const [registryQueryResult, setRegistryQueryResult] = useState<RegistryQueryResult | null>(null);
  const [executionLoading, setExecutionLoading] = useState(false);
  const [executionError, setExecutionError] = useState('');
  const [executionSources, setExecutionSources] = useState<ExecutionSourceResult | null>(null);
  const [prefetchDirectory, setPrefetchDirectory] = useState('/c:/Windows/Prefetch');
  const [prefetchPattern, setPrefetchPattern] = useState('*.pf');
  const [prefetchKeyword, setPrefetchKeyword] = useState('');
  const [prefetchLoading, setPrefetchLoading] = useState(false);
  const [prefetchResult, setPrefetchResult] = useState<PrefetchQueryResult | null>(null);
  const [browserRecentLoading, setBrowserRecentLoading] = useState(false);
  const [browserRecentError, setBrowserRecentError] = useState('');
  const [browserRecentSources, setBrowserRecentSources] = useState<BrowserRecentSourceResult | null>(null);
  const [jobsLoading, setJobsLoading] = useState(false);
  const [jobsError, setJobsError] = useState('');
  const [jobsStatus, setJobsStatus] = useState<JobsStatusResult | null>(null);
  const [vssVolume, setVssVolume] = useState('/c:');
  const [vssSnapshotId, setVssSnapshotId] = useState('');
  const [vssRoot, setVssRoot] = useState('/c:/');
  const [vssPattern, setVssPattern] = useState('*');
  const [vssKeyword, setVssKeyword] = useState('');
  const [vssRecursive, setVssRecursive] = useState(true);
  const [vssLoading, setVssLoading] = useState('');
  const [vssError, setVssError] = useState('');
  const [vssSnapshots, setVssSnapshots] = useState<VssSnapshotResult | null>(null);
  const [vssResult, setVssResult] = useState<VssSearchResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    get<ManualStatus>('/api/manual/status')
      .then((data) => {
        if (!cancelled) {
          setStatus(data);
          setError('');
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const lane = useMemo(
    () => LANES.find((item) => item.id === activeLane) || LANES[0],
    [activeLane],
  );

  const inspectAds = async () => {
    setAdsLoading(true);
    setAdsError('');
    try {
      const result = await post<AdsInfoResult>('/api/manual/ads/info', {
        host_path: hostPath,
        stream_name: streamName,
        include_hash: true,
        include_pe: true,
      });
      setAdsResult(result);
    } catch (err) {
      setAdsError(err instanceof Error ? err.message : String(err));
    } finally {
      setAdsLoading(false);
    }
  };

  const inspectFile = async () => {
    setFileInfoLoading(true);
    setAdsError('');
    try {
      const result = await post<FileInfoResult>('/api/manual/files/info', {
        internal_path: fileInfoPath,
        include_hash: true,
        include_pe: true,
      });
      setFileInfoResult(result);
    } catch (err) {
      setAdsError(err instanceof Error ? err.message : String(err));
    } finally {
      setFileInfoLoading(false);
    }
  };

  const browseFiles = async () => {
    setFileLoading('browse');
    setFileError('');
    try {
      const result = await post<FileSearchResult>('/api/manual/files/browse', {
        path: fileRoot,
        limit: 300,
      });
      setFileResult(result);
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err));
    } finally {
      setFileLoading('');
    }
  };

  const searchFiles = async () => {
    setFileLoading('search');
    setFileError('');
    try {
      const result = await post<FileSearchResult>('/api/manual/files/search', {
        path: fileRoot,
        pattern: filePattern,
        keyword: fileKeyword,
        recursive: fileRecursive,
        limit: 300,
      });
      setFileResult(result);
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err));
    } finally {
      setFileLoading('');
    }
  };

  const loadEvtxFiles = async () => {
    setRegistryEvtxLoading('evtx');
    setRegistryEvtxError('');
    try {
      const result = await get<RegistryEvtxDiscoveryResult>('/api/manual/evtx/files');
      setEvtxDiscovery(result);
    } catch (err) {
      setRegistryEvtxError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegistryEvtxLoading('');
    }
  };

  const loadRegistryHives = async () => {
    setRegistryEvtxLoading('registry');
    setRegistryEvtxError('');
    try {
      const result = await get<RegistryEvtxDiscoveryResult>('/api/manual/registry/hives');
      setRegistryDiscovery(result);
    } catch (err) {
      setRegistryEvtxError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegistryEvtxLoading('');
    }
  };

  const queryEvtx = async () => {
    setRegistryEvtxLoading('evtx_query');
    setRegistryEvtxError('');
    try {
      const result = await post<EvtxQueryResult>('/api/manual/evtx/query', {
        evtx_path: evtxQueryPath,
        event_ids: evtxEventIds,
        keyword: evtxKeyword,
        limit: 200,
      });
      setEvtxQueryResult(result);
    } catch (err) {
      setRegistryEvtxError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegistryEvtxLoading('');
    }
  };

  const queryRegistry = async () => {
    setRegistryEvtxLoading('registry_query');
    setRegistryEvtxError('');
    try {
      const result = await post<RegistryQueryResult>('/api/manual/registry/query', {
        hive_path: registryHivePath,
        key_path: registryKeyPath,
        keyword: registryKeyword,
        search_root: registrySearchRoot,
        limit: 100,
      });
      setRegistryQueryResult(result);
    } catch (err) {
      setRegistryEvtxError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegistryEvtxLoading('');
    }
  };

  const loadExecutionSources = async () => {
    setExecutionLoading(true);
    setExecutionError('');
    try {
      const result = await get<ExecutionSourceResult>('/api/manual/execution/sources');
      setExecutionSources(result);
    } catch (err) {
      setExecutionError(err instanceof Error ? err.message : String(err));
    } finally {
      setExecutionLoading(false);
    }
  };

  const queryPrefetch = async () => {
    setPrefetchLoading(true);
    setExecutionError('');
    try {
      const result = await post<PrefetchQueryResult>('/api/manual/prefetch/query', {
        directory: prefetchDirectory,
        pattern: prefetchPattern,
        keyword: prefetchKeyword,
        limit: 200,
      });
      setPrefetchResult(result);
    } catch (err) {
      setExecutionError(err instanceof Error ? err.message : String(err));
    } finally {
      setPrefetchLoading(false);
    }
  };

  const loadBrowserRecentSources = async () => {
    setBrowserRecentLoading(true);
    setBrowserRecentError('');
    try {
      const result = await get<BrowserRecentSourceResult>('/api/manual/browser-recent/sources');
      setBrowserRecentSources(result);
    } catch (err) {
      setBrowserRecentError(err instanceof Error ? err.message : String(err));
    } finally {
      setBrowserRecentLoading(false);
    }
  };

  const refreshJobs = async () => {
    setJobsLoading(true);
    setJobsError('');
    try {
      const result = await get<JobsStatusResult>('/api/manual/jobs/status');
      setJobsStatus(result);
    } catch (err) {
      setJobsError(err instanceof Error ? err.message : String(err));
    } finally {
      setJobsLoading(false);
    }
  };

  const loadVssSnapshots = async () => {
    setVssLoading('snapshots');
    setVssError('');
    try {
      const result = await get<VssSnapshotResult>(`/api/manual/vss/snapshots?volume=${encodeURIComponent(vssVolume)}`);
      setVssSnapshots(result);
      const first = result.snapshots?.[0]?.snapshot_id || '';
      if (first && !vssSnapshotId) setVssSnapshotId(String(first));
    } catch (err) {
      setVssError(err instanceof Error ? err.message : String(err));
    } finally {
      setVssLoading('');
    }
  };

  const searchVssLayer = async () => {
    setVssLoading('search');
    setVssError('');
    try {
      const result = await post<VssSearchResult>('/api/manual/vss/files/search', {
        snapshot_id: vssSnapshotId,
        volume: vssVolume,
        path: vssRoot,
        pattern: vssPattern,
        keyword: vssKeyword,
        recursive: vssRecursive,
        limit: 300,
      });
      setVssResult(result);
    } catch (err) {
      setVssError(err instanceof Error ? err.message : String(err));
    } finally {
      setVssLoading('');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', minHeight: 0 }}>
      <div style={{
        height: 46,
        flexShrink: 0,
        borderBottom: '1px solid var(--border)',
        background: 'var(--surface)',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '0 16px',
        minWidth: 0,
      }}>
        <div style={{ fontWeight: 700, fontSize: 13 }}>Manual Workbench</div>
        <span className="badge badge-info">Analyst only</span>
        <span style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
          {status?.selected_image || 'No selected image'}
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: '220px minmax(420px, 1fr) 280px',
        flex: 1,
        minHeight: 0,
        overflow: 'hidden',
      }}>
        <aside style={laneRailStyle}>
          <div style={{ padding: 12, borderBottom: '1px solid var(--border)' }}>
            <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
              Evidence Lanes
            </div>
          </div>
          <nav>
            {LANES.map((item) => {
              const active = item.id === activeLane;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveLane(item.id)}
                  style={{
                    width: '100%',
                    minHeight: 48,
                    display: 'grid',
                    gridTemplateColumns: '42px 1fr',
                    gap: 8,
                    alignItems: 'center',
                    padding: '8px 12px',
                    border: 0,
                    borderLeft: active ? '2px solid var(--medium)' : '2px solid transparent',
                    borderBottom: '1px solid var(--border-light)',
                    background: active ? 'var(--surface-2)' : 'transparent',
                    color: active ? 'var(--text)' : 'var(--text-muted)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    fontFamily: 'var(--font)',
                  }}
                >
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: active ? 'var(--medium)' : 'var(--text-subtle)' }}>
                    {item.code}
                  </span>
                  <span style={{ minWidth: 0 }}>
                    <span style={{ display: 'block', fontSize: 12, fontWeight: 600 }}>{item.label}</span>
                    <span style={{ display: 'block', fontSize: 11, color: 'var(--text-subtle)', ...stableTextStyle }}>
                      {item.description}
                    </span>
                  </span>
                </button>
              );
            })}
          </nav>
        </aside>

        <main style={{ minWidth: 0, minHeight: 0, overflow: 'auto', padding: 14 }}>
          <section style={{ ...panelStyle, padding: 14, marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Selected Lane
                </div>
                <h2 style={{ fontSize: 18, margin: '4px 0 2px' }}>{lane.label}</h2>
                <p style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>{lane.description}</p>
              </div>
              <button className="btn btn-primary btn-sm" disabled>
                Lane action pending
              </button>
            </div>
          </section>

          <section style={{ ...panelStyle, padding: 14 }}>
            {loading && <ReservedState title="Loading manual status..." />}
            {!loading && error && <ReservedState title="Manual status unavailable" detail={error} />}
            {!loading && !error && activeLane === 'overview' && <OverviewLane status={status} />}
            {!loading && !error && activeLane === 'files' && (
              <FilesLane
                fileRoot={fileRoot}
                filePattern={filePattern}
                fileKeyword={fileKeyword}
                fileRecursive={fileRecursive}
                loading={fileLoading}
                error={fileError}
                result={fileResult}
                onRootChange={setFileRoot}
                onPatternChange={setFilePattern}
                onKeywordChange={setFileKeyword}
                onRecursiveChange={setFileRecursive}
                onBrowse={browseFiles}
                onSearch={searchFiles}
              />
            )}
            {!loading && !error && activeLane === 'vss' && (
              <VssLane
                vssVolume={vssVolume}
                vssSnapshotId={vssSnapshotId}
                vssRoot={vssRoot}
                vssPattern={vssPattern}
                vssKeyword={vssKeyword}
                vssRecursive={vssRecursive}
                loading={vssLoading}
                error={vssError}
                snapshots={vssSnapshots}
                result={vssResult}
                onVolumeChange={setVssVolume}
                onSnapshotChange={setVssSnapshotId}
                onRootChange={setVssRoot}
                onPatternChange={setVssPattern}
                onKeywordChange={setVssKeyword}
                onRecursiveChange={setVssRecursive}
                onLoadSnapshots={loadVssSnapshots}
                onSearch={searchVssLayer}
              />
            )}
            {!loading && !error && activeLane === 'registry_evtx' && (
              <RegistryEvtxLane
                loading={registryEvtxLoading}
                error={registryEvtxError}
                evtx={evtxDiscovery}
                registry={registryDiscovery}
                evtxQueryPath={evtxQueryPath}
                evtxEventIds={evtxEventIds}
                evtxKeyword={evtxKeyword}
                evtxQuery={evtxQueryResult}
                registryHivePath={registryHivePath}
                registryKeyPath={registryKeyPath}
                registryKeyword={registryKeyword}
                registrySearchRoot={registrySearchRoot}
                registryQuery={registryQueryResult}
                onEvtxQueryPathChange={setEvtxQueryPath}
                onEvtxEventIdsChange={setEvtxEventIds}
                onEvtxKeywordChange={setEvtxKeyword}
                onRegistryHivePathChange={setRegistryHivePath}
                onRegistryKeyPathChange={setRegistryKeyPath}
                onRegistryKeywordChange={setRegistryKeyword}
                onRegistrySearchRootChange={setRegistrySearchRoot}
                onLoadEvtx={loadEvtxFiles}
                onLoadRegistry={loadRegistryHives}
                onQueryEvtx={queryEvtx}
                onQueryRegistry={queryRegistry}
              />
            )}
            {!loading && !error && activeLane === 'execution' && (
              <ExecutionLane
                loading={executionLoading}
                prefetchLoading={prefetchLoading}
                error={executionError}
                result={executionSources}
                prefetchDirectory={prefetchDirectory}
                prefetchPattern={prefetchPattern}
                prefetchKeyword={prefetchKeyword}
                prefetchResult={prefetchResult}
                onPrefetchDirectoryChange={setPrefetchDirectory}
                onPrefetchPatternChange={setPrefetchPattern}
                onPrefetchKeywordChange={setPrefetchKeyword}
                onLoad={loadExecutionSources}
                onQueryPrefetch={queryPrefetch}
              />
            )}
            {!loading && !error && activeLane === 'browser_recent' && (
              <BrowserRecentLane
                loading={browserRecentLoading}
                error={browserRecentError}
                result={browserRecentSources}
                onLoad={loadBrowserRecentSources}
              />
            )}
            {!loading && !error && activeLane === 'jobs' && (
              <JobsLane
                loading={jobsLoading}
                error={jobsError}
                result={jobsStatus}
                onRefresh={refreshJobs}
              />
            )}
            {!loading && !error && activeLane === 'ads_pe' && (
              <AdsPeLane
                hostPath={hostPath}
                streamName={streamName}
                fileInfoPath={fileInfoPath}
                loading={adsLoading}
                fileInfoLoading={fileInfoLoading}
                error={adsError}
                result={adsResult}
                fileInfoResult={fileInfoResult}
                onHostPathChange={setHostPath}
                onStreamNameChange={setStreamName}
                onFileInfoPathChange={setFileInfoPath}
                onInspect={inspectAds}
                onInspectFile={inspectFile}
              />
            )}
            {!loading && !error && activeLane !== 'overview' && activeLane !== 'files' && activeLane !== 'vss' && activeLane !== 'registry_evtx' && activeLane !== 'execution' && activeLane !== 'browser_recent' && activeLane !== 'jobs' && activeLane !== 'ads_pe' && <PlaceholderLane lane={lane} />}
          </section>
        </main>

        <aside style={{
          borderLeft: '1px solid var(--border)',
          background: 'var(--surface)',
          minWidth: 0,
          minHeight: 0,
          overflowY: 'auto',
          padding: 12,
        }}>
          <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700, marginBottom: 10 }}>
            Analyst Context
          </div>
          <ContextBlock label="Mode" value="Manual Workbench is analyst-facing only" />
          <ContextBlock label="LLM ingestion" value={status?.llm_auto_ingest ? 'Enabled' : 'Disabled'} />
          <ContextBlock label="IOC graph" value={status?.auto_ioc_graph ? 'Automatic' : 'Manual promotion only'} />
          <div style={{ ...panelStyle, padding: 10 }}>
            <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 8 }}>Guardrails</div>
            {(status?.guardrails || []).map((note, index) => (
              <div key={index} style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8, ...stableTextStyle }}>
                {note}
              </div>
            ))}
          </div>
        </aside>
      </div>
    </div>
  );
}

function JobsLane({
  loading,
  error,
  result,
  onRefresh,
}: {
  loading: boolean;
  error: string;
  result: JobsStatusResult | null;
  onRefresh: () => void;
}) {
  const notes = result?.coverage_notes || [];

  return (
    <div style={{ minHeight: 320, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        Current absorbed lanes run in synchronous direct mode. This status view is the expansion point for future long-running manual work queue jobs.
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <button
          className="btn btn-primary btn-sm"
          onClick={onRefresh}
          disabled={loading}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading ? 'Refreshing' : 'Refresh jobs'}
        </button>
      </div>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 220,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !result && (
          <div style={{ minHeight: 190, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Refresh manual workbench job status.
          </div>
        )}
        {result && (
          <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              <Metric label="Mode" value={result.mode || '-'} />
              <Metric label="Active jobs" value={String(result.active_job_count ?? 0)} />
              <Metric label="Source" value={result.source || '-'} />
            </div>
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function BrowserRecentLane({
  loading,
  error,
  result,
  onLoad,
}: {
  loading: boolean;
  error: string;
  result: BrowserRecentSourceResult | null;
  onLoad: () => void;
}) {
  const sources = result?.sources || [];
  const notes = result?.coverage_notes || [];
  const summary = result?.summary || {};

  return (
    <div style={{ minHeight: 360, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        Browser / Recent source discovery lists sensitive user-activity source files only. It does not parse URLs, downloads, shortcut targets, or document names.
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <button
          className="btn btn-primary btn-sm"
          onClick={onLoad}
          disabled={loading}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading ? 'Loading' : 'Load browser/recent sources'}
        </button>
      </div>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 250,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !result && (
          <div style={{ minHeight: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Load browser history database and Recent shortcut source candidates.
          </div>
        )}
        {result && (
          <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              <Metric label="Browser history" value={String(summary.browser_history_count ?? 0)} />
              <Metric label="Recent LNK" value={String(summary.recent_lnk_count ?? 0)} />
              <Metric label="Mode" value="discovery" />
            </div>
            {sources.length > 0 && (
              <DiscoveryList title="Browser / Recent candidates" rows={sources} />
            )}
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ExecutionLane({
  loading,
  prefetchLoading,
  error,
  result,
  prefetchDirectory,
  prefetchPattern,
  prefetchKeyword,
  prefetchResult,
  onPrefetchDirectoryChange,
  onPrefetchPatternChange,
  onPrefetchKeywordChange,
  onLoad,
  onQueryPrefetch,
}: {
  loading: boolean;
  prefetchLoading: boolean;
  error: string;
  result: ExecutionSourceResult | null;
  prefetchDirectory: string;
  prefetchPattern: string;
  prefetchKeyword: string;
  prefetchResult: PrefetchQueryResult | null;
  onPrefetchDirectoryChange: (value: string) => void;
  onPrefetchPatternChange: (value: string) => void;
  onPrefetchKeywordChange: (value: string) => void;
  onLoad: () => void;
  onQueryPrefetch: () => void;
}) {
  const sources = result?.sources || [];
  const prefetchEntries = prefetchResult?.entries || [];
  const notes = [
    ...(result?.coverage_notes || []),
    ...(prefetchResult?.coverage_notes || []),
  ];
  const summary = result?.summary || {};

  return (
    <div style={{ minHeight: 450, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        Execution source discovery lists parser inputs for AmCache, BAM/DAM, ShimCache, and UserAssist. Prefetch is execution evidence when enabled, but it still needs corroboration.
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <button
          className="btn btn-primary btn-sm"
          onClick={onLoad}
          disabled={loading}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading ? 'Loading' : 'Load execution sources'}
        </button>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="Prefetch dir" value={prefetchDirectory} onChange={onPrefetchDirectoryChange} placeholder="/c:/Windows/Prefetch" />
        <FieldInput label="Pattern" value={prefetchPattern} onChange={onPrefetchPatternChange} placeholder="*.pf" />
        <FieldInput label="Keyword" value={prefetchKeyword} onChange={onPrefetchKeywordChange} placeholder="optional" mono={false} />
        <button
          className="btn btn-primary btn-sm"
          onClick={onQueryPrefetch}
          disabled={prefetchLoading || !prefetchDirectory.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {prefetchLoading ? 'Querying' : 'Query Prefetch'}
        </button>
      </div>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 280,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !result && !prefetchResult && (
          <div style={{ minHeight: 250, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Load execution parser input sources or query Prefetch records from the captured image.
          </div>
        )}
        {(result || prefetchResult) && (
          <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              <Metric label="AmCache" value={summary.amcache_present ? 'present' : 'missing'} />
              <Metric label="SYSTEM hive" value={summary.system_hive_present ? 'present' : 'missing'} />
              <Metric label="User hives" value={String(summary.user_hive_count ?? '-')} />
              <Metric label="Prefetch matches" value={String(prefetchResult?.returned ?? '-')} />
            </div>
            {prefetchResult?.error && (
              <div style={{ color: 'var(--danger)', fontSize: 12, ...stableTextStyle }}>{prefetchResult.error}</div>
            )}
            {sources.length > 0 && (
              <DiscoveryList title="Execution source candidates" rows={sources} />
            )}
            {prefetchEntries.length > 0 && (
              <div style={{ display: 'grid', gap: 6, minWidth: 0 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Prefetch records
                </div>
                {prefetchEntries.slice(0, 80).map((entry, index) => (
                  <div key={`${String(entry.source_path || index)}-${index}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(150px, 1fr) 82px minmax(160px, 1fr)', gap: 8, minHeight: 32, alignItems: 'center', borderTop: '1px solid var(--border-light)', fontSize: 12 }}>
                    <div style={{ fontFamily: 'var(--mono)', ...stableTextStyle }}>{String(entry.executable_name || '-')}</div>
                    <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>{String(entry.run_count ?? '-')}</div>
                    <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)', ...stableTextStyle }}>{String(entry.latest_run_time_utc || entry.source_path || '-')}</div>
                  </div>
                ))}
              </div>
            )}
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function RegistryEvtxLane({
  loading,
  error,
  evtx,
  registry,
  evtxQueryPath,
  evtxEventIds,
  evtxKeyword,
  evtxQuery,
  registryHivePath,
  registryKeyPath,
  registryKeyword,
  registrySearchRoot,
  registryQuery,
  onEvtxQueryPathChange,
  onEvtxEventIdsChange,
  onEvtxKeywordChange,
  onRegistryHivePathChange,
  onRegistryKeyPathChange,
  onRegistryKeywordChange,
  onRegistrySearchRootChange,
  onLoadEvtx,
  onLoadRegistry,
  onQueryEvtx,
  onQueryRegistry,
}: {
  loading: string;
  error: string;
  evtx: RegistryEvtxDiscoveryResult | null;
  registry: RegistryEvtxDiscoveryResult | null;
  evtxQueryPath: string;
  evtxEventIds: string;
  evtxKeyword: string;
  evtxQuery: EvtxQueryResult | null;
  registryHivePath: string;
  registryKeyPath: string;
  registryKeyword: string;
  registrySearchRoot: string;
  registryQuery: RegistryQueryResult | null;
  onEvtxQueryPathChange: (value: string) => void;
  onEvtxEventIdsChange: (value: string) => void;
  onEvtxKeywordChange: (value: string) => void;
  onRegistryHivePathChange: (value: string) => void;
  onRegistryKeyPathChange: (value: string) => void;
  onRegistryKeywordChange: (value: string) => void;
  onRegistrySearchRootChange: (value: string) => void;
  onLoadEvtx: () => void;
  onLoadRegistry: () => void;
  onQueryEvtx: () => void;
  onQueryRegistry: () => void;
}) {
  const evtxFiles = evtx?.files || [];
  const hives = registry?.hives || [];
  const evtxRecords = evtxQuery?.filtered?.records || [];
  const registryEntries = registryQuery?.entries || [];
  const registryValues = registryQuery?.values || [];
  const notes = [
    ...(evtx?.coverage_notes || []),
    ...(registry?.coverage_notes || []),
    ...(evtxQuery?.coverage_notes || []),
    ...(registryQuery?.coverage_notes || []),
  ];

  return (
    <div style={{ minHeight: 520, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        EVTX and registry discovery lists candidate source files only. Offline query results remain analyst-only and require corroboration. Registry state proves captured hive contents, not execution.
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8, minWidth: 0 }}>
        <button
          className="btn btn-primary btn-sm"
          onClick={onLoadEvtx}
          disabled={loading === 'evtx'}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'evtx' ? 'Loading' : 'Load EVTX files'}
        </button>
        <button
          className="btn btn-primary btn-sm"
          onClick={onLoadRegistry}
          disabled={loading === 'registry'}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'registry' ? 'Loading' : 'Load registry hives'}
        </button>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="EVTX path" value={evtxQueryPath} onChange={onEvtxQueryPathChange} placeholder="/c:/Windows/System32/winevt/Logs/Security.evtx" />
        <FieldInput label="Event IDs" value={evtxEventIds} onChange={onEvtxEventIdsChange} placeholder="7045,1102" />
        <FieldInput label="Keyword" value={evtxKeyword} onChange={onEvtxKeywordChange} placeholder="optional" mono={false} />
        <button
          className="btn btn-primary btn-sm"
          onClick={onQueryEvtx}
          disabled={loading === 'evtx_query' || !evtxQueryPath.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'evtx_query' ? 'Querying' : 'Query EVTX'}
        </button>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(180px, 1fr) minmax(180px, 1fr)',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="Hive path" value={registryHivePath} onChange={onRegistryHivePathChange} placeholder="/c:/Windows/System32/config/SYSTEM" />
        <FieldInput label="Key path" value={registryKeyPath} onChange={onRegistryKeyPathChange} placeholder="\\ControlSet001\\Services" />
        <FieldInput label="Keyword" value={registryKeyword} onChange={onRegistryKeywordChange} placeholder="optional bounded search" mono={false} />
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 1fr) 112px', gap: 8, minWidth: 0 }}>
          <FieldInput label="Search root" value={registrySearchRoot} onChange={onRegistrySearchRootChange} placeholder="\\ControlSet001\\Services" />
          <button
            className="btn btn-primary btn-sm"
            onClick={onQueryRegistry}
            disabled={loading === 'registry_query' || !registryHivePath.trim() || (!registryKeyPath.trim() && !registryKeyword.trim())}
            style={{ height: 32, whiteSpace: 'nowrap', alignSelf: 'end' }}
          >
            {loading === 'registry_query' ? 'Querying' : 'Query registry'}
          </button>
        </div>
      </div>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 300,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !evtx && !registry && !evtxQuery && !registryQuery && (
          <div style={{ minHeight: 260, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Load candidates or run a bounded offline query against EVTX and registry sources from the captured image.
          </div>
        )}
        {(evtx || registry || evtxQuery || registryQuery) && (
          <div style={{ display: 'grid', gap: 12, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              <Metric label="EVTX files" value={String(evtx?.returned ?? '-')} />
              <Metric label="Registry hives" value={String(registry?.returned ?? '-')} />
              <Metric label="EVTX matches" value={String(evtxQuery?.filtered?.returned ?? '-')} />
              <Metric label="Registry matches" value={String(registryQuery?.returned ?? (registryValues.length || '-'))} />
            </div>
            {evtxQuery?.error && (
              <div style={{ color: 'var(--danger)', fontSize: 12, ...stableTextStyle }}>{evtxQuery.error}</div>
            )}
            {registryQuery?.error && (
              <div style={{ color: 'var(--danger)', fontSize: 12, ...stableTextStyle }}>{registryQuery.error}</div>
            )}
            {evtxFiles.length > 0 && (
              <DiscoveryList title="EVTX candidates" rows={evtxFiles} />
            )}
            {hives.length > 0 && (
              <DiscoveryList title="Registry hives" rows={hives} />
            )}
            {evtxQuery && (
              <div style={{ display: 'grid', gap: 8, minWidth: 0 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  EVTX query
                </div>
                <ResultRow label="Backend" value={evtxQuery.parser_backend || '-'} />
                <ResultRow label="Parsed" value={String(evtxQuery.parsed_record_count ?? '-')} />
                <ResultRow label="Total" value={String(evtxQuery.filtered?.total ?? '-')} />
                {evtxRecords.slice(0, 40).map((record, index) => (
                  <div key={`${String(record.timestamp || index)}-${index}`} style={{ display: 'grid', gridTemplateColumns: '82px minmax(160px, 1fr) minmax(180px, 1.4fr)', gap: 8, minHeight: 32, alignItems: 'center', borderTop: '1px solid var(--border-light)', fontSize: 12 }}>
                    <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>{String(record.event_id ?? '-')}</div>
                    <div style={{ fontFamily: 'var(--mono)', ...stableTextStyle }}>{String(record.timestamp || '-')}</div>
                    <div style={{ ...stableTextStyle }}>{String(record.semantic?.label || record.provider || JSON.stringify(record.fields || {}))}</div>
                  </div>
                ))}
              </div>
            )}
            {registryQuery && (
              <div style={{ display: 'grid', gap: 8, minWidth: 0 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Registry query
                </div>
                <ResultRow label="Mode" value={registryQuery.query_mode || '-'} />
                <ResultRow label="Key" value={registryQuery.resolved_key_path || registryQuery.root_key_path || '-'} />
                {registryValues.length > 0 && (
                  <DiscoveryList title="Registry values" rows={registryValues.map((value) => ({
                    path: `${String(value.name || '(default)')} = ${String(value.value || '')}`,
                    size: value.type || '-',
                  }))} />
                )}
                {registryEntries.length > 0 && (
                  <DiscoveryList title="Registry entries" rows={registryEntries.map((entry) => ({
                    path: entry.path,
                    size: entry.values_count ?? '-',
                  }))} />
                )}
              </div>
            )}
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function DiscoveryList({ title, rows }: { title: string; rows: Array<Record<string, any>> }) {
  return (
    <div style={{ display: 'grid', gap: 6, minWidth: 0 }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
        {title}
      </div>
      {rows.slice(0, 80).map((row, index) => {
        const path = String(row.path || row.info?.path || '-');
        const size = String(row.size ?? row.info?.size ?? '-');
        return (
          <div key={`${path}-${index}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 1fr) 82px', gap: 8, minHeight: 30, alignItems: 'center', borderTop: '1px solid var(--border-light)', fontSize: 12 }}>
            <div style={{ fontFamily: 'var(--mono)', ...stableTextStyle }}>{path}</div>
            <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>{size}</div>
          </div>
        );
      })}
    </div>
  );
}

function FilesLane({
  fileRoot,
  filePattern,
  fileKeyword,
  fileRecursive,
  loading,
  error,
  result,
  onRootChange,
  onPatternChange,
  onKeywordChange,
  onRecursiveChange,
  onBrowse,
  onSearch,
}: {
  fileRoot: string;
  filePattern: string;
  fileKeyword: string;
  fileRecursive: boolean;
  loading: string;
  error: string;
  result: FileSearchResult | null;
  onRootChange: (value: string) => void;
  onPatternChange: (value: string) => void;
  onKeywordChange: (value: string) => void;
  onRecursiveChange: (value: boolean) => void;
  onBrowse: () => void;
  onSearch: () => void;
}) {
  const files = result?.files || [];
  const notes = result?.coverage_notes || [];

  return (
    <div style={{ minHeight: 390, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        Current filesystem search is bounded by analyst-selected path, pattern, recursive mode, and limit. Results are not automatically promoted to IOC graph or LLM context.
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px 112px',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="Root path" value={fileRoot} onChange={onRootChange} placeholder="/c:/" />
        <FieldInput label="Pattern" value={filePattern} onChange={onPatternChange} placeholder="*" />
        <FieldInput label="Keyword" value={fileKeyword} onChange={onKeywordChange} placeholder="optional" mono={false} />
        <button
          className="btn btn-primary btn-sm"
          onClick={onBrowse}
          disabled={loading === 'browse' || !fileRoot.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'browse' ? 'Browsing' : 'Browse path'}
        </button>
        <button
          className="btn btn-primary btn-sm"
          onClick={onSearch}
          disabled={loading === 'search' || !fileRoot.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'search' ? 'Searching' : 'Search current layer'}
        </button>
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-dim)' }}>
        <input
          type="checkbox"
          checked={fileRecursive}
          onChange={(event) => onRecursiveChange(event.target.checked)}
        />
        Recursive search
      </label>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 250,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !result && (
          <div style={{ minHeight: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Browse a directory or search the captured current filesystem layer.
          </div>
        )}
        {result && (
          <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              <Metric label="Source" value={result.source || '-'} />
              <Metric label="Returned" value={String(result.returned ?? '-')} />
              <Metric label="Mode" value={result.searched?.recursive ? 'recursive' : 'browse'} />
            </div>
            {files.length > 0 && (
              <div style={{ minWidth: 0, overflowX: 'auto' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, 1fr) 82px 82px', gap: 8, fontSize: 10, color: 'var(--text-subtle)', fontWeight: 700, textTransform: 'uppercase', paddingBottom: 6 }}>
                  <div>Path</div>
                  <div>Size</div>
                  <div>Type</div>
                </div>
                {files.map((file, index) => (
                  <div key={`${String(file.path || index)}-${index}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, 1fr) 82px 82px', gap: 8, minHeight: 32, alignItems: 'center', borderTop: '1px solid var(--border-light)', fontSize: 12 }}>
                    <div style={{ fontFamily: 'var(--mono)', ...stableTextStyle }}>{String(file.path || file.name || '-')}</div>
                    <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>{String(file.size ?? '-')}</div>
                    <div style={{ color: 'var(--text-dim)' }}>{file.is_dir ? 'dir' : 'file'}</div>
                  </div>
                ))}
              </div>
            )}
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function VssLane({
  vssVolume,
  vssSnapshotId,
  vssRoot,
  vssPattern,
  vssKeyword,
  vssRecursive,
  loading,
  error,
  snapshots,
  result,
  onVolumeChange,
  onSnapshotChange,
  onRootChange,
  onPatternChange,
  onKeywordChange,
  onRecursiveChange,
  onLoadSnapshots,
  onSearch,
}: {
  vssVolume: string;
  vssSnapshotId: string;
  vssRoot: string;
  vssPattern: string;
  vssKeyword: string;
  vssRecursive: boolean;
  loading: string;
  error: string;
  snapshots: VssSnapshotResult | null;
  result: VssSearchResult | null;
  onVolumeChange: (value: string) => void;
  onSnapshotChange: (value: string) => void;
  onRootChange: (value: string) => void;
  onPatternChange: (value: string) => void;
  onKeywordChange: (value: string) => void;
  onRecursiveChange: (value: boolean) => void;
  onLoadSnapshots: () => void;
  onSearch: () => void;
}) {
  const files = result?.files || [];
  const notes = [
    ...(snapshots?.coverage_notes || []),
    ...(result?.coverage_notes || []),
  ];

  return (
    <div style={{ minHeight: 430, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        VSS snapshots are historical layers. Search results stay scoped to the selected snapshot and are not treated as current filesystem evidence.
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(130px, 160px) minmax(180px, 1fr) minmax(120px, 180px)',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="Volume" value={vssVolume} onChange={onVolumeChange} placeholder="/c:" />
        <label style={{ display: 'grid', gap: 5, minWidth: 0 }}>
          <span style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
            Snapshot
          </span>
          {snapshots?.snapshots?.length ? (
            <select
              className="input input-mono"
              value={vssSnapshotId}
              onChange={(event) => onSnapshotChange(event.target.value)}
              style={{ height: 32, minWidth: 0, fontFamily: 'var(--mono)', fontSize: 12 }}
            >
              {snapshots.snapshots.map((snap) => (
                <option key={String(snap.snapshot_id)} value={String(snap.snapshot_id)}>
                  #{String(snap.snapshot_index ?? '-')} {String(snap.snapshot_creation_time || snap.snapshot_id)}
                </option>
              ))}
            </select>
          ) : (
            <input
              className="input input-mono"
              value={vssSnapshotId}
              onChange={(event) => onSnapshotChange(event.target.value)}
              placeholder="snapshot id"
              style={{ height: 32, minWidth: 0, fontFamily: 'var(--mono)', fontSize: 12 }}
            />
          )}
        </label>
        <button
          className="btn btn-primary btn-sm"
          onClick={onLoadSnapshots}
          disabled={loading === 'snapshots'}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'snapshots' ? 'Loading' : 'Load snapshots'}
        </button>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(180px, 1fr) minmax(120px, 180px) minmax(120px, 180px) 112px',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="Root path" value={vssRoot} onChange={onRootChange} placeholder="/c:/" />
        <FieldInput label="Pattern" value={vssPattern} onChange={onPatternChange} placeholder="*" />
        <FieldInput label="Keyword" value={vssKeyword} onChange={onKeywordChange} placeholder="optional" mono={false} />
        <button
          className="btn btn-primary btn-sm"
          onClick={onSearch}
          disabled={loading === 'search' || !vssSnapshotId.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading === 'search' ? 'Searching' : 'Search VSS layer'}
        </button>
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-dim)' }}>
        <input
          type="checkbox"
          checked={vssRecursive}
          onChange={(event) => onRecursiveChange(event.target.checked)}
        />
        Recursive search
      </label>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 260,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !snapshots && !result && (
          <div style={{ minHeight: 230, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Load VSS snapshots, select one, then search a bounded historical layer.
          </div>
        )}
        {(snapshots || result) && (
          <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              <Metric label="Snapshots" value={String(snapshots?.snapshot_count ?? '-')} />
              <Metric label="Returned" value={String(result?.returned ?? '-')} />
              <Metric label="Skipped paths" value={String(result?.coverage?.paths_skipped ?? '-')} />
            </div>
            {files.length > 0 && (
              <div style={{ minWidth: 0, overflowX: 'auto' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, 1fr) 82px 132px', gap: 8, fontSize: 10, color: 'var(--text-subtle)', fontWeight: 700, textTransform: 'uppercase', paddingBottom: 6 }}>
                  <div>Path</div>
                  <div>Size</div>
                  <div>Layer</div>
                </div>
                {files.map((file, index) => (
                  <div key={`${String(file.path || index)}-${index}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, 1fr) 82px 132px', gap: 8, minHeight: 32, alignItems: 'center', borderTop: '1px solid var(--border-light)', fontSize: 12 }}>
                    <div style={{ fontFamily: 'var(--mono)', ...stableTextStyle }}>{String(file.path || '-')}</div>
                    <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>{String(file.size ?? '-')}</div>
                    <div style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)', ...stableTextStyle }}>{String(file.temporal_layer || file.snapshot_id || '-')}</div>
                  </div>
                ))}
              </div>
            )}
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function AdsPeLane({
  hostPath,
  streamName,
  fileInfoPath,
  loading,
  fileInfoLoading,
  error,
  result,
  fileInfoResult,
  onHostPathChange,
  onStreamNameChange,
  onFileInfoPathChange,
  onInspect,
  onInspectFile,
}: {
  hostPath: string;
  streamName: string;
  fileInfoPath: string;
  loading: boolean;
  fileInfoLoading: boolean;
  error: string;
  result: AdsInfoResult | null;
  fileInfoResult: FileInfoResult | null;
  onHostPathChange: (value: string) => void;
  onStreamNameChange: (value: string) => void;
  onFileInfoPathChange: (value: string) => void;
  onInspect: () => void;
  onInspectFile: () => void;
}) {
  const hashes = result?.hashes || {};
  const fileHashes = fileInfoResult?.hashes || {};
  const notes = [
    ...(result?.coverage_notes || []),
    ...(fileInfoResult?.coverage_notes || []),
  ];

  return (
    <div style={{ minHeight: 430, minWidth: 0, display: 'grid', gridTemplateRows: 'auto auto auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        ADS inspection reads the named stream content from the evidence image for static analysis only. File static triage reads captured file bytes without executing or auto-ingesting content.
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(220px, 1fr) minmax(160px, 260px) 112px',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <label style={{ display: 'grid', gap: 5, minWidth: 0 }}>
          <span style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
            Host path
          </span>
          <input
            className="input input-mono"
            value={hostPath}
            onChange={(event) => onHostPathChange(event.target.value)}
            placeholder="/c:/Users/alice/Downloads/dropper.exe"
            style={{ height: 32, minWidth: 0, fontFamily: 'var(--mono)', fontSize: 12 }}
          />
        </label>
        <label style={{ display: 'grid', gap: 5, minWidth: 0 }}>
          <span style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
            Stream
          </span>
          <input
            className="input input-mono"
            value={streamName}
            onChange={(event) => onStreamNameChange(event.target.value)}
            placeholder="Zone.Identifier"
            style={{ height: 32, minWidth: 0, fontFamily: 'var(--mono)', fontSize: 12 }}
          />
        </label>
        <button
          className="btn btn-primary btn-sm"
          onClick={onInspect}
          disabled={loading || !hostPath.trim() || !streamName.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {loading ? 'Inspecting' : 'Inspect ADS'}
        </button>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(220px, 1fr) 112px',
        gap: 8,
        alignItems: 'end',
        minWidth: 0,
      }}>
        <FieldInput label="File path" value={fileInfoPath} onChange={onFileInfoPathChange} placeholder="/c:/Users/alice/Downloads/dropper.exe" />
        <button
          className="btn btn-primary btn-sm"
          onClick={onInspectFile}
          disabled={fileInfoLoading || !fileInfoPath.trim()}
          style={{ height: 32, whiteSpace: 'nowrap' }}
        >
          {fileInfoLoading ? 'Inspecting' : 'Inspect file'}
        </button>
      </div>

      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 240,
        minWidth: 0,
        overflow: 'auto',
        padding: 12,
      }}>
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 10, ...stableTextStyle }}>{error}</div>}
        {!error && !result && !fileInfoResult && (
          <div style={{ height: '100%', minHeight: 210, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-subtle)', fontSize: 12, textAlign: 'center', ...stableTextStyle }}>
            Enter an ADS target or a current-layer file path to inspect metadata, hashes, and static PE header status.
          </div>
        )}
        {(result || fileInfoResult) && (
          <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8 }}>
              <Metric label="ADS hash" value={result?.hash_status || '-'} />
              <Metric label="File hash" value={fileInfoResult?.hash_status || '-'} />
              <Metric label="PE status" value={fileInfoResult?.pe_status || result?.pe_status || '-'} />
            </div>
            {result && <ResultRow label="ADS path" value={result.ads_path || '-'} />}
            {fileInfoResult && <ResultRow label="File path" value={fileInfoResult.internal_path || '-'} />}
            <ResultRow label="SHA256" value={hashes.sha256 || '-'} />
            {fileInfoResult && <ResultRow label="File SHA256" value={fileHashes.sha256 || '-'} />}
            <ResultRow label="PE note" value={fileInfoResult?.pe?.interpretation || fileInfoResult?.pe?.reason || result?.pe?.interpretation || result?.pe?.reason || '-'} />
            {notes.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Coverage notes
                </div>
                {notes.map((note, index) => (
                  <div key={index} style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function OverviewLane({ status }: { status: ManualStatus | null }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
      <Metric label="Selected image" value={status?.selected_image || 'None'} />
      <Metric label="Source" value={status?.selected_image_source || '-'} />
      <Metric label="Connected" value={status?.connected ? 'Ready' : 'No image'} />
      <Metric label="Available lanes" value={String(status?.lanes?.length || LANES.length)} />
    </div>
  );
}

function PlaceholderLane({ lane }: { lane: { label: string; description: string } }) {
  return (
    <div style={{ minHeight: 260, display: 'grid', gridTemplateRows: 'auto 1fr', gap: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 12, ...stableTextStyle }}>
        {lane.description}. This lane shell is stable; lane-specific H project functionality will be absorbed in a separate tested slice.
      </div>
      <div style={{
        border: '1px dashed var(--border)',
        borderRadius: 4,
        background: 'var(--bg)',
        minHeight: 190,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--text-subtle)',
        fontSize: 12,
        textAlign: 'center',
        padding: 20,
      }}>
        Reserved result area with stable height for filters, job progress, tables, and coverage notes.
      </div>
    </div>
  );
}

function ReservedState({ title, detail = '' }: { title: string; detail?: string }) {
  return (
    <div style={{ minHeight: 260, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: 8, color: 'var(--text-dim)', textAlign: 'center', padding: 24 }}>
      <div style={{ fontWeight: 700, color: 'var(--text)' }}>{title}</div>
      {detail && <div style={{ maxWidth: 520, fontSize: 12, ...stableTextStyle }}>{detail}</div>}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ ...panelStyle, padding: 10, minHeight: 74 }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700, marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 12, ...stableTextStyle }}>{value}</div>
    </div>
  );
}

function FieldInput({
  label,
  value,
  onChange,
  placeholder,
  mono = true,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <label style={{ display: 'grid', gap: 5, minWidth: 0 }}>
      <span style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
        {label}
      </span>
      <input
        className={mono ? 'input input-mono' : 'input'}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        style={{ height: 32, minWidth: 0, fontFamily: mono ? 'var(--mono)' : 'var(--font)', fontSize: 12 }}
      />
    </label>
  );
}

function ResultRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '92px minmax(0, 1fr)', gap: 10, minWidth: 0 }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 12, ...stableTextStyle }}>{value}</div>
    </div>
  );
}

function ContextBlock({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ ...panelStyle, padding: 10, marginBottom: 10 }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700, marginBottom: 5 }}>
        {label}
      </div>
      <div style={{ fontSize: 12, ...stableTextStyle }}>{value}</div>
    </div>
  );
}
