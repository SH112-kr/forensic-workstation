import { useEffect } from 'react';
import { useStore } from '../hooks/useStore';
import Sidebar from './Sidebar';
import Header from './Header';
import CaseManager from './CaseManager';
import Dashboard from './Dashboard';
import ArtifactBrowser from './ArtifactBrowser';
import DetectionPanel from './DetectionPanel';
import TimelineView from './TimelineView';
import IOCTable from './IOCTable';
import MemoryAnalysis from './MemoryAnalysis';
import BinaryAnalysis from './BinaryAnalysis';
import ReportExport from './ReportExport';
import LogAnalysis from './LogAnalysis';
import NetworkAnalysis from './NetworkAnalysis';
import YaraScan from './YaraScan';
import RegistryAnalysis from './RegistryAnalysis';
import CopilotPanel from './CopilotPanel';
import Settings from './Settings';
import KapeBuilder from './KapeBuilder';
import CoveragePanel from './CoveragePanel';
import CaseComparePanel from './CaseComparePanel';
import PivotPanel from './PivotPanel';
import ManualWorkbench from './ManualWorkbench';

const VIEWS: Record<string, React.FC> = {
  dashboard: Dashboard,
  artifacts: ArtifactBrowser,
  detection: DetectionPanel,
  timeline: TimelineView,
  ioc: IOCTable,
  coverage: CoveragePanel,
  compare: CaseComparePanel,
  pivot: PivotPanel,
  manual: ManualWorkbench,
  memory: MemoryAnalysis,
  binary: BinaryAnalysis,
  logs: LogAnalysis,
  network: NetworkAnalysis,
  yara: YaraScan,
  registry: RegistryAnalysis,
  report: ReportExport,
  settings: Settings,
  kape: KapeBuilder,
};

export default function Layout() {
  const { caseInfo, activeView, setActiveView, copilotOpen, toggleCopilot, lastAction, caseManagerOpen, setCaseManagerOpen } = useStore();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Ctrl+number for tab switching
      if (e.ctrlKey && e.key >= '1' && e.key <= '9') {
        e.preventDefault();
        const views = ['dashboard','artifacts','timeline','detection','ioc','memory','binary','logs','report'];
        const idx = parseInt(e.key) - 1;
        if (idx < views.length) setActiveView(views[idx]);
      }
      // Ctrl+K for search focus (if on artifacts page)
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        setActiveView('artifacts');
        setTimeout(() => document.querySelector<HTMLInputElement>('[placeholder*="Search"]')?.focus(), 100);
      }
      // Ctrl+B for co-pilot toggle
      if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        toggleCopilot();
      }
      // Escape to close modals/detail panels
      if (e.key === 'Escape') {
        // Close co-pilot if open
        if (copilotOpen) toggleCopilot();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [copilotOpen]);

  // Views that work without a case loaded
  const NO_CASE_VIEWS: Record<string, React.FC> = { settings: Settings, kape: KapeBuilder };

  if (!caseInfo && !NO_CASE_VIEWS[activeView]) {
    return <CaseManager />;
  }

  const ViewComponent = NO_CASE_VIEWS[activeView] || VIEWS[activeView] || Dashboard;

  // Minimal layout when no case loaded (Settings/KAPE only)
  if (!caseInfo) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
        <div style={{
          height: 44, background: 'var(--surface)', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', padding: '0 16px', gap: 16,
        }}>
          <span style={{ fontWeight: 700, fontSize: 14 }}>Forensic Workstation</span>
          <div style={{ flex: 1 }} />
          <span
            onClick={() => setActiveView('kape')}
            style={{ fontSize: 12, cursor: 'pointer', padding: '4px 12px', borderRadius: 4,
              background: activeView === 'kape' ? 'var(--accent-light)' : 'transparent',
              color: activeView === 'kape' ? 'var(--accent)' : 'var(--text-dim)',
            }}
          >{'\u25B6'} KAPE</span>
          <span
            onClick={() => setActiveView('settings')}
            style={{ fontSize: 12, cursor: 'pointer', padding: '4px 12px', borderRadius: 4,
              background: activeView === 'settings' ? 'var(--accent-light)' : 'transparent',
              color: activeView === 'settings' ? 'var(--accent)' : 'var(--text-dim)',
            }}
          >{'\u2699'} Settings</span>
          <span
            onClick={() => setActiveView('dashboard')}
            style={{ fontSize: 12, cursor: 'pointer', padding: '4px 12px', borderRadius: 4,
              color: 'var(--text-dim)',
            }}
          >{'\u2190'} Open Case</span>
        </div>
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <ViewComponent />
        </main>
      </div>
    );
  }

  return (
    <>
      <Header />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar />
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <ViewComponent />
        </main>
        {copilotOpen && (
          <aside style={{
            width: 'var(--copilot-w)', borderLeft: '1px solid var(--border)',
            display: 'flex', flexDirection: 'column', background: 'var(--surface)',
            flexShrink: 0,
          }}>
            <CopilotPanel />
          </aside>
        )}
      </div>
      {/* CaseManager overlay — shown when the user clicks "+ Add case" from Header. */}
      {caseManagerOpen && (
        <div style={{
          position: 'fixed', inset: 0, background: 'var(--bg)', zIndex: 900,
          display: 'flex', flexDirection: 'column',
        }}>
          <div style={{
            padding: '10px 16px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <span style={{ fontWeight: 700, fontSize: 13 }}>Add Another Case</span>
            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              Opening a new case adds it to the multi-case set; the current case stays loaded.
            </span>
            <div style={{ flex: 1 }} />
            <button className="btn btn-sm" onClick={() => setCaseManagerOpen(false)}>Close</button>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            <CaseManager />
          </div>
        </div>
      )}
      {/* Status bar */}
      <div style={{
        height: 24, background: 'var(--surface)', borderTop: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', padding: '0 16px',
        fontSize: 11, color: 'var(--text-dim)', gap: 16,
      }}>
        <span>Connected: {caseInfo.case_name}</span>
        <span>{caseInfo.total_hits?.toLocaleString()} artifacts</span>
        <span>{caseInfo.artifact_type_count} types</span>
        {lastAction && (
          <>
            <span style={{ color: 'var(--border)' }}>|</span>
            <span style={{ color: 'var(--accent)' }}>{lastAction}</span>
          </>
        )}
        <div style={{ flex: 1 }} />
        <span>All analysis performed locally</span>
      </div>
    </>
  );
}
