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

const VIEWS: Record<string, React.FC> = {
  dashboard: Dashboard,
  artifacts: ArtifactBrowser,
  detection: DetectionPanel,
  timeline: TimelineView,
  ioc: IOCTable,
  memory: MemoryAnalysis,
  binary: BinaryAnalysis,
  logs: LogAnalysis,
  network: NetworkAnalysis,
  yara: YaraScan,
  registry: RegistryAnalysis,
  report: ReportExport,
};

export default function Layout() {
  const { caseInfo, activeView, setActiveView, copilotOpen, toggleCopilot, lastAction } = useStore();

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

  if (!caseInfo) {
    return <CaseManager />;
  }

  const ViewComponent = VIEWS[activeView] || Dashboard;

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
