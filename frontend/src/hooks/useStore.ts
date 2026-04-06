import { create } from 'zustand';

interface CaseInfo {
  case_name: string;
  total_hits: number;
  artifact_type_count: number;
  date_range_start: string;
  date_range_end: string;
  evidence_sources: string[];
  artifact_types: Record<string, number>;
}

interface AppState {
  // Case
  caseInfo: CaseInfo | null;
  caseLoading: boolean;
  setCaseInfo: (info: CaseInfo | null) => void;
  setCaseLoading: (v: boolean) => void;

  // Detection cache
  detection: any | null;
  mitre: any | null;
  detectionLoading: boolean;
  setDetection: (det: any, mit: any) => void;
  setDetectionLoading: (v: boolean) => void;

  // Active view
  activeView: string;
  setActiveView: (v: string) => void;

  // Theme
  theme: 'light' | 'dark';
  toggleTheme: () => void;

  // Status bar
  lastAction: string;
  setLastAction: (v: string) => void;

  // Project
  evidenceDir: string;
  setEvidenceDir: (v: string) => void;

  // KAPE diagnostics
  kapeDiagnostics: any | null;
  setKapeDiagnostics: (v: any | null) => void;

  // Copilot
  copilotOpen: boolean;
  toggleCopilot: () => void;
}

export const useStore = create<AppState>((set) => ({
  caseInfo: null,
  caseLoading: false,
  setCaseInfo: (info) => set({ caseInfo: info, detection: null, mitre: null }),
  setCaseLoading: (v) => set({ caseLoading: v }),

  detection: null,
  mitre: null,
  detectionLoading: false,
  setDetection: (det, mit) => set({ detection: det, mitre: mit }),
  setDetectionLoading: (v) => set({ detectionLoading: v }),

  activeView: 'dashboard',
  setActiveView: (v) => set({ activeView: v }),

  theme: (() => {
    const saved = localStorage.getItem('theme') as 'light' | 'dark' | null;
    const initial = saved === 'dark' || saved === 'light' ? saved : 'light';
    document.documentElement.setAttribute('data-theme', initial);
    return initial;
  })(),
  toggleTheme: () =>
    set((s) => {
      const next = s.theme === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      return { theme: next };
    }),

  lastAction: '',
  setLastAction: (v) => set({ lastAction: v }),

  evidenceDir: '',
  setEvidenceDir: (v) => set({ evidenceDir: v }),

  kapeDiagnostics: null,
  setKapeDiagnostics: (v) => set({ kapeDiagnostics: v }),

  copilotOpen: false,
  toggleCopilot: () => set((s) => ({ copilotOpen: !s.copilotOpen })),
}));
