import { useState } from 'react';
import { post } from '../hooks/useApi';

interface FileItem {
  name: string;
  path: string;
  type: 'drive' | 'directory' | 'file';
  file_type?: string;
  size_display?: string;
  extension?: string;
}

interface FileBrowserProps {
  open: boolean;
  onClose: () => void;
  onSelect: (path: string) => void;
  title?: string;
  /**
   * 'file'   — default; clicking a file returns it via onSelect, directories drill in.
   * 'folder' — files are rendered greyed out and non-selectable; the current directory
   *            can be returned via the "Select This Folder" action in the path bar.
   */
  mode?: 'file' | 'folder';
}

const icons: Record<string, string> = {
  drive: '\u{1F4BE}',
  directory: '\u{1F4C1}',
  'AXIOM Case': '\u{1F52C}',
  'Memory Dump': '\u{1F9E0}',
  'Binary': '\u2699\uFE0F',
  'Event Log': '\u{1F4CB}',
  'PCAP': '\u{1F310}',
  'YARA Rules': '\u{1F3AF}',
  'Registry Hive': '\u{1F5C2}\uFE0F',
  'Other': '\u{1F4C4}',
};

export default function FileBrowser({ open, onClose, onSelect, title, mode = 'file' }: FileBrowserProps) {
  const [browserPath, setBrowserPath] = useState('');
  const [browserItems, setBrowserItems] = useState<FileItem[]>([]);
  const [browserLoading, setBrowserLoading] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [initialized, setInitialized] = useState(false);

  const browse = async (targetPath: string = '', forceShowAll?: boolean) => {
    setBrowserLoading(true);
    try {
      const data = await post('/api/files/browse', {
        path: targetPath,
        show_all: forceShowAll !== undefined ? forceShowAll : showAll,
      });
      setBrowserPath(data.current || '');
      setBrowserItems(data.items || []);
    } catch {
      setBrowserItems([]);
    } finally {
      setBrowserLoading(false);
    }
  };

  // Auto-browse on first open
  if (open && !initialized) {
    setInitialized(true);
    browse('');
  }

  // Reset when closed
  if (!open && initialized) {
    setInitialized(false);
  }

  if (!open) return null;

  const selectFile = (item: FileItem) => {
    if (item.type === 'drive' || item.type === 'directory') {
      browse(item.path);
      return;
    }
    // File clicked — only selectable in file mode. Folder mode leaves files
    // visible for orientation but does not return them.
    if (mode === 'file') {
      onSelect(item.path);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }} onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 600, maxHeight: '70vh', background: 'var(--bg)',
          border: '1px solid var(--border)', borderRadius: 12,
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}
      >
        {/* Browser header */}
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>{title || 'Select File'}</span>
          <div style={{ flex: 1 }} />
          <label style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-dim)' }}>
            <input type="checkbox" checked={showAll} onChange={(e) => { setShowAll(e.target.checked); browse(browserPath, e.target.checked); }} />
            Show all files
          </label>
          <button className="btn btn-sm" onClick={onClose}>Close</button>
        </div>

        {/* Path bar */}
        <div style={{
          padding: '8px 16px', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
          fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-dim)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <button className="btn btn-sm" onClick={() => browse('')}>Drives</button>
          <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {browserPath || 'Select a drive'}
          </span>
          {mode === 'folder' && browserPath && (
            <button className="btn btn-sm btn-primary" onClick={() => onSelect(browserPath)}
              style={{ fontSize: 11, padding: '4px 12px', flexShrink: 0 }}>
              Select This Folder
            </button>
          )}
          {browserLoading && <span style={{ color: 'var(--accent)' }}>Loading...</span>}
        </div>

        {/* File list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {browserItems.map((item, i) => {
            const isFile = item.type === 'file';
            const fileIsDim = mode === 'folder' && isFile;
            return (
            <div
              key={i}
              onClick={() => selectFile(item)}
              onDoubleClick={() => isFile && mode === 'file' && onSelect(item.path)}
              style={{
                padding: '8px 16px', cursor: fileIsDim ? 'default' : 'pointer', display: 'flex',
                alignItems: 'center', gap: 10, borderBottom: '1px solid var(--border-light)',
                fontSize: 13, opacity: fileIsDim ? 0.4 : 1,
              }}
              onMouseEnter={(e) => { if (!fileIsDim) e.currentTarget.style.background = 'var(--accent-light)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
            >
              <span>{icons[item.type === 'file' ? (item.file_type || 'Other') : item.type] || '\u{1F4C4}'}</span>
              <span style={{ flex: 1, fontWeight: item.type !== 'file' ? 600 : 400 }}>
                {item.name}
              </span>
              {item.file_type && (
                <span style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 600 }}>{item.file_type}</span>
              )}
              {item.size_display && (
                <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>
                  {item.size_display}
                </span>
              )}
            </div>
            );
          })}
          {browserItems.length === 0 && !browserLoading && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
              No forensic files found. Enable "Show all files" to see everything.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
