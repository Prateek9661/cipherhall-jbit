import { Binary, KeyRound, Menu, Upload } from 'lucide-react';
import type { WorkspaceView } from '../types/vault';

interface TopHeaderProps {
  activeView: WorkspaceView;
  activeChatTitle?: string;
  inspectorOpen: boolean;
  onToggleInspector: () => void;
  onOpenSecurityModal: () => void;
  onOpenUploadModal: () => void;
  onOpenMobileNav: () => void;
}

export function TopHeader({
  activeView,
  activeChatTitle,
  inspectorOpen,
  onToggleInspector,
  onOpenSecurityModal,
  onOpenUploadModal,
  onOpenMobileNav,
}: TopHeaderProps) {
  const viewTitle =
    activeView === 'vault'
      ? 'Document Vault'
      : activeView === 'chat'
      ? 'Encrypted Chat'
      : 'Activity Log';

  return (
    <header className="h-14 px-3 sm:px-6 bg-[#0B0F17]/95 border-b border-slate-800/80 flex items-center justify-between gap-2 sm:gap-4 shrink-0">
      {/* Left: Mobile menu + Breadcrumb */}
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileNav}
          aria-label="Open navigation menu"
          className="lg:hidden p-2 -ml-1 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <Menu className="h-5 w-5" aria-hidden="true" />
        </button>

        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-sm min-w-0">
          <span className="text-slate-500 whitespace-nowrap hidden sm:inline">CipherHall</span>
          <span className="text-slate-600 hidden sm:inline" aria-hidden="true">
            /
          </span>
          <span className="font-display font-semibold text-slate-100 truncate">
            {viewTitle}
          </span>
          {activeView === 'chat' && activeChatTitle && (
            <>
              <span className="text-slate-600 hidden md:inline" aria-hidden="true">
                /
              </span>
              <span className="text-slate-400 truncate hidden md:inline">
                {activeChatTitle}
              </span>
            </>
          )}
        </nav>
      </div>

      {/* Right: Primary View Action + Security & Key Backup + Crypto Inspector Toggle */}
      <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
        {activeView === 'vault' && (
          <button
            type="button"
            onClick={onOpenUploadModal}
            aria-label="Upload & Encrypt"
            className="h-9 px-2.5 sm:px-3.5 rounded-lg bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-xs sm:text-sm font-medium text-white transition-colors inline-flex items-center gap-1.5 sm:gap-2 whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
          >
            <Upload className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span className="hidden sm:inline">Upload &amp; Encrypt</span>
            <span className="sm:hidden">Upload</span>
          </button>
        )}

        <button
          type="button"
          onClick={onOpenSecurityModal}
          aria-label="My Security & Key Backup"
          className="h-9 px-2.5 sm:px-3 rounded-lg border border-slate-800 bg-[#111824] hover:border-slate-700 text-slate-300 hover:text-slate-100 text-xs sm:text-sm font-medium transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <KeyRound className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
          <span className="hidden md:inline">My Security &amp; Backup</span>
          <span className="hidden sm:inline md:hidden">Security</span>
        </button>

        <button
          type="button"
          onClick={onToggleInspector}
          aria-expanded={inspectorOpen}
          aria-label={inspectorOpen ? 'Hide Inspector' : 'Open Inspector'}
          className={`h-9 px-2.5 sm:px-3 rounded-lg border text-xs sm:text-sm font-medium transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
            inspectorOpen
              ? 'bg-slate-800 border-slate-700 text-slate-100'
              : 'bg-[#111824] border-slate-800 text-slate-300 hover:text-slate-100 hover:border-slate-700'
          }`}
        >
          <Binary className="h-4 w-4 text-blue-400 shrink-0" aria-hidden="true" />
          <span className="hidden sm:inline">Inspector</span>
        </button>
      </div>
    </header>
  );
}
