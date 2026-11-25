import {
  FolderLock,
  History,
  LogOut,
  MessageSquareLock,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { UserProfile, WorkspaceView } from '../types/vault';

interface SidebarNavProps {
  user: UserProfile;
  activeView: WorkspaceView;
  onSelectView: (view: WorkspaceView) => void;
  fileCount: number;
  unreadChatCount: number;
  activityCount: number;
  onSignOut: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function SidebarNav({
  user,
  activeView,
  onSelectView,
  fileCount,
  unreadChatCount,
  activityCount,
  onSignOut,
  mobileOpen,
  onCloseMobile,
}: SidebarNavProps) {
  const handleNavClick = (view: WorkspaceView) => {
    onSelectView(view);
    onCloseMobile();
  };

  const navContent = (
    <div className="flex flex-col h-full bg-[#0E1420] border-r border-slate-800/80">
      {/* Brand header */}
      <div className="h-14 px-4 flex items-center justify-between border-b border-slate-800/80 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="h-8 w-8 rounded-lg bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <p className="font-display text-sm font-bold tracking-tight text-slate-50 leading-tight truncate">
              CipherHall
            </p>
            <p
              className="text-[11px] text-slate-400 leading-tight truncate"
              title="JB Institute of Technology, Dehradun"
            >
              JB Institute of Technology
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation menu"
          className="lg:hidden p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 shrink-0"
        >
          <X className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>

      {/* Primary navigation */}
      <nav aria-label="Workspace navigation" className="flex-1 px-3 py-5 space-y-1">
        <p className="px-3 pb-2 text-xs font-medium text-slate-500">Workspace</p>

        <button
          type="button"
          onClick={() => handleNavClick('vault')}
          aria-current={activeView === 'vault' ? 'page' : undefined}
          className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
            activeView === 'vault'
              ? 'bg-slate-800/90 text-slate-50'
              : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40'
          }`}
        >
          <span className="flex items-center gap-2.5">
            <FolderLock
              className={`h-4 w-4 ${activeView === 'vault' ? 'text-blue-400' : 'text-slate-500'}`}
              aria-hidden="true"
            />
            <span>Document Vault</span>
          </span>
          <span className="font-mono text-xs text-slate-400 tabular-nums">{fileCount}</span>
        </button>

        <button
          type="button"
          onClick={() => handleNavClick('chat')}
          aria-current={activeView === 'chat' ? 'page' : undefined}
          className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
            activeView === 'chat'
              ? 'bg-slate-800/90 text-slate-50'
              : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40'
          }`}
        >
          <span className="flex items-center gap-2.5">
            <MessageSquareLock
              className={`h-4 w-4 ${activeView === 'chat' ? 'text-blue-400' : 'text-slate-500'}`}
              aria-hidden="true"
            />
            <span>Encrypted Chat</span>
          </span>
          {unreadChatCount > 0 && (
            <span className="font-mono text-xs font-semibold text-blue-400 tabular-nums">
              {unreadChatCount}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleNavClick('activity')}
          aria-current={activeView === 'activity' ? 'page' : undefined}
          className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
            activeView === 'activity'
              ? 'bg-slate-800/90 text-slate-50'
              : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40'
          }`}
        >
          <span className="flex items-center gap-2.5">
            <History
              className={`h-4 w-4 ${activeView === 'activity' ? 'text-blue-400' : 'text-slate-500'}`}
              aria-hidden="true"
            />
            <span>Activity Log</span>
          </span>
          <span className="font-mono text-xs text-slate-400 tabular-nums">{activityCount}</span>
        </button>
      </nav>

      {/* Active Identity Footer */}
      <div className="p-4 border-t border-slate-800/80 space-y-3 shrink-0">
        <div className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-medium text-slate-100 truncate">{user.name}</p>
            <span
              className={`px-1.5 py-0.5 text-[11px] font-medium rounded shrink-0 ${
                user.role === 'Faculty'
                  ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                  : 'bg-blue-500/15 text-blue-300 border border-blue-500/30'
              }`}
            >
              {user.role}
            </span>
          </div>
          <p className="text-xs text-slate-400 truncate">{user.email}</p>
          <p className="text-xs text-slate-500 truncate pt-0.5">{user.department}</p>
        </div>

        <button
          type="button"
          onClick={onSignOut}
          className="w-full h-9 px-3 rounded-lg border border-slate-800 bg-[#111824] hover:bg-slate-800 text-xs font-medium text-slate-300 hover:text-slate-100 transition-colors flex items-center justify-center gap-2 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
          <span>Lock Vault &amp; Sign Out</span>
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop persistent sidebar */}
      <aside className="hidden lg:block w-56 xl:w-60 shrink-0 h-screen sticky top-0">
        {navContent}
      </aside>

      {/* Mobile slide-over navigation */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-xs"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative w-72 max-w-[85vw] h-full z-10">{navContent}</aside>
        </div>
      )}
    </>
  );
}
