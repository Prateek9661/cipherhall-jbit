import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  FileLock2,
  History,
  MessageSquareLock,
  Search,
  ShieldCheck,
  Users,
} from 'lucide-react';
import type { ActivityCategory, ActivityEvent } from '../types/vault';
import { filterActivityEvents, INSTITUTION_NAME } from '../utils/cryptoEngine';

interface ActivityLogProps {
  events: ActivityEvent[];
}

const CATEGORY_TABS: { id: 'all' | ActivityCategory; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'file', label: 'Files' },
  { id: 'access', label: 'Access' },
  { id: 'chat', label: 'Messages' },
  { id: 'security', label: 'Security' },
];

export function ActivityLog({ events }: ActivityLogProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<'all' | ActivityCategory>('all');

  const filteredEvents = useMemo(
    () => filterActivityEvents(events, { query, category }),
    [events, query, category]
  );

  const renderCategoryIcon = (event: ActivityEvent) => {
    if (event.status === 'warning') {
      return (
        <div className="h-8 w-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
        </div>
      );
    }
    switch (event.category) {
      case 'file':
        return (
          <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
            <FileLock2 className="h-4 w-4" aria-hidden="true" />
          </div>
        );
      case 'access':
        return (
          <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-300 shrink-0">
            <Users className="h-4 w-4" aria-hidden="true" />
          </div>
        );
      case 'chat':
        return (
          <div className="h-8 w-8 rounded-lg bg-slate-800 border border-slate-700/80 flex items-center justify-center text-slate-300 shrink-0">
            <MessageSquareLock className="h-4 w-4" aria-hidden="true" />
          </div>
        );
      case 'security':
        return (
          <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          </div>
        );
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-[1100px] mx-auto space-y-5">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-50">
            Activity Log
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Human-readable security and file activity across {INSTITUTION_NAME}.
          </p>
        </div>

        <div className="text-xs text-slate-400 shrink-0">
          <span className="text-slate-500">Recorded Events</span>
          <p className="font-mono text-sm font-semibold text-slate-100 tabular-nums mt-0.5">
            {events.length}
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search
            className="h-4 w-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
            aria-hidden="true"
          />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search activity log"
            placeholder="Search events, files, or people..."
            className="w-full h-10 pl-10 pr-3.5 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
          />
        </div>

        <div
          role="group"
          aria-label="Filter activity by category"
          className="inline-flex flex-wrap items-center p-1 rounded-lg bg-[#111824] border border-slate-800"
        >
          {CATEGORY_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setCategory(tab.id)}
              aria-pressed={category === tab.id}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                category === tab.id
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Clean Audit Feed */}
      <div className="rounded-xl border border-slate-800/90 bg-[#111824] overflow-hidden">
        {events.length === 0 ? (
          <div className="py-16 px-6 text-center">
            <History className="h-9 w-9 text-slate-600 mx-auto" aria-hidden="true" />
            <h2 className="mt-3 font-display text-base font-medium text-slate-200">
              No activity recorded yet
            </h2>
            <p className="mt-1 text-sm text-slate-400 max-w-md mx-auto">
              Encrypted file uploads, local decryptions, access changes, and key backups will
              appear here automatically.
            </p>
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="py-16 px-6 text-center">
            <History className="h-9 w-9 text-slate-600 mx-auto" aria-hidden="true" />
            <h2 className="mt-3 font-display text-base font-medium text-slate-200">
              No matching activity events
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Try clearing your search or switching event categories.
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-slate-800/70">
            {filteredEvents.map((event) => (
              <li
                key={event.id}
                className="px-4 sm:px-5 py-4 flex items-start justify-between gap-4 hover:bg-slate-800/30 transition-colors"
              >
                <div className="flex items-start gap-3.5 min-w-0">
                  {renderCategoryIcon(event)}
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-100 leading-snug">
                      <span>{event.title}</span>
                      {event.statusLabel && (
                        <>
                          <span className="mx-1.5 text-slate-500" aria-hidden="true">
                            ·
                          </span>
                          <span
                            className={
                              event.status === 'success'
                                ? 'text-emerald-400 font-medium'
                                : event.status === 'warning'
                                ? 'text-rose-400 font-medium'
                                : 'text-blue-400 font-medium'
                            }
                          >
                            {event.statusLabel}
                          </span>
                        </>
                      )}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-400 leading-relaxed">
                      {event.detail}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-slate-300 font-medium">{event.actorName}</span>
                      <span
                        className={`px-1.5 py-0.5 text-[10px] font-medium rounded border ${
                          event.actorRole === 'Faculty'
                            ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                            : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                        }`}
                      >
                        {event.actorRole}
                      </span>
                    </div>
                  </div>
                </div>
                <span className="font-mono text-xs text-slate-500 tabular-nums whitespace-nowrap shrink-0 pt-0.5">
                  {event.timestampLabel}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
