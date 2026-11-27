import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  Download,
  FileText,
  Lock,
  MessageSquareLock,
  Paperclip,
  Search,
  Send,
  ShieldCheck,
  User,
  X,
} from 'lucide-react';
import type { ChatMessage, ChatThread, VaultFile } from '../types/vault';
import { formatByteSize, INSTITUTION_NAME } from '../utils/cryptoEngine';
import { SecurityTooltip } from './SecurityTooltip';

interface EncryptedChatProps {
  threads: ChatThread[];
  activeThreadId: string | null;
  selectedMessageId: string | null;
  vaultFiles: VaultFile[];
  onSelectThread: (threadId: string) => void;
  onSelectMessage: (message: ChatMessage, threadTitle: string) => void;
  onSendMessage: (
    threadId: string,
    text: string,
    attachedFile?: VaultFile
  ) => Promise<void> | void;
  onDownloadVaultFile?: (
    fileId: string
  ) => Promise<{ state: 'success' | 'error'; message: string } | void> | void;
}

const E2E_TOOLTIP =
  'Messages and shared files are encrypted on your device using AES-256-GCM and locked with each participant’s RSA-2048 public key. Not even campus IT admins can read them.';

export function EncryptedChat({
  threads,
  activeThreadId,
  selectedMessageId,
  vaultFiles,
  onSelectThread,
  onSelectMessage,
  onSendMessage,
  onDownloadVaultFile,
}: EncryptedChatProps) {
  const [threadQuery, setThreadQuery] = useState('');
  const [draft, setDraft] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const [mobileShowThread, setMobileShowThread] = useState(false);
  const [attachPickerOpen, setAttachPickerOpen] = useState(false);
  const [attachedFile, setAttachedFile] = useState<VaultFile | null>(null);
  const [downloadingFileId, setDownloadingFileId] = useState<string | null>(null);
  const [downloadNotice, setDownloadNotice] = useState<{
    state: 'success' | 'error';
    message: string;
  } | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const filteredThreads = useMemo(() => {
    const q = threadQuery.trim().toLowerCase();
    if (!q) return threads;
    return threads.filter(
      (t) =>
        t.title.toLowerCase().includes(q) ||
        t.subtitle.toLowerCase().includes(q) ||
        (t.participantEmail?.toLowerCase().includes(q) ?? false) ||
        (t.participantRole?.toLowerCase().includes(q) ?? false)
    );
  }, [threads, threadQuery]);

  const activeThread = useMemo(
    () =>
      (activeThreadId ? threads.find((t) => t.id === activeThreadId) : undefined) ??
      threads[0] ??
      null,
    [threads, activeThreadId]
  );

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [activeThread?.id, activeThread?.messages.length]);

  const handleChooseThread = (threadId: string) => {
    onSelectThread(threadId);
    setMobileShowThread(true);
    setAttachPickerOpen(false);
    setSendError(null);
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const trimmed = draft.trim();
    if ((!trimmed && !attachedFile) || !activeThread || isSending) return;
    setIsSending(true);
    setSendError(null);
    try {
      const resolvedText =
        trimmed ||
        (attachedFile ? `Shared an encrypted vault document: ${attachedFile.filename}` : '');
      await onSendMessage(activeThread.id, resolvedText, attachedFile ?? undefined);
      setDraft('');
      setAttachedFile(null);
      setAttachPickerOpen(false);
    } catch (err) {
      setSendError(
        err instanceof Error ? err.message : 'Unable to encrypt and send message.'
      );
    } finally {
      setIsSending(false);
    }
  };

  const handleDownloadAttachment = async (
    event: React.MouseEvent,
    fileId: string
  ) => {
    event.stopPropagation();
    if (!onDownloadVaultFile) return;
    setDownloadingFileId(fileId);
    setDownloadNotice(null);
    try {
      const outcome = await onDownloadVaultFile(fileId);
      if (outcome) {
        setDownloadNotice(outcome);
      }
    } finally {
      setDownloadingFileId(null);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-[#0B0F17]">
      {/* Left Conversation List (Registered Campus Contacts Only) */}
      <aside
        aria-label="Encrypted conversations"
        className={`${
          mobileShowThread ? 'hidden md:flex' : 'flex'
        } w-full md:w-64 lg:w-72 xl:w-80 h-full min-h-0 border-r border-slate-800/80 bg-[#0E1420] flex-col shrink-0`}
      >
        <div className="p-3.5 border-b border-slate-800/80 shrink-0">
          <div className="relative">
            <Search
              className="h-3.5 w-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              aria-hidden="true"
            />
            <input
              type="search"
              value={threadQuery}
              onChange={(e) => setThreadQuery(e.target.value)}
              aria-label="Search registered contacts"
              placeholder="Search name, email, or role..."
              className="w-full h-9 pl-9 pr-3 rounded-lg bg-[#111824] border border-slate-800 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto p-2.5 space-y-3">
          <h2 className="px-2.5 pt-1 text-xs font-medium text-slate-500 flex items-center justify-between">
            <span>Registered Campus Contacts</span>
            <span className="font-mono tabular-nums">{filteredThreads.length}</span>
          </h2>

          {threads.length === 0 ? (
            <div className="px-3 py-8 text-center">
              <User className="h-7 w-7 text-slate-600 mx-auto" aria-hidden="true" />
              <p className="mt-2 text-xs font-medium text-slate-300">No campus contacts yet</p>
              <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                Other registered students and faculty will appear here once they create an
                account.
              </p>
            </div>
          ) : filteredThreads.length === 0 ? (
            <p className="px-3 py-6 text-center text-xs text-slate-500">
              No contacts match “{threadQuery}”.
            </p>
          ) : (
            <div className="space-y-1">
              {filteredThreads.map((thread) => {
                const isActive = thread.id === activeThread?.id;
                return (
                  <button
                    key={thread.id}
                    type="button"
                    onClick={() => handleChooseThread(thread.id)}
                    aria-current={isActive ? 'true' : undefined}
                    className={`w-full text-left px-2.5 py-2.5 rounded-lg transition-colors flex items-start gap-2.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                      isActive
                        ? 'bg-slate-800/90 text-slate-50'
                        : 'text-slate-300 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="h-8 w-8 rounded-lg bg-slate-800 border border-slate-700/80 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                      <User className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-medium text-slate-100 truncate">
                          {thread.title}
                        </span>
                        {thread.participantRole && (
                          <span
                            className={`px-1.5 py-0.5 text-[10px] font-medium rounded border shrink-0 ${
                              thread.participantRole === 'Faculty'
                                ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                                : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                            }`}
                          >
                            {thread.participantRole}
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 flex items-center justify-between gap-2">
                        <span className="text-xs text-slate-400 truncate">
                          {thread.participantEmail ?? thread.subtitle}
                        </span>
                        {thread.lastActivity && (
                          <span className="font-mono text-[11px] text-slate-500 tabular-nums shrink-0">
                            {thread.lastActivity}
                          </span>
                        )}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </aside>

      {/* Right Full-Height Live Chat Window with Pinned Bottom Composer */}
      {!activeThread ? (
        <section
          aria-label="Encrypted messaging empty state"
          className={`${
            mobileShowThread ? 'flex' : 'hidden md:flex'
          } flex-1 flex-col items-center justify-center p-8 text-center bg-[#0B0F17]`}
        >
          <div className="h-12 w-12 rounded-xl bg-[#111824] border border-slate-800 flex items-center justify-center text-slate-400">
            <MessageSquareLock className="h-6 w-6" aria-hidden="true" />
          </div>
          <h1 className="mt-4 font-display text-lg font-semibold text-slate-100">
            No encrypted conversations yet
          </h1>
          <p className="mt-1.5 text-sm text-slate-400 max-w-md leading-relaxed">
            Once other students or faculty from {INSTITUTION_NAME} register on CipherHall,
            they will appear in your contacts list for end-to-end encrypted messaging.
          </p>
        </section>
      ) : (
        <section
          aria-label={`Conversation with ${activeThread.title}`}
          className={`${
            mobileShowThread ? 'flex' : 'hidden md:flex'
          } flex-1 flex-col min-w-0 min-h-0 h-full bg-[#0B0F17]`}
        >
          {/* Active Thread Header with Narrow-Screen Back Button & End-to-End Encrypted Badge */}
          <div className="px-4 sm:px-5 py-3 border-b border-slate-800/80 bg-[#0E1420]/70 flex items-center justify-between gap-3 shrink-0">
            <div className="flex items-center gap-2.5 min-w-0">
              <button
                type="button"
                onClick={() => setMobileShowThread(false)}
                aria-label="Back to conversations"
                className="md:hidden p-1.5 -ml-1 rounded-lg border border-slate-800 bg-[#111824] text-slate-300 hover:text-slate-100 hover:bg-slate-800 shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              </button>

              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h1 className="font-display text-base font-semibold text-slate-50 truncate">
                    {activeThread.title}
                  </h1>
                  {activeThread.participantRole && (
                    <span
                      className={`px-2 py-0.5 text-[11px] font-medium rounded border shrink-0 ${
                        activeThread.participantRole === 'Faculty'
                          ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                          : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                      }`}
                    >
                      {activeThread.participantRole}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-0.5 truncate">
                  {activeThread.participantEmail ?? activeThread.subtitle}
                </p>
              </div>
            </div>

            <SecurityTooltip text={E2E_TOOLTIP} align="right" position="bottom">
              <div
                tabIndex={0}
                className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-md bg-emerald-950/50 border border-emerald-500/30 text-xs font-medium text-emerald-300 whitespace-nowrap shrink-0 cursor-help focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                <ShieldCheck
                  className="h-3.5 w-3.5 text-emerald-400 shrink-0"
                  aria-hidden="true"
                />
                <span className="hidden sm:inline">End-to-End Encrypted</span>
                <span className="sm:hidden">Encrypted</span>
              </div>
            </SecurityTooltip>
          </div>

          {downloadNotice && (
            <div
              role="status"
              aria-live="polite"
              className={`px-4 sm:px-6 py-2 border-b text-xs flex items-center justify-between gap-3 shrink-0 ${
                downloadNotice.state === 'success'
                  ? 'bg-emerald-950/35 border-emerald-500/30 text-emerald-200'
                  : 'bg-rose-950/35 border-rose-500/30 text-rose-200'
              }`}
            >
              <span>{downloadNotice.message}</span>
              <button
                type="button"
                onClick={() => setDownloadNotice(null)}
                className="text-slate-400 hover:text-slate-100 whitespace-nowrap shrink-0"
              >
                Dismiss
              </button>
            </div>
          )}

          {sendError && (
            <div
              role="alert"
              className="px-4 sm:px-6 py-2 border-b border-rose-500/30 bg-rose-950/35 text-xs text-rose-200 flex items-center justify-between gap-3 shrink-0"
            >
              <span>{sendError}</span>
              <button
                type="button"
                onClick={() => setSendError(null)}
                className="text-slate-400 hover:text-slate-100 whitespace-nowrap shrink-0"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Independently Scrollable Messages Stream */}
          <div className="flex-1 min-h-0 overflow-y-auto px-4 sm:px-6 py-5 space-y-5">
            {activeThread.messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center py-12">
                <Lock className="h-7 w-7 text-slate-600" aria-hidden="true" />
                <p className="mt-3 text-sm font-medium text-slate-200">
                  No messages with {activeThread.title} yet
                </p>
                <p className="mt-1 text-xs text-slate-400 max-w-sm leading-relaxed">
                  Send an end-to-end encrypted message or attach a Vault file below to start
                  this conversation.
                </p>
              </div>
            ) : (
              activeThread.messages.map((message) => {
                const isSelected = message.id === selectedMessageId;
                const isSelf = Boolean(message.isCurrentUser);

                return (
                  <div
                    key={message.id}
                    className={`flex flex-col ${isSelf ? 'items-end' : 'items-start'}`}
                  >
                    <div className="flex items-center gap-2 mb-1.5 px-1 text-xs">
                      <span className="font-medium text-slate-200">{message.senderName}</span>
                      <span
                        className={`px-1.5 py-0.5 text-[10px] font-medium rounded border ${
                          message.senderRole === 'Faculty'
                            ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                            : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                        }`}
                      >
                        {message.senderRole}
                      </span>
                      <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                        {message.timestamp}
                      </span>
                      <Lock className="h-3 w-3 text-slate-500" aria-label="Encrypted message" />
                    </div>

                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => onSelectMessage(message, activeThread.title)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onSelectMessage(message, activeThread.title);
                        }
                      }}
                      aria-pressed={isSelected}
                      aria-label={`Message from ${message.senderName}`}
                      className={`text-left max-w-xl rounded-xl px-4 py-3 border transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                        isSelected
                          ? 'bg-blue-600/15 border-blue-500/70 text-slate-100'
                          : isSelf
                          ? 'bg-[#152033] border-slate-700/80 hover:border-slate-600 text-slate-100'
                          : 'bg-[#111824] border-slate-800/90 hover:border-slate-700 text-slate-200'
                      }`}
                    >
                      <p className="text-sm leading-relaxed">{message.text}</p>

                      {message.attachedFile && (
                        <div className="mt-3 p-3 rounded-lg bg-[#0B0F17]/90 border border-slate-800 flex items-center justify-between gap-3">
                          <div className="flex items-center gap-2.5 min-w-0">
                            <div className="h-8 w-8 rounded-md bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
                              <FileText className="h-4 w-4" aria-hidden="true" />
                            </div>
                            <div className="min-w-0">
                              <p className="text-xs font-medium text-slate-100 truncate">
                                {message.attachedFile.filename}
                              </p>
                              <div className="mt-0.5 flex items-center gap-2 text-[11px] text-slate-400">
                                <span className="tabular-nums">
                                  {formatByteSize(message.attachedFile.sizeBytes)}
                                </span>
                                <span>·</span>
                                <span
                                  className={`inline-flex items-center gap-1 ${
                                    message.attachedFile.sha256Status === 'Verified'
                                      ? 'text-emerald-400'
                                      : message.attachedFile.sha256Status === 'Pending'
                                      ? 'text-amber-300'
                                      : 'text-rose-400'
                                  }`}
                                >
                                  {message.attachedFile.sha256Status === 'Verified' ? (
                                    <ShieldCheck className="h-3 w-3" aria-hidden="true" />
                                  ) : message.attachedFile.sha256Status === 'Pending' ? (
                                    <Clock className="h-3 w-3" aria-hidden="true" />
                                  ) : (
                                    <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                                  )}
                                  <span>
                                    {message.attachedFile.sha256Status === 'Mismatch'
                                      ? 'Integrity Alert'
                                      : message.attachedFile.sha256Status}
                                  </span>
                                </span>
                              </div>
                            </div>
                          </div>

                          {onDownloadVaultFile && (
                            <button
                              type="button"
                              disabled={downloadingFileId === message.attachedFile.fileId}
                              onClick={(e) =>
                                void handleDownloadAttachment(e, message.attachedFile!.fileId)
                              }
                              aria-label={`Decrypt & Download ${message.attachedFile.filename}`}
                              className="h-8 px-2.5 rounded-md border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-xs font-medium text-slate-100 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
                            >
                              <Download className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                              <span>
                                {downloadingFileId === message.attachedFile.fileId
                                  ? 'Decrypting…'
                                  : 'Decrypt'}
                              </span>
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Pinned Encrypted Message Composer + Vault File Attachment Picker */}
          <div className="relative border-t border-slate-800/80 bg-[#0E1420]/90 shrink-0">
            {/* Vault File Picker Popover */}
            {attachPickerOpen && (
              <div
                role="dialog"
                aria-label="Attach a file from Document Vault"
                className="absolute bottom-full left-3 right-3 sm:left-4 sm:right-auto sm:w-96 mb-2 rounded-xl bg-[#111824] border border-slate-700/90 shadow-2xl overflow-hidden z-20"
              >
                <div className="px-3.5 py-2.5 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-200">
                    Share a File from Document Vault
                  </span>
                  <button
                    type="button"
                    onClick={() => setAttachPickerOpen(false)}
                    aria-label="Close vault file picker"
                    className="p-1 rounded text-slate-400 hover:text-slate-100"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
                <div className="max-h-56 overflow-y-auto divide-y divide-slate-800/70">
                  {vaultFiles.length === 0 ? (
                    <p className="px-3.5 py-6 text-center text-xs text-slate-400">
                      No encrypted files in your Document Vault yet.
                    </p>
                  ) : (
                    vaultFiles.map((file) => {
                      const isPicked = attachedFile?.id === file.id;
                      return (
                        <button
                          key={file.id}
                          type="button"
                          onClick={() => {
                            setAttachedFile(file);
                            setAttachPickerOpen(false);
                          }}
                          className={`w-full text-left px-3.5 py-2.5 flex items-center justify-between gap-3 transition-colors ${
                            isPicked ? 'bg-blue-600/15' : 'hover:bg-slate-800/50'
                          }`}
                        >
                          <div className="flex items-center gap-2.5 min-w-0">
                            <FileText
                              className="h-4 w-4 text-blue-400 shrink-0"
                              aria-hidden="true"
                            />
                            <div className="min-w-0">
                              <p className="text-xs font-medium text-slate-100 truncate">
                                {file.filename}
                              </p>
                              <p className="text-[11px] text-slate-400 truncate">
                                {formatByteSize(file.sizeBytes)} · {file.uploadedBy}
                              </p>
                            </div>
                          </div>
                          {file.sha256Status === 'Verified' && (
                            <span className="text-[11px] font-medium text-emerald-400 shrink-0">
                              Verified
                            </span>
                          )}
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            )}

            {/* Selected Attachment Preview Chip */}
            {attachedFile && (
              <div className="px-4 pt-3 pb-0">
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-600/15 border border-blue-500/35 text-xs text-blue-200 max-w-full">
                  <FileText className="h-3.5 w-3.5 text-blue-400 shrink-0" aria-hidden="true" />
                  <span className="truncate font-medium">{attachedFile.filename}</span>
                  <span className="text-blue-300/70 shrink-0">
                    ({formatByteSize(attachedFile.sizeBytes)})
                  </span>
                  <button
                    type="button"
                    onClick={() => setAttachedFile(null)}
                    aria-label="Remove attached file"
                    className="p-0.5 rounded hover:bg-blue-500/20 text-blue-300 hover:text-white shrink-0"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="p-3 sm:p-4">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setAttachPickerOpen((prev) => !prev)}
                  aria-expanded={attachPickerOpen}
                  aria-label="Attach Vault File"
                  title="Share a file from Document Vault"
                  className={`h-11 w-11 rounded-lg border transition-colors inline-flex items-center justify-center shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    attachPickerOpen || attachedFile
                      ? 'bg-blue-600/15 border-blue-500/50 text-blue-300'
                      : 'bg-[#111824] border-slate-800 text-slate-400 hover:text-slate-100 hover:border-slate-700'
                  }`}
                >
                  <Paperclip className="h-4 w-4" aria-hidden="true" />
                </button>

                <label htmlFor="chat-message-input" className="sr-only">
                  Write an encrypted message to {activeThread.title}
                </label>
                <div className="relative flex-1 min-w-0">
                  <Lock
                    className="h-4 w-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                    aria-hidden="true"
                  />
                  <input
                    id="chat-message-input"
                    type="text"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder={`Message ${activeThread.title}...`}
                    className="w-full h-11 pl-10 pr-4 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={(!draft.trim() && !attachedFile) || isSending}
                  aria-label="Send Encrypted"
                  className="h-11 px-3.5 sm:px-4 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-sm font-medium text-white transition-colors inline-flex items-center gap-2 whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                >
                  <Send className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span className="hidden sm:inline">
                    {isSending ? 'Encrypting…' : 'Send Encrypted'}
                  </span>
                </button>
              </div>
            </form>
          </div>
        </section>
      )}
    </div>
  );
}
