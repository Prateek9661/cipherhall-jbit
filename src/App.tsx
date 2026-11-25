import { useEffect, useMemo, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { ActivityLog } from './components/ActivityLog';
import { AuthScreen } from './components/AuthScreen';
import { CryptoInspectorDrawer } from './components/CryptoInspectorDrawer';
import { DocumentVault } from './components/DocumentVault';
import { EncryptedChat } from './components/EncryptedChat';
import { ManageAccessModal } from './components/ManageAccessModal';
import { SecurityBackupModal } from './components/SecurityBackupModal';
import { SidebarNav } from './components/SidebarNav';
import { TopHeader } from './components/TopHeader';
import { UploadEncryptModal } from './components/UploadEncryptModal';
import {
  CAMPUS_RECIPIENTS,
  DEFAULT_DEMO_USER,
  INITIAL_ACTIVITY_LOG,
  INITIAL_CHAT_THREADS,
  INITIAL_VAULT_FILES,
} from './data/mockVaultData';
import type {
  ActivityCategory,
  ActivityEvent,
  ChatMessage,
  ChatThread,
  InspectorTarget,
  Recipient,
  UserProfile,
  VaultFile,
  WorkspaceView,
} from './types/vault';
import {
  decryptPayloadWithWebCrypto,
  encryptPayloadWithWebCrypto,
  generateUserKeyBundle,
  hydrateRecipientsWithRealKeys,
  updateFileRecipientAccess,
  verifyFileIntegrity,
} from './utils/cryptoEngine';

function shouldAutostartWorkspace(): boolean {
  if (typeof window === 'undefined') return false;
  const params = new URLSearchParams(window.location.search);
  return params.get('autostart') === '1';
}

function formatNowTimeLabel(): string {
  const now = new Date();
  const time = now.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  return `Today · ${time}`;
}

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(() =>
    shouldAutostartWorkspace() ? DEFAULT_DEMO_USER : null
  );
  const [recipients, setRecipients] = useState<Recipient[]>(CAMPUS_RECIPIENTS);
  const [activeView, setActiveView] = useState<WorkspaceView>('vault');
  const [files, setFiles] = useState<VaultFile[]>(INITIAL_VAULT_FILES);
  const [threads, setThreads] = useState<ChatThread[]>(INITIAL_CHAT_THREADS);
  const [activeThreadId, setActiveThreadId] = useState<string>(INITIAL_CHAT_THREADS[0].id);
  const [activityLog, setActivityLog] = useState<ActivityEvent[]>(INITIAL_ACTIVITY_LOG);
  const [inspectorOpen, setInspectorOpen] = useState<boolean>(false);
  const [inspectorTarget, setInspectorTarget] = useState<InspectorTarget | null>({
    kind: 'file',
    file: INITIAL_VAULT_FILES[0],
  });
  const [uploadModalOpen, setUploadModalOpen] = useState<boolean>(false);
  const [securityModalOpen, setSecurityModalOpen] = useState<boolean>(false);
  const [manageAccessFile, setManageAccessFile] = useState<VaultFile | null>(null);
  const [vaultNotice, setVaultNotice] = useState<{
    state: 'success' | 'error';
    message: string;
  } | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState<boolean>(false);

  const appendActivity = (params: {
    category: ActivityCategory;
    title: string;
    detail: string;
    actor?: UserProfile | null;
    status?: 'info' | 'success' | 'warning';
    statusLabel?: string;
  }) => {
    const actor = params.actor ?? user;
    const entry: ActivityEvent = {
      id: `act-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      category: params.category,
      title: params.title,
      detail: params.detail,
      actorName: actor?.name ?? 'Campus Member',
      actorRole: actor?.role ?? 'Student',
      timestampLabel: formatNowTimeLabel(),
      status: params.status ?? 'info',
      statusLabel: params.statusLabel,
    };
    setActivityLog((prev) => [entry, ...prev]);
  };

  // Hydrate campus directory with real RSA-OAEP-2048 public keys for authentic Web Crypto key wrapping
  useEffect(() => {
    let cancelled = false;
    hydrateRecipientsWithRealKeys(CAMPUS_RECIPIENTS)
      .then((hydrated) => {
        if (!cancelled) {
          setRecipients(hydrated);
        }
      })
      .catch(() => {
        // Fallback handled lazily during encryption if Web Crypto is deferred
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // When autostart=1 is used, generate a real RSA-OAEP-2048 key pair & PBKDF2-protected private key for the demo session
  useEffect(() => {
    if (!user || user.privateKey) return;
    let cancelled = false;
    generateUserKeyBundle('cedar-lattice-410')
      .then((material) => {
        if (!cancelled) {
          setUser((prev) =>
            prev
              ? {
                  ...prev,
                  keyFingerprint: material.keyFingerprint,
                  publicKey: material.publicKey,
                  privateKey: material.privateKey,
                  protectedPrivateKey: material.protectedPrivateKey,
                }
              : prev
          );
        }
      })
      .catch(() => {
        // Ignore if unmounted
      });
    return () => {
      cancelled = true;
    };
  }, [user]);

  const syncedRecipients = useMemo<Recipient[]>(() => {
    if (!user) return recipients;
    return recipients.map((r) =>
      r.id === user.id || r.email.toLowerCase() === user.email.toLowerCase()
        ? {
            ...r,
            id: user.id,
            name: user.name,
            role: user.role,
            keyFingerprint: user.keyFingerprint,
            publicKey: user.publicKey ?? r.publicKey,
          }
        : r
    );
  }, [recipients, user]);

  const displayThreads = useMemo<ChatThread[]>(() => {
    if (!user) return threads;
    return threads.map((thread) => {
      const normalizedMessages = thread.messages.map((msg) => ({
        ...msg,
        isCurrentUser: msg.senderId === user.id,
      }));
      // If signed in as Dr. Elena Vance, display Maya Lin as the 1-on-1 counterparty on thread-vance
      if (thread.id === 'thread-vance' && user.id === 'usr-vance') {
        return {
          ...thread,
          title: 'Maya Lin',
          subtitle: 'Student · Computer Science (M.S.)',
          participantRole: 'Student',
          messages: normalizedMessages,
        };
      }
      return {
        ...thread,
        messages: normalizedMessages,
      };
    });
  }, [threads, user]);

  const unreadChatCount = useMemo(
    () => displayThreads.reduce((total, thread) => total + thread.unreadCount, 0),
    [displayThreads]
  );

  const activeThread = useMemo(
    () => displayThreads.find((t) => t.id === activeThreadId) ?? displayThreads[0],
    [displayThreads, activeThreadId]
  );

  const handleAuthenticated = (authenticatedUser: UserProfile) => {
    setUser(authenticatedUser);
    setActiveView('vault');
    setInspectorTarget({ kind: 'file', file: files[0] });
    setInspectorOpen(false);
    setVaultNotice(null);
    appendActivity({
      category: 'security',
      title: `${authenticatedUser.name} unlocked local vault session`,
      detail: 'Personal RSA-2048 private key unlocked locally on this device.',
      actor: authenticatedUser,
      status: 'success',
      statusLabel: 'Protected',
    });
  };

  const handleSignOut = () => {
    setUser(null);
    setUploadModalOpen(false);
    setSecurityModalOpen(false);
    setManageAccessFile(null);
    setMobileNavOpen(false);
    setInspectorOpen(false);
    setVaultNotice(null);
  };

  const handleSelectFile = (file: VaultFile) => {
    setInspectorTarget({ kind: 'file', file });
  };

  const handleFileEncrypted = (newFile: VaultFile) => {
    setFiles((prev) => [newFile, ...prev]);
    setInspectorTarget({ kind: 'file', file: newFile });
    const count = newFile.recipients.length;
    appendActivity({
      category: 'file',
      title: `${newFile.uploadedBy} encrypted & uploaded ${newFile.filename}`,
      detail: `Encrypted locally on your device and shared with ${count} ${
        count === 1 ? 'person' : 'people'
      }.`,
      status: 'success',
      statusLabel: 'Verified',
    });
  };

  const handleSaveFileAccess = (file: VaultFile, retainedNames: string[]) => {
    const { updatedFile, revokedNames, addedNames } = updateFileRecipientAccess(
      file,
      retainedNames
    );

    setFiles((prev) => prev.map((f) => (f.id === file.id ? updatedFile : f)));
    if (inspectorTarget?.kind === 'file' && inspectorTarget.file.id === file.id) {
      setInspectorTarget({ kind: 'file', file: updatedFile });
    }

    const parts: string[] = [];
    if (revokedNames.length > 0) {
      parts.push(`Revoked access for ${revokedNames.join(', ')}`);
    }
    if (addedNames.length > 0) {
      parts.push(`Granted access to ${addedNames.join(', ')}`);
    }
    const summary = parts.join(' and ');

    setVaultNotice({
      state: 'success',
      message: `${summary} on ${file.filename}.`,
    });

    const actorName = user?.name ?? 'Faculty';
    appendActivity({
      category: 'access',
      title:
        revokedNames.length > 0
          ? `${actorName} revoked access on ${file.filename}`
          : `${actorName} updated access on ${file.filename}`,
      detail: `${summary}. ${updatedFile.recipients.length} ${
        updatedFile.recipients.length === 1 ? 'person' : 'people'
      } currently authorized.`,
      status: revokedNames.length > 0 ? 'warning' : 'info',
      statusLabel: revokedNames.length > 0 ? 'Access Revoked' : 'Access Updated',
    });
  };

  const handleSelectThread = (threadId: string) => {
    setActiveThreadId(threadId);
    setThreads((prev) =>
      prev.map((t) => (t.id === threadId ? { ...t, unreadCount: 0 } : t))
    );
    const chosen = displayThreads.find((t) => t.id === threadId);
    if (chosen && chosen.messages.length > 0) {
      const latestMsg = chosen.messages[chosen.messages.length - 1];
      setInspectorTarget({
        kind: 'message',
        message: latestMsg,
        threadTitle: chosen.title,
      });
    }
  };

  const handleSelectMessage = (message: ChatMessage, threadTitle: string) => {
    setInspectorTarget({ kind: 'message', message, threadTitle });
  };

  const handleSendMessage = async (
    threadId: string,
    text: string,
    attachedFile?: VaultFile
  ) => {
    if (!user) return;
    const thread = displayThreads.find((t) => t.id === threadId);
    if (!thread) return;

    const now = new Date();
    const timestamp = now.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });

    const threadRecipients = syncedRecipients.filter((r) =>
      thread.recipientIds.includes(r.id)
    );
    const effectiveThreadRecipients: Recipient[] =
      threadRecipients.length > 0 ? [...threadRecipients] : syncedRecipients.slice(0, 2);

    if (!effectiveThreadRecipients.some((r) => r.id === user.id)) {
      effectiveThreadRecipients.unshift({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        keyFingerprint: user.keyFingerprint,
        publicKey: user.publicKey,
      });
    }

    const payloadString = attachedFile
      ? `${text}\n[Attachment: ${attachedFile.filename}]`
      : text;
    const messageBytes = new TextEncoder().encode(payloadString);
    const envelope = await encryptPayloadWithWebCrypto({
      plaintextBytes: messageBytes,
      recipients: effectiveThreadRecipients,
      encryptedAt: `${now.toISOString().replace('T', ' ').slice(0, 19)} UTC`,
    });

    const newMessage: ChatMessage = {
      id: `msg-${now.getTime()}`,
      threadId,
      senderId: user.id,
      senderName: user.name,
      senderRole: user.role,
      text,
      timestamp,
      isCurrentUser: true,
      attachedFile: attachedFile
        ? {
            fileId: attachedFile.id,
            filename: attachedFile.filename,
            sizeBytes: attachedFile.sizeBytes,
            sha256Status: attachedFile.sha256Status,
          }
        : undefined,
      crypto: envelope,
    };

    setThreads((prev) =>
      prev.map((t) =>
        t.id === threadId
          ? {
              ...t,
              lastActivity: timestamp,
              messages: [...t.messages, newMessage],
            }
          : t
      )
    );
    setInspectorTarget({
      kind: 'message',
      message: newMessage,
      threadTitle: thread.title,
    });

    appendActivity({
      category: 'chat',
      title: attachedFile
        ? `${user.name} shared ${attachedFile.filename} with ${thread.title}`
        : `${user.name} sent an encrypted message to ${thread.title}`,
      detail: attachedFile
        ? 'Attached an encrypted vault document inside an end-to-end encrypted conversation.'
        : `Encrypted message delivered locally for ${effectiveThreadRecipients.length} participants.`,
      status: 'info',
      statusLabel: 'Encrypted',
    });
  };

  const handleDownloadVaultFileFromChat = async (
    fileId: string
  ): Promise<{ state: 'success' | 'error'; message: string } | void> => {
    if (!user) return;
    const targetFile = files.find((f) => f.id === fileId);
    if (!targetFile) return;

    const triggerDownload = (blob: Blob, downloadName: string) => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = downloadName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    };

    if (
      targetFile.crypto.isWebCryptoReal &&
      targetFile.crypto.rawCiphertextBase64 &&
      user.privateKey
    ) {
      try {
        const result = await decryptPayloadWithWebCrypto({
          envelope: targetFile.crypto,
          privateKey: user.privateKey,
          recipientId: user.id,
          recipientFingerprint: user.keyFingerprint,
        });
        const copy = new Uint8Array(result.plaintextBytes.byteLength);
        copy.set(result.plaintextBytes);
        triggerDownload(
          new Blob([copy.buffer], {
            type: targetFile.mimeType || 'application/octet-stream',
          }),
          targetFile.filename
        );
        appendActivity({
          category: 'file',
          title: `${user.name} decrypted ${targetFile.filename} from chat`,
          detail: 'Verified integrity locally and decrypted shared attachment.',
          status: 'success',
          statusLabel: 'Verified',
        });
        return {
          state: 'success',
          message: `Decrypted ${targetFile.filename} locally and verified file integrity.`,
        };
      } catch (err) {
        const errMsg =
          err instanceof Error ? err.message : 'Integrity verification failed.';
        appendActivity({
          category: 'security',
          title: `Blocked chat decryption for ${targetFile.filename}`,
          detail: errMsg,
          status: 'warning',
          statusLabel: 'Blocked',
        });
        return {
          state: 'error',
          message: `Unable to decrypt ${targetFile.filename}: ${errMsg}`,
        };
      }
    }

    const check = verifyFileIntegrity(targetFile);
    if (!check.valid) {
      appendActivity({
        category: 'security',
        title: `Integrity alert blocked ${targetFile.filename} in chat`,
        detail: 'File integrity verification failed and download was blocked.',
        status: 'warning',
        statusLabel: 'Integrity Alert',
      });
      return {
        state: 'error',
        message: `Blocked download for ${targetFile.filename}: file integrity verification failed.`,
      };
    }

    triggerDownload(
      new Blob(
        [`${targetFile.decryptedPreviewContent}\n\n---\nDecrypted locally by CipherHall\n`],
        { type: 'text/plain;charset=utf-8' }
      ),
      `decrypted_${targetFile.filename.replace(/\.[^.]+$/, '')}.txt`
    );
    appendActivity({
      category: 'file',
      title: `${user.name} decrypted ${targetFile.filename} from chat`,
      detail: 'Verified integrity locally and downloaded shared attachment.',
      status: 'success',
      statusLabel: 'Verified',
    });
    return {
      state: 'success',
      message: `Decrypted ${targetFile.filename} locally and verified file integrity.`,
    };
  };

  const handleSelectView = (view: WorkspaceView) => {
    setActiveView(view);
    if (view === 'vault' && files.length > 0 && inspectorTarget?.kind !== 'file') {
      setInspectorTarget({ kind: 'file', file: files[0] });
    } else if (view === 'chat' && activeThread && activeThread.messages.length > 0) {
      const latest = activeThread.messages[activeThread.messages.length - 1];
      setInspectorTarget({
        kind: 'message',
        message: latest,
        threadTitle: activeThread.title,
      });
    }
  };

  if (!user) {
    return <AuthScreen onAuthenticated={handleAuthenticated} />;
  }

  return (
    <div className="h-screen overflow-hidden bg-[#0B0F17] text-slate-100 flex">
      <SidebarNav
        user={user}
        activeView={activeView}
        onSelectView={handleSelectView}
        fileCount={files.length}
        unreadChatCount={unreadChatCount}
        activityCount={activityLog.length}
        onSignOut={handleSignOut}
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <TopHeader
          activeView={activeView}
          activeChatTitle={activeThread?.title}
          inspectorOpen={inspectorOpen}
          onToggleInspector={() => setInspectorOpen((prev) => !prev)}
          onOpenSecurityModal={() => setSecurityModalOpen(true)}
          onOpenUploadModal={() => setUploadModalOpen(true)}
          onOpenMobileNav={() => setMobileNavOpen(true)}
        />

        {/* Subtle Plain-English Zero-Knowledge Banner */}
        <div
          role="note"
          className="px-3 sm:px-6 py-2 bg-[#0E1420]/90 border-b border-slate-800/80 flex items-center gap-2 text-xs text-slate-400 shrink-0"
        >
          <ShieldCheck
            className="h-3.5 w-3.5 text-emerald-400 shrink-0"
            aria-hidden="true"
          />
          <p className="truncate sm:whitespace-normal">
            Your files and messages are encrypted on your device before leaving your browser.
            Not even campus IT admins can read them.
          </p>
        </div>

        <div className="flex-1 flex min-h-0 min-w-0 overflow-hidden">
          <main
            className={`flex-1 min-w-0 min-h-0 ${
              activeView === 'chat' ? 'overflow-hidden' : 'overflow-y-auto'
            }`}
          >
            {activeView === 'vault' && (
              <DocumentVault
                files={files}
                currentUser={user}
                selectedFileId={
                  inspectorTarget?.kind === 'file' ? inspectorTarget.file.id : null
                }
                inspectorOpen={inspectorOpen}
                externalNotice={vaultNotice}
                onClearExternalNotice={() => setVaultNotice(null)}
                onSelectFile={handleSelectFile}
                onOpenUploadModal={() => setUploadModalOpen(true)}
                onManageAccess={(file) => setManageAccessFile(file)}
                onDecryptActivity={({ file, success, detail }) =>
                  appendActivity({
                    category: success ? 'file' : 'security',
                    title: success
                      ? `${user.name} decrypted & verified ${file.filename}`
                      : `Integrity alert blocked ${file.filename}`,
                    detail,
                    status: success ? 'success' : 'warning',
                    statusLabel: success ? 'Verified' : 'Integrity Alert',
                  })
                }
              />
            )}

            {activeView === 'chat' && (
              <EncryptedChat
                threads={displayThreads}
                activeThreadId={activeThreadId}
                selectedMessageId={
                  inspectorTarget?.kind === 'message' ? inspectorTarget.message.id : null
                }
                vaultFiles={files}
                onSelectThread={handleSelectThread}
                onSelectMessage={handleSelectMessage}
                onSendMessage={handleSendMessage}
                onDownloadVaultFile={handleDownloadVaultFileFromChat}
              />
            )}

            {activeView === 'activity' && <ActivityLog events={activityLog} />}
          </main>

          <CryptoInspectorDrawer
            open={inspectorOpen}
            target={inspectorTarget}
            onClose={() => setInspectorOpen(false)}
          />
        </div>
      </div>

      <UploadEncryptModal
        open={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        recipients={syncedRecipients}
        currentUser={user}
        onFileEncrypted={handleFileEncrypted}
      />

      <SecurityBackupModal
        open={securityModalOpen}
        user={user}
        onClose={() => setSecurityModalOpen(false)}
        onBackupDownloaded={(filename) =>
          appendActivity({
            category: 'security',
            title: `${user.name} downloaded encrypted key backup`,
            detail: `Saved passphrase-protected backup file (${filename}) to this device.`,
            status: 'success',
            statusLabel: 'Protected',
          })
        }
      />

      <ManageAccessModal
        file={manageAccessFile}
        currentUser={user}
        allRecipients={syncedRecipients}
        onClose={() => setManageAccessFile(null)}
        onSaveAccess={handleSaveFileAccess}
      />
    </div>
  );
}
