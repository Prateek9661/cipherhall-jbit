import { useCallback, useEffect, useMemo, useState } from 'react';
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
  fetchActivityLogApi,
  fetchEncryptedMessagesApi,
  fetchRegisteredUsersApi,
  fetchVaultFilesApi,
  recordActivityEventApi,
  sendEncryptedMessageApi,
  updateFileAccessApi,
  uploadEncryptedFileApi,
} from './services/vaultApi';
import type {
  ActivityCategory,
  ActivityEvent,
  ChatMessage,
  ChatThread,
  CryptoEnvelope,
  InspectorTarget,
  Recipient,
  StoredEncryptedMessageDTO,
  UserProfile,
  VaultFile,
  WorkspaceView,
} from './types/vault';
import {
  decryptPayloadWithWebCrypto,
  encryptPayloadWithWebCrypto,
  rewrapAesKeyForRecipients,
} from './utils/cryptoEngine';

async function decryptStoredMessages(
  stored: StoredEncryptedMessageDTO[],
  currentUser: UserProfile
): Promise<ChatMessage[]> {
  const decoder = new TextDecoder();
  return Promise.all(
    stored.map(async (msg) => {
      const peerId = msg.senderId === currentUser.id ? msg.recipientId : msg.senderId;
      let plaintext = 'Encrypted message (unlock key required)';
      if (currentUser.privateKey) {
        try {
          const result = await decryptPayloadWithWebCrypto({
            envelope: msg.crypto,
            privateKey: currentUser.privateKey,
            recipientId: currentUser.id,
            recipientFingerprint: currentUser.keyFingerprint,
          });
          plaintext = decoder.decode(result.plaintextBytes);
        } catch {
          plaintext = 'Unable to decrypt message with your current private key.';
        }
      }

      return {
        id: msg.id,
        threadId: peerId,
        senderId: msg.senderId,
        senderName: msg.senderName,
        senderRole: msg.senderRole,
        text: plaintext,
        timestamp: msg.timestamp,
        isCurrentUser: msg.senderId === currentUser.id,
        attachedFile: msg.attachedFile,
        crypto: msg.crypto,
      };
    })
  );
}

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [registeredUsers, setRegisteredUsers] = useState<Recipient[]>([]);
  const [activeView, setActiveView] = useState<WorkspaceView>('vault');
  const [files, setFiles] = useState<VaultFile[]>([]);
  const [decryptedMessages, setDecryptedMessages] = useState<ChatMessage[]>([]);
  const [activeThreadId, setActiveThreadId] = useState<string | null>(null);
  const [activityLog, setActivityLog] = useState<ActivityEvent[]>([]);
  const [inspectorOpen, setInspectorOpen] = useState<boolean>(false);
  const [inspectorTarget, setInspectorTarget] = useState<InspectorTarget | null>(null);
  const [uploadModalOpen, setUploadModalOpen] = useState<boolean>(false);
  const [securityModalOpen, setSecurityModalOpen] = useState<boolean>(false);
  const [manageAccessFile, setManageAccessFile] = useState<VaultFile | null>(null);
  const [vaultNotice, setVaultNotice] = useState<{
    state: 'success' | 'error';
    message: string;
  } | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState<boolean>(false);

  const syncWorkspaceData = useCallback(
    async (token: string, currentUser: UserProfile) => {
      try {
        const [usersList, filesList, rawMessages, eventsList] = await Promise.all([
          fetchRegisteredUsersApi(token),
          fetchVaultFilesApi(token),
          fetchEncryptedMessagesApi(token),
          fetchActivityLogApi(token),
        ]);

        setRegisteredUsers(usersList);
        setFiles(filesList);
        setActivityLog(eventsList);

        const messages = await decryptStoredMessages(rawMessages, currentUser);
        setDecryptedMessages(messages);

        setInspectorTarget((prev) => {
          if (prev) return prev;
          if (filesList.length > 0) return { kind: 'file', file: filesList[0] };
          return null;
        });
      } catch (err) {
        setVaultNotice({
          state: 'error',
          message:
            err instanceof Error
              ? err.message
              : 'Unable to load encrypted workspace data from the server.',
        });
      }
    },
    []
  );

  // Refresh workspace data when user switches views or opens recipient modals
  useEffect(() => {
    if (!authToken || !user) return;
    void syncWorkspaceData(authToken, user);
  }, [authToken, user, activeView, uploadModalOpen, manageAccessFile, syncWorkspaceData]);

  // Build 1-on-1 chat threads strictly from real registered users (excluding current user)
  const chatThreads = useMemo<ChatThread[]>(() => {
    if (!user) return [];
    const peers = registeredUsers.filter((u) => u.id !== user.id);

    const messagesByPeer = new Map<string, ChatMessage[]>();
    for (const msg of decryptedMessages) {
      const list = messagesByPeer.get(msg.threadId) ?? [];
      list.push(msg);
      messagesByPeer.set(msg.threadId, list);
    }

    return peers.map((peer) => {
      const peerMessages = messagesByPeer.get(peer.id) ?? [];
      const latest = peerMessages[peerMessages.length - 1];
      return {
        id: peer.id,
        title: peer.name,
        type: 'direct',
        subtitle: `${peer.role} · ${peer.department}`,
        participantEmail: peer.email,
        participantRole: peer.role,
        memberCount: 2,
        recipientIds: [user.id, peer.id],
        unreadCount: 0,
        lastActivity: latest?.timestamp ?? '',
        messages: peerMessages,
      };
    });
  }, [registeredUsers, decryptedMessages, user]);

  useEffect(() => {
    if (chatThreads.length === 0) {
      setActiveThreadId(null);
      return;
    }
    setActiveThreadId((prev) =>
      prev && chatThreads.some((t) => t.id === prev) ? prev : chatThreads[0].id
    );
  }, [chatThreads]);

  const activeThread = useMemo(
    () =>
      (activeThreadId ? chatThreads.find((t) => t.id === activeThreadId) : undefined) ??
      chatThreads[0] ??
      null,
    [chatThreads, activeThreadId]
  );

  const recordClientActivity = async (params: {
    category: ActivityCategory;
    title: string;
    detail: string;
    status?: 'info' | 'success' | 'warning';
    statusLabel?: string;
  }) => {
    if (!authToken) return;
    try {
      const event = await recordActivityEventApi(authToken, params);
      setActivityLog((prev) => [event, ...prev]);
    } catch {
      // Non-blocking audit log recording
    }
  };

  const handleAuthenticated = (session: { user: UserProfile; token: string }) => {
    setUser(session.user);
    setAuthToken(session.token);
    setActiveView('vault');
    setFiles([]);
    setDecryptedMessages([]);
    setRegisteredUsers([]);
    setActivityLog([]);
    setActiveThreadId(null);
    setInspectorTarget(null);
    setInspectorOpen(false);
    setVaultNotice(null);
  };

  const handleSignOut = () => {
    setUser(null);
    setAuthToken(null);
    setRegisteredUsers([]);
    setFiles([]);
    setDecryptedMessages([]);
    setActivityLog([]);
    setActiveThreadId(null);
    setInspectorTarget(null);
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

  const handleUploadEncryptedFile = async (payload: {
    filename: string;
    mimeType?: string;
    sizeBytes: number;
    recipientIds: string[];
    crypto: CryptoEnvelope;
  }) => {
    if (!authToken || !user) {
      throw new Error('Your session has expired. Please sign in again.');
    }
    const storedFile = await uploadEncryptedFileApi(authToken, payload);
    setFiles((prev) => [storedFile, ...prev]);
    setInspectorTarget({ kind: 'file', file: storedFile });
    setVaultNotice({
      state: 'success',
      message: `Encrypted & uploaded ${storedFile.filename} for ${storedFile.recipients.length} ${
        storedFile.recipients.length === 1 ? 'person' : 'people'
      }.`,
    });
    const events = await fetchActivityLogApi(authToken).catch(() => null);
    if (events) setActivityLog(events);
  };

  const handleSaveFileAccess = async (
    file: VaultFile,
    retainedRecipientIds: string[]
  ) => {
    if (!authToken || !user || !user.privateKey) {
      throw new Error('Unable to update file keys without an active unlocked private key.');
    }

    const targetRecipients = registeredUsers
      .filter((r) => retainedRecipientIds.includes(r.id))
      .map((r) =>
        r.id === user.id
          ? {
              ...r,
              publicKey: user.publicKey ?? r.publicKey,
              publicKeySpkiBase64: user.publicKeySpkiBase64 ?? r.publicKeySpkiBase64,
            }
          : r
      );

    const rewrappedKeys = await rewrapAesKeyForRecipients({
      envelope: file.crypto,
      ownerPrivateKey: user.privateKey,
      ownerRecipientId: user.id,
      ownerFingerprint: user.keyFingerprint,
      targetRecipients,
    });

    const result = await updateFileAccessApi(authToken, file.id, {
      recipientIds: retainedRecipientIds,
      wrappedKeys: rewrappedKeys,
    });

    setFiles((prev) => prev.map((f) => (f.id === file.id ? result.file : f)));
    if (inspectorTarget?.kind === 'file' && inspectorTarget.file.id === file.id) {
      setInspectorTarget({ kind: 'file', file: result.file });
    }

    const parts: string[] = [];
    if (result.revokedNames.length > 0) {
      parts.push(`Revoked access for ${result.revokedNames.join(', ')}`);
    }
    if (result.addedNames.length > 0) {
      parts.push(`Granted access to ${result.addedNames.join(', ')}`);
    }
    const summary = parts.join(' and ') || 'Updated file access';

    setVaultNotice({
      state: 'success',
      message: `${summary} on ${file.filename}.`,
    });

    const events = await fetchActivityLogApi(authToken).catch(() => null);
    if (events) setActivityLog(events);
  };

  const handleSelectThread = (threadId: string) => {
    setActiveThreadId(threadId);
    const chosen = chatThreads.find((t) => t.id === threadId);
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
    if (!user || !authToken) return;
    const peer = registeredUsers.find((u) => u.id === threadId);
    if (!peer) {
      throw new Error('Selected contact is no longer available.');
    }

    const selfRecipient: Recipient = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      department: user.department,
      keyFingerprint: user.keyFingerprint,
      publicKeySpkiBase64: user.publicKeySpkiBase64,
      publicKey: user.publicKey,
    };

    const now = new Date();
    const messageBytes = new TextEncoder().encode(text);
    const envelope = await encryptPayloadWithWebCrypto({
      plaintextBytes: messageBytes,
      recipients: [selfRecipient, peer],
      encryptedAt: `${now.toISOString().replace('T', ' ').slice(0, 19)} UTC`,
    });

    const storedMsg = await sendEncryptedMessageApi(authToken, {
      recipientId: peer.id,
      attachedFile: attachedFile
        ? {
            fileId: attachedFile.id,
            filename: attachedFile.filename,
            sizeBytes: attachedFile.sizeBytes,
            sha256Status: attachedFile.sha256Status,
          }
        : undefined,
      crypto: envelope,
    });

    const newMessage: ChatMessage = {
      id: storedMsg.id,
      threadId: peer.id,
      senderId: storedMsg.senderId,
      senderName: storedMsg.senderName,
      senderRole: storedMsg.senderRole,
      text,
      timestamp: storedMsg.timestamp,
      isCurrentUser: true,
      attachedFile: storedMsg.attachedFile,
      crypto: storedMsg.crypto,
    };

    setDecryptedMessages((prev) => [...prev, newMessage]);
    setInspectorTarget({
      kind: 'message',
      message: newMessage,
      threadTitle: peer.name,
    });

    const events = await fetchActivityLogApi(authToken).catch(() => null);
    if (events) setActivityLog(events);
  };

  const handleDownloadVaultFileFromChat = async (
    fileId: string
  ): Promise<{ state: 'success' | 'error'; message: string } | void> => {
    if (!user || !user.privateKey) return;
    const targetFile = files.find((f) => f.id === fileId);
    if (!targetFile) {
      return {
        state: 'error',
        message: 'This file is not currently shared with your account.',
      };
    }

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
      await recordClientActivity({
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
      const errMsg = err instanceof Error ? err.message : 'Integrity verification failed.';
      await recordClientActivity({
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

  if (!user || !authToken) {
    return <AuthScreen onAuthenticated={handleAuthenticated} />;
  }

  return (
    <div className="h-screen overflow-hidden bg-[#0B0F17] text-slate-100 flex">
      <SidebarNav
        user={user}
        activeView={activeView}
        onSelectView={handleSelectView}
        fileCount={files.length}
        unreadChatCount={0}
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
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
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
                onDecryptActivity={({ file, success, detail }) => {
                  void recordClientActivity({
                    category: success ? 'file' : 'security',
                    title: success
                      ? `${user.name} decrypted & verified ${file.filename}`
                      : `Integrity alert blocked ${file.filename}`,
                    detail,
                    status: success ? 'success' : 'warning',
                    statusLabel: success ? 'Verified' : 'Integrity Alert',
                  });
                }}
              />
            )}

            {activeView === 'chat' && (
              <EncryptedChat
                threads={chatThreads}
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
        recipients={registeredUsers}
        currentUser={user}
        onUploadEncryptedFile={handleUploadEncryptedFile}
      />

      <SecurityBackupModal
        open={securityModalOpen}
        user={user}
        onClose={() => setSecurityModalOpen(false)}
        onBackupDownloaded={(filename) => {
          void recordClientActivity({
            category: 'security',
            title: `${user.name} downloaded encrypted key backup`,
            detail: `Saved passphrase-protected backup file (${filename}) to this device.`,
            status: 'success',
            statusLabel: 'Protected',
          });
        }}
      />

      <ManageAccessModal
        file={manageAccessFile}
        currentUser={user}
        allRecipients={registeredUsers}
        onClose={() => setManageAccessFile(null)}
        onSaveAccess={handleSaveFileAccess}
      />
    </div>
  );
}
