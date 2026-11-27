import React, { useEffect, useMemo, useState } from 'react';
import { FileUp, Loader2, Lock, ShieldCheck, X } from 'lucide-react';
import type { CryptoEnvelope, Recipient, UserProfile } from '../types/vault';
import { encryptPayloadWithWebCrypto, INSTITUTION_NAME } from '../utils/cryptoEngine';

interface UploadEncryptModalProps {
  open: boolean;
  onClose: () => void;
  recipients: Recipient[];
  currentUser: UserProfile;
  onUploadEncryptedFile: (payload: {
    filename: string;
    mimeType?: string;
    sizeBytes: number;
    recipientIds: string[];
    crypto: CryptoEnvelope;
  }) => Promise<void>;
}

export function UploadEncryptModal({
  open,
  onClose,
  recipients,
  currentUser,
  onUploadEncryptedFile,
}: UploadEncryptModalProps) {
  const [filename, setFilename] = useState('');
  const [selectedFileBytes, setSelectedFileBytes] = useState<Uint8Array | null>(null);
  const [selectedFileMime, setSelectedFileMime] = useState<string | undefined>(undefined);
  const [plaintextNote, setPlaintextNote] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Use ONLY real registered users returned by the backend API
  const registeredUsers = useMemo<Recipient[]>(() => {
    const mapped = recipients.map((r) =>
      r.id === currentUser.id
        ? {
            ...r,
            publicKey: currentUser.publicKey ?? r.publicKey,
            publicKeySpkiBase64: currentUser.publicKeySpkiBase64 ?? r.publicKeySpkiBase64,
          }
        : r
    );
    const hasSelf = mapped.some((r) => r.id === currentUser.id);
    if (!hasSelf) {
      mapped.unshift({
        id: currentUser.id,
        name: currentUser.name,
        email: currentUser.email,
        role: currentUser.role,
        department: currentUser.department,
        keyFingerprint: currentUser.keyFingerprint,
        publicKeySpkiBase64: currentUser.publicKeySpkiBase64,
        publicKey: currentUser.publicKey,
      });
    }
    // Sort current user first, then alphabetically by full name
    return mapped.sort((a, b) => {
      if (a.id === currentUser.id) return -1;
      if (b.id === currentUser.id) return 1;
      return a.name.localeCompare(b.name);
    });
  }, [recipients, currentUser]);

  const [selectedRecipientIds, setSelectedRecipientIds] = useState<string[]>([]);

  useEffect(() => {
    if (!open) return;
    // Default select current user so they can always decrypt their own upload
    setSelectedRecipientIds([currentUser.id]);
    setError(null);
  }, [open, currentUser.id]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isEncrypting) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, isEncrypting, onClose]);

  if (!open) return null;

  const toggleRecipient = (recipientId: string) => {
    setSelectedRecipientIds((prev) =>
      prev.includes(recipientId)
        ? prev.filter((id) => id !== recipientId)
        : [...prev, recipientId]
    );
    if (error) setError(null);
  };

  const handleFileInputChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const picked = event.target.files?.[0];
    if (!picked) return;
    const buffer = await picked.arrayBuffer();
    setFilename(picked.name);
    setSelectedFileBytes(new Uint8Array(buffer));
    setSelectedFileMime(picked.type || 'application/octet-stream');
    setError(null);
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const cleanedFilename = filename.trim();
    if (!cleanedFilename) {
      setError('Select a local file or enter a filename before encrypting.');
      return;
    }
    if (selectedRecipientIds.length === 0) {
      setError('Select at least one registered Student or Faculty recipient.');
      return;
    }

    const chosenRecipients = registeredUsers.filter((r) =>
      selectedRecipientIds.includes(r.id)
    );
    if (chosenRecipients.length === 0) {
      setError('No valid registered recipients selected.');
      return;
    }

    const fallbackNote =
      plaintextNote.trim() ||
      `Encrypted academic document "${cleanedFilename}" uploaded by ${currentUser.name} (${currentUser.role}).`;

    const plaintextBytes =
      selectedFileBytes && selectedFileBytes.byteLength > 0
        ? selectedFileBytes
        : new TextEncoder().encode(fallbackNote);

    const resolvedMime =
      selectedFileBytes && selectedFileBytes.byteLength > 0
        ? selectedFileMime || 'application/octet-stream'
        : 'text/plain;charset=utf-8';

    setIsEncrypting(true);
    setError(null);

    try {
      const now = new Date();
      const envelope = await encryptPayloadWithWebCrypto({
        plaintextBytes,
        recipients: chosenRecipients,
        encryptedAt: `${now.toISOString().replace('T', ' ').slice(0, 19)} UTC`,
      });

      await onUploadEncryptedFile({
        filename: cleanedFilename,
        mimeType: resolvedMime,
        sizeBytes: plaintextBytes.byteLength,
        recipientIds: chosenRecipients.map((r) => r.id),
        crypto: envelope,
      });

      setFilename('');
      setSelectedFileBytes(null);
      setSelectedFileMime(undefined);
      setPlaintextNote('');
      onClose();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Web Crypto encryption or upload failed. Please try again.'
      );
    } finally {
      setIsEncrypting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs"
      role="presentation"
      onClick={() => {
        if (!isEncrypting) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="upload-encrypt-title"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-xl max-h-[90vh] overflow-y-auto rounded-xl bg-[#111824] border border-slate-800 shadow-2xl"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800/90 flex items-center justify-between gap-4">
          <div>
            <h2
              id="upload-encrypt-title"
              className="font-display text-lg font-semibold text-slate-50"
            >
              Upload &amp; Encrypt Document
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Encrypted on your device with AES-256-GCM and locked with each recipient’s
              RSA-OAEP-2048 public key.
            </p>
          </div>
          <button
            type="button"
            disabled={isEncrypting}
            onClick={onClose}
            aria-label="Close Upload & Encrypt modal"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} noValidate className="p-6 space-y-5">
          {/* File selection */}
          <div>
            <label
              htmlFor="vault-upload-filename"
              className="block text-sm font-medium text-slate-200 mb-1.5"
            >
              Document Filename
            </label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                id="vault-upload-filename"
                type="text"
                value={filename}
                onChange={(e) => {
                  setFilename(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="e.g. Lab_Assignment_Report.pdf"
                className="flex-1 h-10 px-3.5 rounded-lg bg-[#0B0F17] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
              <label className="h-10 px-3.5 rounded-lg border border-slate-700 bg-slate-800/70 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors inline-flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap shrink-0">
                <FileUp className="h-4 w-4 text-blue-400" aria-hidden="true" />
                <span>Browse File</span>
                <input type="file" onChange={handleFileInputChange} className="sr-only" />
              </label>
            </div>
            {selectedFileBytes && (
              <p className="mt-1.5 text-xs font-mono text-emerald-400">
                Loaded {selectedFileBytes.byteLength.toLocaleString()} bytes locally for
                AES-256-GCM encryption.
              </p>
            )}
          </div>

          {/* Optional Plaintext Note */}
          <div>
            <label
              htmlFor="vault-upload-note"
              className="block text-sm font-medium text-slate-200 mb-1.5"
            >
              Plaintext Content / Abstract{' '}
              <span className="text-xs font-normal text-slate-500">
                (encrypted if no local file is attached)
              </span>
            </label>
            <textarea
              id="vault-upload-note"
              rows={3}
              value={plaintextNote}
              onChange={(e) => setPlaintextNote(e.target.value)}
              placeholder="Enter document text to encrypt locally with AES-256-GCM..."
              className="w-full px-3.5 py-2.5 rounded-lg bg-[#0B0F17] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 resize-none"
            />
          </div>

          {/* Multi-Recipient Checkboxes (Strictly Real Registered Users) */}
          <div>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm font-medium text-slate-200">
                Registered Recipients ({selectedRecipientIds.length} selected)
              </span>
              <div className="flex items-center gap-3 text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setSelectedRecipientIds(registeredUsers.map((r) => r.id));
                    if (error) setError(null);
                  }}
                  className="text-blue-400 hover:text-blue-300 font-medium whitespace-nowrap"
                >
                  Select All
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedRecipientIds([])}
                  className="text-slate-400 hover:text-slate-200 font-medium whitespace-nowrap"
                >
                  Clear
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0B0F17] divide-y divide-slate-800/80 max-h-64 overflow-y-auto">
              {registeredUsers.map((recipient) => {
                const checked = selectedRecipientIds.includes(recipient.id);
                const isSelf = recipient.id === currentUser.id;
                return (
                  <label
                    key={recipient.id}
                    className={`flex items-center justify-between gap-3 px-3.5 py-2.5 cursor-pointer transition-colors ${
                      checked ? 'bg-blue-600/10' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleRecipient(recipient.id)}
                        className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                      />
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-slate-100 truncate">
                          {recipient.name}
                          {isSelf && (
                            <span className="ml-1.5 text-xs font-normal text-blue-400">
                              (You)
                            </span>
                          )}
                        </p>
                        <p className="text-xs text-slate-400 truncate">{recipient.email}</p>
                      </div>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[11px] font-medium rounded border shrink-0 ${
                        recipient.role === 'Faculty'
                          ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                          : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                      }`}
                    >
                      {recipient.role}
                    </span>
                  </label>
                );
              })}
            </div>

            {registeredUsers.length === 1 && (
              <p className="mt-2 text-xs text-slate-500">
                Other {INSTITUTION_NAME} students and faculty will appear here once they
                create an account.
              </p>
            )}
          </div>

          {/* Encryption Pipeline Summary */}
          <div className="flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-lg bg-[#0E1420] border border-slate-800/80 text-xs text-slate-400">
            <span className="flex items-center gap-2 text-slate-300">
              <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
              <span>End-to-end encrypted in your browser</span>
            </span>
            <span className="tabular-nums text-slate-300 shrink-0">
              Shared with {selectedRecipientIds.length}{' '}
              {selectedRecipientIds.length === 1 ? 'person' : 'people'}
            </span>
          </div>

          {error && (
            <p role="alert" className="text-xs text-rose-400">
              {error}
            </p>
          )}

          {/* Footer actions */}
          <div className="pt-2 flex items-center justify-end gap-2.5">
            <button
              type="button"
              disabled={isEncrypting}
              onClick={onClose}
              className="h-10 px-4 rounded-lg border border-slate-700 text-sm font-medium text-slate-300 hover:text-slate-100 hover:bg-slate-800 transition-colors whitespace-nowrap"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isEncrypting}
              className="h-10 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:bg-blue-700/60 disabled:cursor-wait text-sm font-medium text-white transition-colors inline-flex items-center gap-2 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
            >
              {isEncrypting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  <span>Encrypting &amp; Uploading…</span>
                </>
              ) : (
                <>
                  <Lock className="h-4 w-4" aria-hidden="true" />
                  <span>Encrypt &amp; Upload</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
