import { useEffect, useMemo, useState } from 'react';
import { Loader2, ShieldAlert, UserCheck, UserMinus, Users, X } from 'lucide-react';
import type { Recipient, UserProfile, VaultFile } from '../types/vault';

interface ManageAccessModalProps {
  file: VaultFile | null;
  currentUser: UserProfile;
  allRecipients: Recipient[];
  onClose: () => void;
  onSaveAccess: (file: VaultFile, retainedRecipientIds: string[]) => Promise<void>;
}

export function ManageAccessModal({
  file,
  currentUser,
  allRecipients,
  onClose,
  onSaveAccess,
}: ManageAccessModalProps) {
  const [retainedIds, setRetainedIds] = useState<string[]>([]);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const initialAuthorizedIds = useMemo(() => {
    if (!file) return [];
    if (file.recipientIds && file.recipientIds.length > 0) {
      return file.recipientIds;
    }
    return file.crypto.wrappedKeys.map((wk) => wk.recipientId);
  }, [file]);

  useEffect(() => {
    if (!file) return;
    setRetainedIds(initialAuthorizedIds);
    setError(null);
  }, [file, initialAuthorizedIds]);

  useEffect(() => {
    if (!file) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isSaving) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [file, isSaving, onClose]);

  if (!file) return null;

  const isOwnerRow = (recipientId: string) => recipientId === currentUser.id;

  const toggleAccess = (recipientId: string) => {
    setError(null);
    if (isOwnerRow(recipientId)) {
      setError('You cannot revoke your own uploader access from this document.');
      return;
    }
    setRetainedIds((prev) =>
      prev.includes(recipientId)
        ? prev.filter((id) => id !== recipientId)
        : [...prev, recipientId]
    );
  };

  const revokedCount = initialAuthorizedIds.filter((id) => !retainedIds.includes(id)).length;
  const hasChanges =
    revokedCount > 0 || retainedIds.some((id) => !initialAuthorizedIds.includes(id));

  const recipientById = new Map(allRecipients.map((r) => [r.id, r]));
  const otherRegisteredUsers = allRecipients.filter(
    (r) => !initialAuthorizedIds.includes(r.id)
  );

  const handleSave = async () => {
    if (retainedIds.length === 0) {
      setError('At least one person must retain access to this file.');
      return;
    }
    setIsSaving(true);
    setError(null);
    try {
      await onSaveAccess(file, retainedIds);
      onClose();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to save access changes right now.'
      );
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs"
      role="presentation"
      onClick={() => {
        if (!isSaving) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="manage-access-title"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-xl bg-[#111824] border border-slate-800 shadow-2xl"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800/90 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-300 shrink-0">
              <Users className="h-4 w-4" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <h2
                id="manage-access-title"
                className="font-display text-lg font-semibold text-slate-50 truncate"
              >
                Manage &amp; Revoke Access
              </h2>
              <p className="text-xs text-slate-400 truncate" title={file.filename}>
                {file.filename}
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={isSaving}
            onClick={onClose}
            aria-label="Close Manage Access modal"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          <p className="text-xs text-slate-400 leading-relaxed">
            Revoking a person immediately removes their RSA-wrapped decryption key from this
            document. Granting access wraps the file key using their registered RSA-2048 public
            key.
          </p>

          {/* Current File Recipients */}
          <div>
            <h3 className="text-xs font-medium text-slate-400 mb-2">
              Authorized People ({retainedIds.length} active)
            </h3>
            <div className="rounded-lg border border-slate-800 bg-[#0B0F17] divide-y divide-slate-800/80">
              {initialAuthorizedIds.map((recipientId) => {
                const info = recipientById.get(recipientId);
                const fallbackKey = file.crypto.wrappedKeys.find(
                  (wk) => wk.recipientId === recipientId
                );
                const displayName = info?.name ?? fallbackKey?.recipientName ?? 'Registered Member';
                const displayRole = info?.role ?? fallbackKey?.recipientRole ?? 'Student';
                const isRetained = retainedIds.includes(recipientId);
                const isOwner = isOwnerRow(recipientId);

                return (
                  <div
                    key={recipientId}
                    className="px-3.5 py-2.5 flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p
                          className={`text-sm font-medium truncate ${
                            isRetained ? 'text-slate-100' : 'text-slate-500 line-through'
                          }`}
                        >
                          {displayName}
                        </p>
                        <span
                          className={`px-1.5 py-0.5 text-[10px] font-medium rounded border shrink-0 ${
                            displayRole === 'Faculty'
                              ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                          }`}
                        >
                          {displayRole}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 truncate">
                        {isOwner
                          ? `File owner · ${info?.email ?? currentUser.email}`
                          : info?.email ?? 'Registered Campus Member'}
                      </p>
                    </div>

                    {isOwner ? (
                      <span className="text-xs font-medium text-slate-500 whitespace-nowrap">
                        Owner
                      </span>
                    ) : isRetained ? (
                      <button
                        type="button"
                        disabled={isSaving}
                        onClick={() => toggleAccess(recipientId)}
                        aria-label={`Revoke access for ${displayName}`}
                        className="h-8 px-2.5 rounded-md border border-rose-500/35 bg-rose-950/35 hover:bg-rose-950/60 text-xs font-medium text-rose-300 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
                      >
                        <UserMinus className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Revoke</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={isSaving}
                        onClick={() => toggleAccess(recipientId)}
                        aria-label={`Restore access for ${displayName}`}
                        className="h-8 px-2.5 rounded-md border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
                      >
                        <UserCheck className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                        <span>Restore</span>
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Grant Access to Other Registered Campus Users */}
          {otherRegisteredUsers.length > 0 && (
            <div>
              <h3 className="text-xs font-medium text-slate-400 mb-2">
                Add Other Registered Users
              </h3>
              <div className="rounded-lg border border-slate-800 bg-[#0B0F17] divide-y divide-slate-800/80 max-h-44 overflow-y-auto">
                {otherRegisteredUsers.map((recipient) => {
                  const isAdded = retainedIds.includes(recipient.id);
                  return (
                    <div
                      key={recipient.id}
                      className="px-3.5 py-2.5 flex items-center justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium text-slate-200 truncate">
                            {recipient.name}
                          </p>
                          <span
                            className={`px-1.5 py-0.5 text-[10px] font-medium rounded border shrink-0 ${
                              recipient.role === 'Faculty'
                                ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                                : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                            }`}
                          >
                            {recipient.role}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 truncate">{recipient.email}</p>
                      </div>
                      <button
                        type="button"
                        disabled={isSaving}
                        onClick={() => toggleAccess(recipient.id)}
                        className={`h-8 px-2.5 rounded-md border text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                          isAdded
                            ? 'border-emerald-500/35 bg-emerald-950/35 text-emerald-300'
                            : 'border-slate-700 bg-slate-800/70 hover:bg-slate-700 text-slate-200'
                        }`}
                      >
                        {isAdded ? 'Added' : 'Grant Access'}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {revokedCount > 0 && (
            <div className="flex items-start gap-2.5 px-3.5 py-2.5 rounded-lg bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200">
              <ShieldAlert className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" aria-hidden="true" />
              <span>
                {revokedCount} {revokedCount === 1 ? 'person' : 'people'} will immediately lose
                decryption access once saved.
              </span>
            </div>
          )}

          {error && (
            <p role="alert" className="text-xs text-rose-400">
              {error}
            </p>
          )}

          <div className="pt-1 flex items-center justify-end gap-2.5">
            <button
              type="button"
              disabled={isSaving}
              onClick={onClose}
              className="h-9 px-4 rounded-lg border border-slate-700 text-xs font-medium text-slate-300 hover:text-slate-100 hover:bg-slate-800 transition-colors whitespace-nowrap"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={!hasChanges || isSaving}
              onClick={() => void handleSave()}
              className="h-9 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-xs font-medium text-white transition-colors inline-flex items-center gap-1.5 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
            >
              {isSaving ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  <span>Updating Keys…</span>
                </>
              ) : (
                <span>Save Access Changes</span>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
