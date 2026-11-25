import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Download,
  KeyRound,
  Lock,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { UserProfile } from '../types/vault';
import {
  buildEncryptedKeyBackupPayload,
  INSTITUTION_NAME,
} from '../utils/cryptoEngine';

interface SecurityBackupModalProps {
  open: boolean;
  user: UserProfile;
  onClose: () => void;
  onBackupDownloaded: (filename: string) => void;
}

export function SecurityBackupModal({
  open,
  user,
  onClose,
  onBackupDownloaded,
}: SecurityBackupModalProps) {
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setStatusMessage(null);
    setErrorMessage(null);
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const isKeyReady = Boolean(user.protectedPrivateKey && user.privateKey);

  const handleDownloadBackup = () => {
    setErrorMessage(null);
    try {
      const payload = buildEncryptedKeyBackupPayload(user);
      const safeHandle = user.email.split('@')[0].replace(/[^a-z0-9_-]/gi, '_') || 'vault';
      const filename = `cipherhall-key-backup-${safeHandle}.json`;
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: 'application/json;charset=utf-8',
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      setStatusMessage(
        `Saved ${filename} to your device. Keep it alongside your Vault Passphrase in a safe place.`
      );
      onBackupDownloaded(filename);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Unable to export key backup right now.'
      );
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs"
      role="presentation"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-backup-title"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-xl bg-[#111824] border border-slate-800 shadow-2xl"
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800/90 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
              <KeyRound className="h-4 w-4" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <h2
                id="security-backup-title"
                className="font-display text-lg font-semibold text-slate-50 truncate"
              >
                My Security &amp; Key Backup
              </h2>
              <p className="text-xs text-slate-400 truncate">{INSTITUTION_NAME}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close My Security & Key Backup modal"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Active Protection Summary */}
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/20 p-4 flex items-start gap-3">
            <ShieldCheck
              className="h-5 w-5 text-emerald-400 mt-0.5 shrink-0"
              aria-hidden="true"
            />
            <div className="space-y-1">
              <p className="text-sm font-medium text-emerald-200">
                Active Device-Side Encryption Enabled
              </p>
              <p className="text-xs text-slate-300 leading-relaxed">
                Your personal RSA-2048 private key is unlocked locally in this browser session
                and protected by your Vault Passphrase. No unencrypted key or file ever leaves
                your device.
              </p>
            </div>
          </div>

          {/* Clear Protection Rows */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0B0F17] divide-y divide-slate-800/80 text-sm">
            <div className="px-4 py-3 flex items-center justify-between gap-4">
              <div>
                <p className="font-medium text-slate-200">Personal Key Pair</p>
                <p className="text-xs text-slate-400">Used to unlock shared files and chats</p>
              </div>
              <span className="px-2.5 py-1 rounded border border-emerald-500/30 bg-emerald-950/40 text-xs font-medium text-emerald-300 whitespace-nowrap">
                RSA-2048 Active
              </span>
            </div>

            <div className="px-4 py-3 flex items-center justify-between gap-4">
              <div>
                <p className="font-medium text-slate-200">File &amp; Message Encryption</p>
                <p className="text-xs text-slate-400">
                  Fresh key created automatically per document
                </p>
              </div>
              <span className="px-2.5 py-1 rounded border border-emerald-500/30 bg-emerald-950/40 text-xs font-medium text-emerald-300 whitespace-nowrap">
                AES-256 Active
              </span>
            </div>

            <div className="px-4 py-3 flex items-center justify-between gap-4">
              <div>
                <p className="font-medium text-slate-200">Passphrase Key Lock</p>
                <p className="text-xs text-slate-400">
                  Private key backup stays encrypted on export
                </p>
              </div>
              <span className="px-2.5 py-1 rounded border border-blue-500/30 bg-blue-950/40 text-xs font-medium text-blue-300 whitespace-nowrap">
                Passphrase Locked
              </span>
            </div>

            <div className="px-4 py-3 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <p className="font-medium text-slate-200 truncate">{user.name}</p>
                  <span
                    className={`px-2 py-0.5 text-[11px] font-medium rounded border shrink-0 ${
                      user.role === 'Faculty'
                        ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                        : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                    }`}
                  >
                    {user.role} Account
                  </span>
                </div>
                <p className="text-xs text-slate-400 truncate mt-0.5">
                  {user.email} · {user.department}
                </p>
              </div>
              <span className="text-xs text-slate-400 whitespace-nowrap shrink-0">
                Unlocked at {user.vaultUnlockedAt}
              </span>
            </div>
          </div>

          {/* Backup Guidance & Download */}
          <div className="rounded-xl border border-slate-800/90 bg-[#0E1420] p-4 space-y-3">
            <div className="flex items-start gap-2.5">
              <Lock className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" aria-hidden="true" />
              <div className="space-y-1">
                <h3 className="text-sm font-medium text-slate-100">
                  Encrypted Key Backup
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Download a passphrase-protected backup file so you can recover access to your
                  vault if you switch laptops or clear browser storage.
                </p>
              </div>
            </div>

            <button
              type="button"
              disabled={!isKeyReady}
              onClick={handleDownloadBackup}
              className="w-full h-10 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:bg-slate-800 disabled:text-slate-500 text-sm font-medium text-white transition-colors inline-flex items-center justify-center gap-2 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
            >
              <Download className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>Download Encrypted Key Backup (.json)</span>
            </button>
          </div>

          {statusMessage && (
            <div
              role="status"
              className="flex items-start gap-2.5 px-3.5 py-3 rounded-lg bg-emerald-950/35 border border-emerald-500/30 text-xs text-emerald-200"
            >
              <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" aria-hidden="true" />
              <span>{statusMessage}</span>
            </div>
          )}

          {errorMessage && (
            <p role="alert" className="text-xs text-rose-400">
              {errorMessage}
            </p>
          )}

          <div className="flex justify-end pt-1">
            <button
              type="button"
              onClick={onClose}
              className="h-9 px-4 rounded-lg border border-slate-700 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
