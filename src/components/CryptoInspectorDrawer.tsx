import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Binary,
  Check,
  CheckCircle2,
  Copy,
  FileText,
  KeyRound,
  MessageSquareLock,
  X,
} from 'lucide-react';
import type { InspectorTarget } from '../types/vault';
import { formatHexSpaced } from '../utils/cryptoEngine';

interface CryptoInspectorDrawerProps {
  open: boolean;
  target: InspectorTarget | null;
  onClose: () => void;
}

export function CryptoInspectorDrawer({
  open,
  target,
  onClose,
}: CryptoInspectorDrawerProps) {
  const [selectedRecipientIndex, setSelectedRecipientIndex] = useState(0);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const targetId =
    target?.kind === 'file' ? target.file.id : target?.kind === 'message' ? target.message.id : null;

  useEffect(() => {
    setSelectedRecipientIndex(0);
    setCopiedField(null);
  }, [targetId]);

  if (!open) return null;

  const handleCopy = async (field: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      window.setTimeout(() => {
        setCopiedField((prev) => (prev === field ? null : prev));
      }, 1600);
    } catch {
      setCopiedField(field);
    }
  };

  const crypto = target
    ? target.kind === 'file'
      ? target.file.crypto
      : target.message.crypto
    : null;

  const wrappedKeys = crypto?.wrappedKeys ?? [];
  const activeWrappedKey =
    wrappedKeys[Math.min(selectedRecipientIndex, Math.max(0, wrappedKeys.length - 1))];

  const hashMatches = crypto ? crypto.sha256Hash === crypto.expectedSha256Hash : true;

  return (
    <aside
      aria-label="Live Crypto Inspector"
      className="fixed inset-y-0 right-0 z-30 w-full max-w-[360px] xl:static xl:w-[344px] xl:shrink-0 bg-[#0E1420] border-l border-slate-800/80 flex flex-col h-screen xl:h-full shadow-2xl xl:shadow-none"
    >
      {/* Drawer Header */}
      <div className="px-5 py-3.5 border-b border-slate-800/80 flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <Binary className="h-4 w-4 text-blue-400 shrink-0" aria-hidden="true" />
          <h2 className="font-display text-sm font-semibold text-slate-100 truncate">
            Live Crypto Inspector
          </h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close Crypto Inspector"
          className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {!target || !crypto ? (
        <div className="flex-1 flex flex-col items-center justify-center px-6 text-center">
          <Binary className="h-8 w-8 text-slate-600" aria-hidden="true" />
          <p className="mt-3 text-sm font-medium text-slate-300">No payload selected</p>
          <p className="mt-1 text-xs text-slate-500">
            Select a file in the Document Vault or a message in Encrypted Chat to inspect its
            live cryptographic envelope.
          </p>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Selected Payload Summary */}
          <div className="pb-4 border-b border-slate-800/80">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              {target.kind === 'file' ? (
                <FileText className="h-3.5 w-3.5 text-blue-400 shrink-0" aria-hidden="true" />
              ) : (
                <MessageSquareLock
                  className="h-3.5 w-3.5 text-blue-400 shrink-0"
                  aria-hidden="true"
                />
              )}
              <span>
                {target.kind === 'file' ? 'Encrypted File' : `Message · ${target.threadTitle}`}
              </span>
            </div>
            <p className="mt-1.5 text-sm font-semibold text-slate-100 break-words">
              {target.kind === 'file' ? target.file.filename : target.message.senderName}
            </p>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-400 font-mono">
              <span>{crypto.algorithm}</span>
              <span aria-hidden="true" className="text-slate-600">
                ·
              </span>
              <span>{crypto.keyWrapAlgorithm}</span>
              <span aria-hidden="true" className="text-slate-600">
                ·
              </span>
              <span className={crypto.isWebCryptoReal ? 'text-emerald-400' : 'text-slate-500'}>
                {crypto.isWebCryptoReal ? 'Web Crypto' : 'Seeded Demo'}
              </span>
            </div>
          </div>

          {/* 1. 12-Byte IV / Nonce */}
          <section className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-slate-200">
                12-Byte IV / Nonce (96-bit)
              </h3>
              <button
                type="button"
                onClick={() => handleCopy('iv', crypto.ivHex)}
                aria-label="Copy 12-byte IV"
                className="text-xs text-slate-400 hover:text-slate-100 inline-flex items-center gap-1 transition-colors"
              >
                {copiedField === 'iv' ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" aria-hidden="true" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <div className="rounded-lg bg-[#0B0F17] border border-slate-800/90 p-3 space-y-2">
              <div>
                <p className="text-[11px] text-slate-500">Hex (12 bytes)</p>
                <p
                  data-testid="inspector-iv-hex"
                  className="mt-0.5 font-mono text-xs text-blue-300 break-all leading-relaxed"
                >
                  {formatHexSpaced(crypto.ivHex)}
                </p>
              </div>
              <div className="pt-2 border-t border-slate-800/70 flex items-center justify-between gap-2 text-[11px]">
                <span className="text-slate-500">Base64</span>
                <span className="font-mono text-slate-300">{crypto.ivBase64}</span>
              </div>
            </div>
          </section>

          {/* 2. Live Base64 Ciphertext Preview */}
          <section className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-slate-200">
                Base64 Ciphertext Preview
              </h3>
              <button
                type="button"
                onClick={() => handleCopy('ciphertext', crypto.ciphertextBase64)}
                aria-label="Copy Base64 ciphertext"
                className="text-xs text-slate-400 hover:text-slate-100 inline-flex items-center gap-1 transition-colors"
              >
                {copiedField === 'ciphertext' ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" aria-hidden="true" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <div className="rounded-lg bg-[#0B0F17] border border-slate-800/90 p-3">
              <pre
                data-testid="inspector-ciphertext"
                className="font-mono text-[11px] text-slate-300 whitespace-pre-wrap break-all leading-relaxed max-h-32 overflow-y-auto"
              >
                {crypto.ciphertextBase64}
              </pre>
              <div className="mt-2.5 pt-2 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono text-slate-500">
                <span>GCM Tag {crypto.authTagHex.slice(0, 12)}…</span>
                <span className="tabular-nums">{crypto.ciphertextByteLength} B ciphertext</span>
              </div>
            </div>
          </section>

          {/* 3. SHA-256 File / Payload Hash */}
          <section className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-slate-200">
                SHA-256 {target.kind === 'file' ? 'File Hash' : 'Payload Digest'}
              </h3>
              <button
                type="button"
                onClick={() => handleCopy('sha256', crypto.sha256Hash)}
                aria-label="Copy SHA-256 hash"
                className="text-xs text-slate-400 hover:text-slate-100 inline-flex items-center gap-1 transition-colors"
              >
                {copiedField === 'sha256' ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" aria-hidden="true" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <div className="rounded-lg bg-[#0B0F17] border border-slate-800/90 p-3 space-y-2">
              <p
                data-testid="inspector-sha256"
                className="font-mono text-[11px] text-slate-200 break-all leading-relaxed"
              >
                {crypto.sha256Hash}
              </p>
              <div className="pt-2 border-t border-slate-800/70 flex items-center gap-1.5 text-xs">
                {hashMatches ? (
                  <>
                    <CheckCircle2
                      className="h-3.5 w-3.5 text-emerald-400 shrink-0"
                      aria-hidden="true"
                    />
                    <span className="text-emerald-400 font-medium">
                      Integrity Verified (256-bit digest match)
                    </span>
                  </>
                ) : (
                  <>
                    <AlertTriangle
                      className="h-3.5 w-3.5 text-rose-400 shrink-0"
                      aria-hidden="true"
                    />
                    <span className="text-rose-400 font-medium">
                      Hash Mismatch — Potential Tampering
                    </span>
                  </>
                )}
              </div>
            </div>
          </section>

          {/* 4. RSA-OAEP-2048 Wrapped AES Key */}
          <section className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <KeyRound className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                <span>RSA-OAEP-2048 Wrapped AES Key</span>
              </h3>
              {activeWrappedKey && (
                <button
                  type="button"
                  onClick={() => handleCopy('rsa', activeWrappedKey.wrappedKeyBase64)}
                  aria-label="Copy RSA-wrapped AES key"
                  className="text-xs text-slate-400 hover:text-slate-100 inline-flex items-center gap-1 transition-colors"
                >
                  {copiedField === 'rsa' ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" aria-hidden="true" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {wrappedKeys.length > 1 && (
              <div>
                <label htmlFor="inspector-recipient-select" className="sr-only">
                  Select recipient wrapped key
                </label>
                <select
                  id="inspector-recipient-select"
                  value={selectedRecipientIndex}
                  onChange={(e) => setSelectedRecipientIndex(Number(e.target.value))}
                  className="w-full h-9 px-3 rounded-lg bg-[#111824] border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  {wrappedKeys.map((wk, idx) => (
                    <option key={wk.recipientId} value={idx}>
                      {wk.recipientName} ({wk.recipientRole})
                    </option>
                  ))}
                </select>
              </div>
            )}

            {activeWrappedKey && (
              <div className="rounded-lg bg-[#0B0F17] border border-slate-800/90 p-3 space-y-2">
                <div className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="text-slate-300 font-medium truncate">
                    {activeWrappedKey.recipientName}
                  </span>
                  <span className="font-mono text-slate-500 shrink-0">
                    {activeWrappedKey.keyFingerprint.slice(0, 14)}
                  </span>
                </div>
                <pre
                  data-testid="inspector-rsa-key"
                  className="font-mono text-[11px] text-amber-200/90 whitespace-pre-wrap break-all leading-relaxed max-h-28 overflow-y-auto"
                >
                  {activeWrappedKey.wrappedKeyBase64}
                </pre>
              </div>
            )}
          </section>
        </div>
      )}
    </aside>
  );
}
