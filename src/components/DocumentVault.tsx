import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  FileText,
  Search,
  ShieldCheck,
  Upload,
  Users,
} from 'lucide-react';
import type { IntegrityStatus, UserProfile, UserRole, VaultFile } from '../types/vault';
import {
  canManageFileAccess,
  decryptPayloadWithWebCrypto,
  filterVaultFiles,
  formatByteSize,
  verifyFileIntegrity,
} from '../utils/cryptoEngine';
import { SecurityTooltip } from './SecurityTooltip';

interface DocumentVaultProps {
  files: VaultFile[];
  currentUser: UserProfile;
  selectedFileId: string | null;
  inspectorOpen?: boolean;
  externalNotice?: { state: 'success' | 'error'; message: string } | null;
  onClearExternalNotice?: () => void;
  onSelectFile: (file: VaultFile) => void;
  onOpenUploadModal: () => void;
  onManageAccess: (file: VaultFile) => void;
  onDecryptActivity?: (params: {
    file: VaultFile;
    success: boolean;
    detail: string;
  }) => void;
}

const VERIFIED_TOOLTIP =
  'File integrity verified locally using SHA-256. No changes or tampering have been detected since upload.';
const PENDING_TOOLTIP =
  'Awaiting final faculty co-signature before integrity verification is finalized.';
const ALERT_TOOLTIP =
  'File fingerprint does not match the original upload. Download is automatically blocked for your protection.';

export function DocumentVault({
  files,
  currentUser,
  selectedFileId,
  inspectorOpen = false,
  externalNotice,
  onClearExternalNotice,
  onSelectFile,
  onOpenUploadModal,
  onManageAccess,
  onDecryptActivity,
}: DocumentVaultProps) {
  const [query, setQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<'All' | UserRole>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | IntegrityStatus>('All');
  const [decryptingFileId, setDecryptingFileId] = useState<string | null>(null);
  const [decryptFeedback, setDecryptFeedback] = useState<{
    fileId: string;
    filename: string;
    state: 'success' | 'error';
    message: string;
  } | null>(null);

  const filteredFiles = useMemo(
    () => filterVaultFiles(files, { query, roleFilter, statusFilter }),
    [files, query, roleFilter, statusFilter]
  );

  const verifiedCount = useMemo(
    () => files.filter((f) => f.sha256Status === 'Verified').length,
    [files]
  );

  const hasAnyManageableRow = useMemo(
    () => filteredFiles.some((file) => canManageFileAccess(currentUser, file)),
    [filteredFiles, currentUser]
  );

  const triggerBrowserDownload = (blob: Blob, downloadName: string) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = downloadName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleDecryptAndDownload = async (file: VaultFile) => {
    onSelectFile(file);

    // Real Web Crypto path for newly uploaded files
    if (file.crypto.isWebCryptoReal && file.crypto.rawCiphertextBase64) {
      if (!currentUser.privateKey) {
        setDecryptFeedback({
          fileId: file.id,
          filename: file.filename,
          state: 'error',
          message:
            'Your vault key is still initializing. Please try again in a moment.',
        });
        return;
      }

      setDecryptingFileId(file.id);
      try {
        const result = await decryptPayloadWithWebCrypto({
          envelope: file.crypto,
          privateKey: currentUser.privateKey,
          recipientId: currentUser.id,
          recipientFingerprint: currentUser.keyFingerprint,
        });

        const bytesCopy = new Uint8Array(result.plaintextBytes.byteLength);
        bytesCopy.set(result.plaintextBytes);
        const blob = new Blob([bytesCopy.buffer], {
          type: file.mimeType || 'application/octet-stream',
        });
        triggerBrowserDownload(blob, file.filename);

        const successMsg = `Decrypted ${file.filename} (${formatByteSize(
          result.plaintextBytes.byteLength
        )}) locally and verified file integrity.`;
        setDecryptFeedback({
          fileId: file.id,
          filename: file.filename,
          state: 'success',
          message: successMsg,
        });
        onDecryptActivity?.({
          file,
          success: true,
          detail: `Verified integrity locally and decrypted ${file.filename} on this device.`,
        });
      } catch (err) {
        const errMsg =
          err instanceof Error ? err.message : 'Integrity verification failed.';
        setDecryptFeedback({
          fileId: file.id,
          filename: file.filename,
          state: 'error',
          message: `Unable to decrypt ${file.filename}: ${errMsg}`,
        });
        onDecryptActivity?.({
          file,
          success: false,
          detail: `Decryption blocked for ${file.filename}: ${errMsg}`,
        });
      } finally {
        setDecryptingFileId(null);
      }
      return;
    }

    // Pre-seeded demo files path
    const check = verifyFileIntegrity(file);
    if (!check.valid) {
      setDecryptFeedback({
        fileId: file.id,
        filename: file.filename,
        state: 'error',
        message: `Blocked download for ${file.filename}: file integrity verification failed.`,
      });
      onDecryptActivity?.({
        file,
        success: false,
        detail: `Automatically blocked download of ${file.filename} due to an integrity alert.`,
      });
      return;
    }

    const blob = new Blob(
      [
        `${file.decryptedPreviewContent}\n\n---\nDecrypted locally by CipherHall\n`,
      ],
      { type: 'text/plain;charset=utf-8' }
    );
    triggerBrowserDownload(blob, `decrypted_${file.filename.replace(/\.[^.]+$/, '')}.txt`);

    setDecryptFeedback({
      fileId: file.id,
      filename: file.filename,
      state: 'success',
      message: `Decrypted ${file.filename} locally and verified file integrity.`,
    });
    onDecryptActivity?.({
      file,
      success: true,
      detail: `Verified integrity locally and downloaded ${file.filename}.`,
    });
  };

  const activeBanner = decryptFeedback
    ? {
        state: decryptFeedback.state,
        message: decryptFeedback.message,
        dismiss: () => setDecryptFeedback(null),
      }
    : externalNotice
    ? {
        state: externalNotice.state,
        message: externalNotice.message,
        dismiss: () => onClearExternalNotice?.(),
      }
    : null;

  return (
    <div
      className={`${
        inspectorOpen ? 'p-4' : 'p-4 sm:p-6'
      } max-w-[1280px] mx-auto space-y-5`}
    >
      {/* Section Header + Compact Metrics Strip */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-50">
            Shared Encrypted Files
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Encrypted documents shared across your courses, advisors, and research groups.
          </p>
        </div>

        <div className="flex items-center gap-5 text-xs text-slate-400 shrink-0">
          <div>
            <span className="text-slate-500">Total Files</span>
            <p className="font-mono text-sm font-semibold text-slate-100 tabular-nums mt-0.5">
              {files.length}
            </p>
          </div>
          <div className="h-7 w-px bg-slate-800" aria-hidden="true" />
          <div>
            <span className="text-slate-500">Verified Files</span>
            <p className="font-mono text-sm font-semibold text-emerald-400 tabular-nums mt-0.5">
              {verifiedCount}/{files.length}
            </p>
          </div>
        </div>
      </div>

      {/* Decrypt / Access Update Banner */}
      {activeBanner && (
        <div
          role="status"
          aria-live="polite"
          className={`flex items-start justify-between gap-4 px-4 py-3 rounded-lg border text-sm ${
            activeBanner.state === 'success'
              ? 'bg-emerald-950/35 border-emerald-500/30 text-emerald-200'
              : 'bg-rose-950/35 border-rose-500/30 text-rose-200'
          }`}
        >
          <div className="flex items-start gap-2.5">
            {activeBanner.state === 'success' ? (
              <CheckCircle2
                className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0"
                aria-hidden="true"
              />
            ) : (
              <AlertTriangle
                className="h-4 w-4 text-rose-400 mt-0.5 shrink-0"
                aria-hidden="true"
              />
            )}
            <span>{activeBanner.message}</span>
          </div>
          <button
            type="button"
            onClick={activeBanner.dismiss}
            className="text-xs font-medium text-slate-400 hover:text-slate-100 whitespace-nowrap shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Filter & Search Toolbar */}
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
            aria-label="Search encrypted files"
            placeholder="Search filename, uploader, or department..."
            className="w-full h-10 pl-10 pr-3.5 rounded-lg bg-[#111824] border border-slate-800 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Role Segmented Filter */}
          <div
            role="group"
            aria-label="Filter by uploader role"
            className="inline-flex items-center p-1 rounded-lg bg-[#111824] border border-slate-800"
          >
            {(['All', 'Faculty', 'Student'] as const).map((roleOption) => (
              <button
                key={roleOption}
                type="button"
                onClick={() => setRoleFilter(roleOption)}
                aria-pressed={roleFilter === roleOption}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  roleFilter === roleOption
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {roleOption}
              </button>
            ))}
          </div>

          {/* Integrity Status Select */}
          <label className="sr-only" htmlFor="vault-status-filter">
            Filter by verification status
          </label>
          <select
            id="vault-status-filter"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as 'All' | IntegrityStatus)}
            className="h-10 pl-3 pr-8 rounded-lg bg-[#111824] border border-slate-800 text-xs font-medium text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="All">All Statuses</option>
            <option value="Verified">Verified</option>
            <option value="Pending">Pending</option>
            <option value="Mismatch">Integrity Alert</option>
          </select>
        </div>
      </div>

      {/* Encrypted Files Table */}
      <div className="rounded-xl border border-slate-800/90 bg-[#111824] overflow-hidden">
        {filteredFiles.length === 0 ? (
          <div className="py-16 px-6 text-center">
            <FileText className="h-9 w-9 text-slate-600 mx-auto" aria-hidden="true" />
            <h2 className="mt-3 font-display text-base font-medium text-slate-200">
              No matching encrypted files
            </h2>
            <p className="mt-1 text-sm text-slate-400 max-w-sm mx-auto">
              Adjust your search or filters, or encrypt a new document for your course
              recipients.
            </p>
            <div className="mt-5 flex items-center justify-center gap-3">
              {(query || roleFilter !== 'All' || statusFilter !== 'All') && (
                <button
                  type="button"
                  onClick={() => {
                    setQuery('');
                    setRoleFilter('All');
                    setStatusFilter('All');
                  }}
                  className="h-9 px-4 rounded-lg border border-slate-700 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap"
                >
                  Reset Filters
                </button>
              )}
              <button
                type="button"
                onClick={onOpenUploadModal}
                className="h-9 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-medium text-white transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
              >
                <Upload className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Upload &amp; Encrypt</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800/90 bg-[#0E1420] text-xs font-medium text-slate-400">
                  <th
                    scope="col"
                    className={`py-3 whitespace-nowrap ${
                      inspectorOpen ? 'pl-3 pr-1.5' : 'pl-4 pr-2'
                    }`}
                  >
                    Filename
                  </th>
                  <th
                    scope="col"
                    className={`py-3 whitespace-nowrap ${inspectorOpen ? 'px-1.5' : 'px-2.5'}`}
                  >
                    Uploaded By
                  </th>
                  <th
                    scope="col"
                    className={`py-3 whitespace-nowrap ${inspectorOpen ? 'px-1.5' : 'px-2.5'}`}
                  >
                    Role
                  </th>
                  <th
                    scope="col"
                    className={`py-3 whitespace-nowrap ${inspectorOpen ? 'px-1.5' : 'px-2.5'}`}
                  >
                    Date
                  </th>
                  <th
                    scope="col"
                    className={`py-3 whitespace-nowrap ${inspectorOpen ? 'px-1.5' : 'px-2.5'}`}
                  >
                    Verification
                  </th>
                  <th
                    scope="col"
                    className={`py-3 text-right whitespace-nowrap ${
                      inspectorOpen ? 'pl-1.5 pr-3' : 'pl-2 pr-4'
                    }`}
                  >
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-sm">
                {filteredFiles.map((file, rowIndex) => {
                  const isSelected = file.id === selectedFileId;
                  const sharedCount = file.recipients.length;
                  const isManageable = canManageFileAccess(currentUser, file);
                  const tooltipPos =
                    rowIndex >= filteredFiles.length - 2 && filteredFiles.length > 2
                      ? 'top'
                      : 'bottom';

                  const filenameMaxWidth = inspectorOpen
                    ? hasAnyManageableRow
                      ? 'max-w-[125px] xl:max-w-[140px]'
                      : 'max-w-[140px] xl:max-w-[165px]'
                    : hasAnyManageableRow
                    ? 'max-w-[200px] lg:max-w-[230px]'
                    : 'max-w-[240px] lg:max-w-[280px]';

                  const uploaderMaxWidth = inspectorOpen
                    ? hasAnyManageableRow
                      ? 'max-w-[92px]'
                      : 'max-w-[105px]'
                    : 'max-w-[145px]';

                  return (
                    <tr
                      key={file.id}
                      onClick={() => onSelectFile(file)}
                      className={`transition-colors cursor-pointer ${
                        isSelected ? 'bg-blue-600/10' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      {/* Filename + Friendly Sharing Metadata */}
                      <td className={`py-3.5 ${inspectorOpen ? 'pl-3 pr-1.5' : 'pl-4 pr-2'}`}>
                        <div className="flex items-start gap-2 min-w-0">
                          <FileText
                            className={`h-4 w-4 mt-0.5 shrink-0 ${
                              isSelected ? 'text-blue-400' : 'text-slate-500'
                            }`}
                            aria-hidden="true"
                          />
                          <div className="min-w-0">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectFile(file);
                              }}
                              title={file.filename}
                              className={`text-left text-[13px] font-medium text-slate-100 hover:text-blue-300 transition-colors focus-visible:outline-none focus-visible:underline block truncate ${filenameMaxWidth}`}
                            >
                              {file.filename}
                            </button>
                            <div
                              className={`mt-0.5 flex items-center gap-1.5 text-xs text-slate-500 whitespace-nowrap ${
                                inspectorOpen ? 'max-w-[140px] xl:max-w-[165px] truncate' : ''
                              }`}
                            >
                              <span className="tabular-nums">{formatByteSize(file.sizeBytes)}</span>
                              <span aria-hidden="true">·</span>
                              <span>
                                Shared with {sharedCount}{' '}
                                {sharedCount === 1 ? 'person' : 'people'}
                              </span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Uploaded By */}
                      <td
                        className={`py-3.5 whitespace-nowrap ${
                          inspectorOpen ? 'px-1.5' : 'px-2.5'
                        }`}
                      >
                        <p
                          className={`text-[13px] text-slate-200 font-medium truncate ${uploaderMaxWidth}`}
                        >
                          {file.uploadedBy}
                        </p>
                        <p
                          className={`text-xs text-slate-500 mt-0.5 truncate ${uploaderMaxWidth}`}
                        >
                          {file.department}
                        </p>
                      </td>

                      {/* Role Badge */}
                      <td
                        className={`py-3.5 whitespace-nowrap ${
                          inspectorOpen ? 'px-1.5' : 'px-2.5'
                        }`}
                      >
                        <span
                          className={`inline-flex items-center px-2 py-0.5 text-[11px] font-medium rounded border ${
                            file.uploadedByRole === 'Faculty'
                              ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                          }`}
                        >
                          {file.uploadedByRole}
                        </span>
                      </td>

                      {/* Date */}
                      <td
                        className={`py-3.5 whitespace-nowrap text-xs text-slate-400 tabular-nums ${
                          inspectorOpen ? 'px-1.5' : 'px-2.5'
                        }`}
                      >
                        {file.dateLabel}
                      </td>

                      {/* Friendly Verification Shield Badge with Plain-English Tooltip */}
                      <td
                        className={`py-3.5 whitespace-nowrap ${
                          inspectorOpen ? 'px-1.5' : 'px-2.5'
                        }`}
                      >
                        {file.sha256Status === 'Verified' && (
                          <SecurityTooltip
                            text={VERIFIED_TOOLTIP}
                            align="center"
                            position={tooltipPos}
                          >
                            <span
                              tabIndex={0}
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-950/40 text-xs font-medium text-emerald-300 cursor-help focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
                            >
                              <ShieldCheck
                                className="h-3.5 w-3.5 text-emerald-400 shrink-0"
                                aria-hidden="true"
                              />
                              <span>Verified</span>
                            </span>
                          </SecurityTooltip>
                        )}
                        {file.sha256Status === 'Pending' && (
                          <SecurityTooltip
                            text={PENDING_TOOLTIP}
                            align="center"
                            position={tooltipPos}
                          >
                            <span
                              tabIndex={0}
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-amber-500/30 bg-amber-950/30 text-xs font-medium text-amber-300 cursor-help focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
                            >
                              <Clock
                                className="h-3.5 w-3.5 text-amber-400 shrink-0"
                                aria-hidden="true"
                              />
                              <span>Pending</span>
                            </span>
                          </SecurityTooltip>
                        )}
                        {file.sha256Status === 'Mismatch' && (
                          <SecurityTooltip
                            text={ALERT_TOOLTIP}
                            align="center"
                            position={tooltipPos}
                          >
                            <span
                              tabIndex={0}
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-rose-500/30 bg-rose-950/40 text-xs font-medium text-rose-300 cursor-help focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
                            >
                              <AlertTriangle
                                className="h-3.5 w-3.5 text-rose-400 shrink-0"
                                aria-hidden="true"
                              />
                              <span>Integrity Alert</span>
                            </span>
                          </SecurityTooltip>
                        )}
                      </td>

                      {/* Actions: Faculty Manage/Revoke Access + Decrypt & Download */}
                      <td
                        className={`py-3.5 text-right whitespace-nowrap ${
                          inspectorOpen ? 'pl-1.5 pr-3' : 'pl-2 pr-4'
                        }`}
                      >
                        <div className="inline-flex items-center justify-end gap-1.5">
                          {isManageable && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onManageAccess(file);
                              }}
                              aria-label={`Manage / Revoke Access for ${file.filename}`}
                              className={`h-8 rounded-md border border-amber-500/30 bg-amber-950/25 hover:bg-amber-950/45 font-medium text-amber-200 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 ${
                                inspectorOpen ? 'px-2 text-[11px]' : 'px-2.5 text-xs'
                              }`}
                            >
                              <Users
                                className="h-3.5 w-3.5 text-amber-300 shrink-0"
                                aria-hidden="true"
                              />
                              <span>
                                {inspectorOpen ? 'Access' : 'Manage / Revoke Access'}
                              </span>
                            </button>
                          )}

                          <button
                            type="button"
                            disabled={decryptingFileId === file.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleDecryptAndDownload(file);
                            }}
                            aria-label={`Decrypt & Download ${file.filename}`}
                            className={`h-8 rounded-md border border-slate-700/90 bg-slate-800/70 hover:bg-slate-700/80 disabled:opacity-60 disabled:cursor-wait font-medium text-slate-100 transition-colors inline-flex items-center gap-1.5 whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                              inspectorOpen ? 'px-2 text-[11px]' : 'px-2.5 text-xs'
                            }`}
                          >
                            <Download
                              className="h-3.5 w-3.5 text-blue-400 shrink-0"
                              aria-hidden="true"
                            />
                            <span>
                              {decryptingFileId === file.id
                                ? 'Decrypting…'
                                : inspectorOpen && isManageable
                                ? 'Decrypt'
                                : 'Decrypt & Download'}
                            </span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
