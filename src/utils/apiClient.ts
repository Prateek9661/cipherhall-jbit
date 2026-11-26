/**
 * CipherHall – API client
 *
 * All routes talk to http://localhost:5000/api (or VITE_API_URL).
 * Zero-knowledge contract:
 *   - auth calls send only hashed intent (name/email/bcrypt-compatible password).
 *   - Vault Passphrase is NEVER sent.
 *   - `publicKeyJwk` and `protectedPrivateKey` are opaque blobs produced
 *     by the Web Crypto engine on the client.
 *   - File blobs sent to /files/upload are AES-256-GCM ciphertext only.
 *   - Chat messages sent to /messages are AES-256-GCM envelopes only.
 */

export const API_BASE =
  (import.meta as ImportMeta & { env: Record<string, string> }).env.VITE_API_URL ||
  'http://localhost:5000/api';

// ─── Token storage ────────────────────────────────────────────────────────────

const TOKEN_KEY = 'cipherhall_jwt';

export function getStoredToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function storeToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

// ─── Fetch wrapper ────────────────────────────────────────────────────────────

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  token?: string | null;
  signal?: AbortSignal;
}

async function apiFetch<T>(
  path: string,
  opts: RequestOptions = {}
): Promise<T> {
  const { method = 'GET', body, signal } = opts;
  const token = opts.token !== undefined ? opts.token : getStoredToken();

  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal,
  });

  if (!res.ok) {
    let errMsg = `API error ${res.status}`;
    try {
      const json = await res.json();
      errMsg = json.error || errMsg;
    } catch { /* ignore parse errors */ }
    throw new Error(errMsg);
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;

  return res.json() as Promise<T>;
}

// ─── Health ───────────────────────────────────────────────────────────────────

export async function checkHealth(): Promise<{ status: string; mongoState: number }> {
  return apiFetch('/health', { token: null });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export interface ApiUser {
  id: string;
  name: string;
  email: string;
  role: 'Student' | 'Faculty';
  department: string;
  keyFingerprint: string;
}

export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
  role: 'Student' | 'Faculty';
  department?: string;
  publicKeyJwk?: JsonWebKey | null;
  keyFingerprint?: string;
  protectedPrivateKey?: object | null;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user: ApiUser;
  /** Opaque PBKDF2+AES-GCM bundle. Client uses it + local passphrase to unwrap RSA private key. */
  protectedPrivateKey?: object | null;
  publicKeyJwk?: JsonWebKey | null;
}

export async function register(payload: RegisterPayload): Promise<AuthResponse> {
  const res = await apiFetch<AuthResponse>('/auth/register', {
    method: 'POST',
    body: payload,
    token: null,
  });
  storeToken(res.token);
  return res;
}

export async function login(payload: LoginPayload): Promise<AuthResponse> {
  const res = await apiFetch<AuthResponse>('/auth/login', {
    method: 'POST',
    body: payload,
    token: null,
  });
  storeToken(res.token);
  return res;
}

export function logout(): void {
  clearToken();
}

// ─── Users / Directory ────────────────────────────────────────────────────────

export interface ApiRecipient {
  id: string;
  name: string;
  email: string;
  role: 'Student' | 'Faculty';
  department: string;
  keyFingerprint: string;
  publicKeyJwk?: JsonWebKey | null;
}

export async function fetchCampusDirectory(): Promise<ApiRecipient[]> {
  return apiFetch<ApiRecipient[]>('/users');
}

export interface KeyMaterialPayload {
  publicKeyJwk: JsonWebKey;
  keyFingerprint: string;
  protectedPrivateKey: object;
}

export async function pushKeyMaterial(payload: KeyMaterialPayload): Promise<void> {
  await apiFetch<{ ok: boolean }>('/users/keys', {
    method: 'PUT',
    body: payload,
  });
}

// ─── Vault Files ─────────────────────────────────────────────────────────────

export interface ApiVaultFile {
  id: string;
  filename: string;
  fileType: string;
  mimeType: string;
  sizeBytes: number;
  uploadedBy: string;
  uploadedByRole: 'Student' | 'Faculty';
  department: string;
  uploadedAt: string;
  sha256Status: 'Verified' | 'Pending' | 'Mismatch';
  recipients: string[];
  crypto: object;             // CryptoEnvelope – opaque to server
  decryptedPreviewContent: string;
}

export interface UploadFileMetadata {
  filename: string;
  fileType: string;
  mimeType: string;
  sizeBytes: number;
  department: string;
  recipients: string[];
  authorizedUserIds: string[];
  cryptoEnvelope: object;     // produced by Web Crypto on client
}

/**
 * Upload an encrypted file blob.
 * `encryptedBlob` is the raw AES-256-GCM ciphertext produced by the browser.
 * `metadata.cryptoEnvelope` contains the IV, auth tag, wrapped AES keys, etc.
 */
export async function uploadEncryptedFile(
  encryptedBlob: Uint8Array | null,
  metadata: UploadFileMetadata
): Promise<ApiVaultFile> {
  const token = getStoredToken();
  const form = new FormData();

  if (encryptedBlob && encryptedBlob.byteLength > 0) {
    // Copy to a plain ArrayBuffer to satisfy strict BlobPart typings
    const buf = encryptedBlob.buffer.slice(
      encryptedBlob.byteOffset,
      encryptedBlob.byteOffset + encryptedBlob.byteLength
    ) as ArrayBuffer;
    form.append('blob', new Blob([buf], { type: 'application/octet-stream' }), `${metadata.filename}.enc`);
  }
  form.append('metadata', JSON.stringify(metadata));

  const res = await fetch(`${API_BASE}/files/upload`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });

  if (!res.ok) {
    let errMsg = `Upload failed (${res.status})`;
    try { errMsg = (await res.json()).error || errMsg; } catch { /* ignore */ }
    throw new Error(errMsg);
  }

  return res.json();
}

export async function fetchVaultFiles(): Promise<ApiVaultFile[]> {
  return apiFetch<ApiVaultFile[]>('/files');
}

/**
 * Download the encrypted blob for a file. The caller decrypts it in the browser.
 */
export async function fetchEncryptedBlob(fileId: string): Promise<ArrayBuffer> {
  const token = getStoredToken();
  const res = await fetch(`${API_BASE}/files/${fileId}/blob`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    let errMsg = `Blob fetch failed (${res.status})`;
    try { errMsg = (await res.json()).error || errMsg; } catch { /* ignore */ }
    throw new Error(errMsg);
  }
  return res.arrayBuffer();
}

export interface AccessUpdatePayload {
  recipients: string[];
  authorizedUserIds: string[];
  cryptoEnvelope?: object;
}

export async function updateFileAccess(
  fileId: string,
  payload: AccessUpdatePayload
): Promise<ApiVaultFile> {
  return apiFetch<ApiVaultFile>(`/files/${fileId}/access`, {
    method: 'PATCH',
    body: payload,
  });
}

// ─── Chat Messages ────────────────────────────────────────────────────────────

export interface ApiChatMessage {
  id: string;
  threadId: string;
  senderId: string;
  senderName: string;
  senderRole: 'Student' | 'Faculty';
  recipientId: string | null;
  recipientName: string | null;
  timestamp: string;
  crypto: object;             // AES-256-GCM envelope – opaque to server
  attachedFileId: string | null;
}

export async function fetchMessages(peerId: string): Promise<ApiChatMessage[]> {
  return apiFetch<ApiChatMessage[]>(`/messages/${peerId}`);
}

export interface SendMessagePayload {
  recipientId: string;
  cryptoEnvelope: object;
  attachedFileId?: string | null;
}

export async function sendEncryptedMessage(
  payload: SendMessagePayload
): Promise<ApiChatMessage> {
  return apiFetch<ApiChatMessage>('/messages', {
    method: 'POST',
    body: payload,
  });
}

// ─── Audit ────────────────────────────────────────────────────────────────────

export interface ApiAuditEvent {
  id: string;
  actorName: string;
  actorRole: string;
  event: string;
  detail: string;
  status: 'info' | 'success' | 'warning' | 'error';
  timestamp: string;
}

export async function fetchAuditLog(): Promise<ApiAuditEvent[]> {
  return apiFetch<ApiAuditEvent[]>('/audit');
}
