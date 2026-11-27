import type {
  ActivityCategory,
  ActivityEvent,
  AuthUserDTO,
  ChatFileAttachment,
  CryptoEnvelope,
  ProtectedPrivateKeyBundle,
  Recipient,
  StoredEncryptedMessageDTO,
  UserRole,
  VaultFile,
} from '../types/vault';

async function apiRequest<T>(
  url: string,
  options: {
    method?: 'GET' | 'POST' | 'PATCH';
    token?: string | null;
    body?: unknown;
  } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }

  const response = await fetch(url, {
    method: options.method ?? 'GET',
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  const payload = (await response.json().catch(() => ({}))) as { error?: string } & T;
  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return payload;
}

export interface AuthResponse {
  token: string;
  user: AuthUserDTO;
}

export async function registerUserApi(input: {
  name: string;
  email: string;
  password: string;
  role: UserRole;
  department?: string;
  keyFingerprint: string;
  publicKeySpkiBase64: string;
  protectedPrivateKey: ProtectedPrivateKeyBundle;
}): Promise<AuthResponse> {
  return apiRequest<AuthResponse>('/api/auth/register', {
    method: 'POST',
    body: input,
  });
}

export async function loginUserApi(input: {
  email: string;
  password: string;
}): Promise<AuthResponse> {
  return apiRequest<AuthResponse>('/api/auth/login', {
    method: 'POST',
    body: input,
  });
}

export async function fetchRegisteredUsersApi(token: string): Promise<Recipient[]> {
  const data = await apiRequest<{ users: Recipient[] }>('/api/users', { token });
  return data.users;
}

export async function fetchVaultFilesApi(token: string): Promise<VaultFile[]> {
  const data = await apiRequest<{ files: VaultFile[] }>('/api/files', { token });
  return data.files;
}

export async function uploadEncryptedFileApi(
  token: string,
  input: {
    filename: string;
    mimeType?: string;
    sizeBytes: number;
    recipientIds: string[];
    crypto: CryptoEnvelope;
  }
): Promise<VaultFile> {
  const data = await apiRequest<{ file: VaultFile }>('/api/files', {
    method: 'POST',
    token,
    body: input,
  });
  return data.file;
}

export async function updateFileAccessApi(
  token: string,
  fileId: string,
  input: {
    recipientIds: string[];
    wrappedKeys: CryptoEnvelope['wrappedKeys'];
  }
): Promise<{
  file: VaultFile;
  revokedNames: string[];
  addedNames: string[];
}> {
  return apiRequest(`/api/files/${encodeURIComponent(fileId)}/access`, {
    method: 'PATCH',
    token,
    body: input,
  });
}

export async function fetchEncryptedMessagesApi(
  token: string
): Promise<StoredEncryptedMessageDTO[]> {
  const data = await apiRequest<{ messages: StoredEncryptedMessageDTO[] }>('/api/messages', {
    token,
  });
  return data.messages;
}

export async function sendEncryptedMessageApi(
  token: string,
  input: {
    recipientId: string;
    attachedFile?: ChatFileAttachment;
    crypto: CryptoEnvelope;
  }
): Promise<StoredEncryptedMessageDTO> {
  const data = await apiRequest<{ message: StoredEncryptedMessageDTO }>('/api/messages', {
    method: 'POST',
    token,
    body: input,
  });
  return data.message;
}

export async function fetchActivityLogApi(token: string): Promise<ActivityEvent[]> {
  const data = await apiRequest<{ events: ActivityEvent[] }>('/api/activity', { token });
  return data.events;
}

export async function recordActivityEventApi(
  token: string,
  input: {
    category: ActivityCategory;
    title: string;
    detail: string;
    status?: 'info' | 'success' | 'warning';
    statusLabel?: string;
  }
): Promise<ActivityEvent> {
  const data = await apiRequest<{ event: ActivityEvent }>('/api/activity', {
    method: 'POST',
    token,
    body: input,
  });
  return data.event;
}
