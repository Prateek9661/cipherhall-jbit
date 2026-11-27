export type UserRole = 'Student' | 'Faculty';

export type IntegrityStatus = 'Verified' | 'Pending' | 'Mismatch';

export type WorkspaceView = 'vault' | 'chat' | 'activity';

export interface ProtectedPrivateKeyBundle {
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltBase64: string;
  wrapAlgorithm: 'AES-256-GCM';
  wrapIvHex: string;
  wrappedPrivateKeyBase64: string;
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  keyFingerprint: string;
  publicKeySpkiBase64?: string;
  vaultUnlockedAt: string;
  publicKey?: CryptoKey;
  privateKey?: CryptoKey;
  protectedPrivateKey?: ProtectedPrivateKeyBundle;
}

export interface Recipient {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  keyFingerprint: string;
  publicKeySpkiBase64?: string;
  publicKey?: CryptoKey;
}

export interface AuthUserDTO {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  keyFingerprint: string;
  publicKeySpkiBase64: string;
  protectedPrivateKey: ProtectedPrivateKeyBundle;
}

export interface WrappedRecipientKey {
  recipientId: string;
  recipientName: string;
  recipientRole: UserRole;
  keyFingerprint: string;
  wrappedKeyBase64: string;
}

export interface CryptoEnvelope {
  algorithm: 'AES-256-GCM';
  keyWrapAlgorithm: 'RSA-OAEP-2048';
  ivHex: string; // 12 bytes = 24 hex chars
  ivBase64: string; // 12 bytes = 16 base64 chars
  authTagHex: string; // 16 bytes = 32 hex chars
  ciphertextBase64: string; // Base64 preview for Live Crypto Inspector
  rawCiphertextBase64?: string; // Full AES-GCM ciphertext + 16-byte auth tag for real decryption
  ciphertextByteLength: number;
  sha256Hash: string; // 64 hex chars
  expectedSha256Hash: string; // matches sha256Hash unless tampered
  wrappedKeys: WrappedRecipientKey[];
  encryptedAt: string;
  isWebCryptoReal?: boolean;
}

export interface VaultFile {
  id: string;
  filename: string;
  fileType: string;
  mimeType?: string;
  sizeBytes: number;
  uploaderId?: string;
  uploadedBy: string;
  uploadedByRole: UserRole;
  department: string;
  uploadedAt: string;
  dateLabel: string;
  sha256Status: IntegrityStatus;
  decryptedPreviewContent?: string;
  recipientIds?: string[];
  recipients: string[];
  crypto: CryptoEnvelope;
}

export interface ChatFileAttachment {
  fileId: string;
  filename: string;
  sizeBytes: number;
  sha256Status: IntegrityStatus;
}

export interface StoredEncryptedMessageDTO {
  id: string;
  senderId: string;
  senderName: string;
  senderRole: UserRole;
  recipientId: string;
  timestamp: string;
  createdAt: string;
  attachedFile?: ChatFileAttachment;
  crypto: CryptoEnvelope;
}

export interface ChatMessage {
  id: string;
  threadId: string;
  senderId: string;
  senderName: string;
  senderRole: UserRole;
  text: string;
  timestamp: string;
  isCurrentUser?: boolean;
  attachedFile?: ChatFileAttachment;
  crypto: CryptoEnvelope;
}

export interface ChatThread {
  id: string;
  title: string;
  type: 'direct' | 'group';
  subtitle: string;
  participantEmail?: string;
  participantRole?: UserRole;
  memberCount: number;
  recipientIds: string[];
  unreadCount: number;
  lastActivity: string;
  messages: ChatMessage[];
}

export type ActivityCategory = 'file' | 'access' | 'chat' | 'security';

export interface ActivityEvent {
  id: string;
  category: ActivityCategory;
  title: string;
  detail: string;
  actorName: string;
  actorRole: UserRole;
  timestampLabel: string;
  status: 'info' | 'success' | 'warning';
  statusLabel?: string;
}

export interface EncryptedKeyBackupPayload {
  schemaVersion: string;
  application: 'CipherHall';
  institution: string;
  exportedAt: string;
  owner: {
    id: string;
    name: string;
    email: string;
    role: UserRole;
    department: string;
  };
  protection: {
    asymmetricAlgorithm: 'RSA-OAEP-2048';
    symmetricAlgorithm: 'AES-256-GCM';
    integrityHash: 'SHA-256';
    keyDerivation: 'PBKDF2-SHA256';
    iterations: number;
  };
  encryptedPrivateKeyBundle: ProtectedPrivateKeyBundle;
}

export type InspectorTarget =
  | { kind: 'file'; file: VaultFile }
  | { kind: 'message'; message: ChatMessage; threadTitle: string };
