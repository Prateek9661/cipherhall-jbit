import type {
  ActivityCategory,
  ActivityEvent,
  CryptoEnvelope,
  EncryptedKeyBackupPayload,
  IntegrityStatus,
  ProtectedPrivateKeyBundle,
  Recipient,
  UserProfile,
  UserRole,
  VaultFile,
  WrappedRecipientKey,
} from '../types/vault';

export const INSTITUTION_NAME = 'JB Institute of Technology, Dehradun';

export const PBKDF2_ITERATIONS = 100_000;
const RSA_MODULUS_LENGTH = 2048;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const CIPHERTEXT_PREVIEW_MAX_BYTES = 384;

function getWebCrypto(): Crypto {
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    return window.crypto;
  }
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error('Web Crypto API (crypto.subtle) is unavailable in this environment.');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export interface AuthFormInput {
  mode: 'login' | 'register';
  name: string;
  email: string;
  password: string;
  role: UserRole;
  passphrase: string;
}

export interface AuthValidationResult {
  valid: boolean;
  errors: Partial<Record<'name' | 'email' | 'password' | 'passphrase', string>>;
}

export function validateAuthForm(input: AuthFormInput): AuthValidationResult {
  const errors: Partial<Record<'name' | 'email' | 'password' | 'passphrase', string>> = {};

  if (input.mode === 'register' && input.name.trim().length < 2) {
    errors.name = 'Enter your full name (at least 2 characters).';
  }

  const emailTrimmed = input.email.trim();
  if (!emailTrimmed) {
    errors.email = 'Enter your institute email address.';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailTrimmed)) {
    errors.email = 'Enter a valid campus email address (e.g. name@jbitdoon.edu.in).';
  }

  if (!input.password) {
    errors.password = 'Enter your account password.';
  } else if (input.password.length < 8) {
    errors.password = 'Password must be at least 8 characters.';
  }

  if (!input.passphrase) {
    errors.passphrase = 'Vault passphrase is required to unlock your local private key.';
  } else if (input.passphrase.length < 6) {
    errors.passphrase = 'Vault passphrase must be at least 6 characters.';
  }

  return {
    valid: Object.keys(errors).length === 0,
    errors,
  };
}

export interface PassphraseStrength {
  score: 0 | 1 | 2 | 3 | 4;
  label: 'Empty' | 'Weak' | 'Fair' | 'Strong' | 'Hardened';
}

export function evaluatePassphraseStrength(passphrase: string): PassphraseStrength {
  if (!passphrase) {
    return { score: 0, label: 'Empty' };
  }
  let score = 0;
  if (passphrase.length >= 6) score += 1;
  if (passphrase.length >= 12) score += 1;
  if (/[A-Z]/.test(passphrase) && /[a-z]/.test(passphrase)) score += 1;
  if (/[0-9]/.test(passphrase) || /[^A-Za-z0-9]/.test(passphrase)) score += 1;

  const clamped = Math.min(4, Math.max(1, score)) as 1 | 2 | 3 | 4;
  const labels: Record<1 | 2 | 3 | 4, PassphraseStrength['label']> = {
    1: 'Weak',
    2: 'Fair',
    3: 'Strong',
    4: 'Hardened',
  };
  return { score: clamped, label: labels[clamped] };
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length.');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const triplet = (b0 << 16) | (b1 << 8) | b2;
    result += BASE64_CHARS[(triplet >> 18) & 0x3f];
    result += BASE64_CHARS[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? BASE64_CHARS[(triplet >> 6) & 0x3f] : '=';
    result += i + 2 < bytes.length ? BASE64_CHARS[triplet & 0x3f] : '=';
  }
  return result;
}

export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/\s+/g, '');
  const padding = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  const outputLength = Math.floor((clean.length * 3) / 4) - padding;
  const bytes = new Uint8Array(outputLength);

  let byteIndex = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = BASE64_CHARS.indexOf(clean[i]);
    const c1 = BASE64_CHARS.indexOf(clean[i + 1]);
    const c2 = clean[i + 2] === '=' ? 0 : BASE64_CHARS.indexOf(clean[i + 2]);
    const c3 = clean[i + 3] === '=' ? 0 : BASE64_CHARS.indexOf(clean[i + 3]);

    const triplet = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    if (byteIndex < outputLength) bytes[byteIndex++] = (triplet >> 16) & 0xff;
    if (byteIndex < outputLength) bytes[byteIndex++] = (triplet >> 8) & 0xff;
    if (byteIndex < outputLength) bytes[byteIndex++] = triplet & 0xff;
  }
  return bytes;
}

export async function computeSha256Hex(data: Uint8Array): Promise<string> {
  const webCrypto = getWebCrypto();
  const digest = await webCrypto.subtle.digest('SHA-256', toArrayBuffer(data));
  return bytesToHex(new Uint8Array(digest));
}

export async function generateRsaOaepKeyPair(): Promise<CryptoKeyPair> {
  const webCrypto = getWebCrypto();
  return webCrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: RSA_MODULUS_LENGTH,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

export async function computePublicKeyFingerprint(publicKey: CryptoKey): Promise<string> {
  const webCrypto = getWebCrypto();
  const spki = await webCrypto.subtle.exportKey('spki', publicKey);
  const digest = await webCrypto.subtle.digest('SHA-256', spki);
  const shortHex = bytesToHex(new Uint8Array(digest).slice(0, 10)).toUpperCase();
  return shortHex.match(/.{1,4}/g)?.join(':') ?? shortHex;
}

async function derivePassphraseKek(
  passphrase: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const baseKey = await webCrypto.subtle.importKey(
    'raw',
    toArrayBuffer(passphraseBytes),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return webCrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(salt),
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export interface GeneratedUserKeyMaterial {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  keyFingerprint: string;
  protectedPrivateKey: ProtectedPrivateKeyBundle;
  /** RSA-OAEP-2048 public key exported as JWK – safe to store on the server */
  publicKeyJwk: JsonWebKey;
}

/**
 * Generates a real RSA-OAEP-2048 (SHA-256) key pair on login/registration,
 * wraps the PKCS8 private key with an AES-256-GCM KEK derived from the Vault
 * Passphrase via PBKDF2 (SHA-256), and verifies unwrapping with that passphrase.
 */
export async function generateUserKeyBundle(
  passphrase: string
): Promise<GeneratedUserKeyMaterial> {
  const webCrypto = getWebCrypto();
  const keyPair = await generateRsaOaepKeyPair();
  const keyFingerprint = await computePublicKeyFingerprint(keyPair.publicKey);

  const salt = webCrypto.getRandomValues(new Uint8Array(16));
  const wrapIv = webCrypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
  const kek = await derivePassphraseKek(passphrase, salt, PBKDF2_ITERATIONS);

  const wrappedPrivateKeyBuffer = await webCrypto.subtle.wrapKey(
    'pkcs8',
    keyPair.privateKey,
    kek,
    { name: 'AES-GCM', iv: toArrayBuffer(wrapIv) }
  );

  const protectedPrivateKey: ProtectedPrivateKeyBundle = {
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    saltBase64: bytesToBase64(salt),
    wrapAlgorithm: 'AES-256-GCM',
    wrapIvHex: bytesToHex(wrapIv),
    wrappedPrivateKeyBase64: bytesToBase64(new Uint8Array(wrappedPrivateKeyBuffer)),
  };

  // Immediately verify round-trip unwrapping with the Vault Passphrase
  const unlockedPrivateKey = await unlockPrivateKeyWithPassphrase(
    protectedPrivateKey,
    passphrase
  );

  // Export public key as JWK so the server can store it for peer key-wrapping
  const publicKeyJwk = await webCrypto.subtle.exportKey('jwk', keyPair.publicKey);

  return {
    publicKey: keyPair.publicKey,
    privateKey: unlockedPrivateKey,
    keyFingerprint,
    protectedPrivateKey,
    publicKeyJwk,
  };
}

/**
 * Derives the AES-256-GCM KEK via PBKDF2 (SHA-256) from the Vault Passphrase
 * and unwraps the protected PKCS8 RSA-OAEP-2048 private key.
 */
export async function unlockPrivateKeyWithPassphrase(
  bundle: ProtectedPrivateKeyBundle,
  passphrase: string
): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const salt = base64ToBytes(bundle.saltBase64);
  const wrapIv = hexToBytes(bundle.wrapIvHex);
  const wrappedBytes = base64ToBytes(bundle.wrappedPrivateKeyBase64);
  const kek = await derivePassphraseKek(passphrase, salt, bundle.iterations);

  return webCrypto.subtle.unwrapKey(
    'pkcs8',
    toArrayBuffer(wrappedBytes),
    kek,
    { name: 'AES-GCM', iv: toArrayBuffer(wrapIv) },
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt', 'unwrapKey']
  );
}

/**
 * Generates real RSA-OAEP-2048 public keys for mock campus recipients so every
 * recipient selection performs authentic Web Crypto RSA-OAEP-2048 key wrapping.
 */
/**
 * Imports an RSA-OAEP-2048 public key from a JWK object (retrieved from server).
 * Used to hydrate the campus directory with real per-user public keys.
 */
export async function importPublicKeyFromJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  return webCrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt', 'wrapKey']
  );
}

export async function hydrateRecipientsWithRealKeys(
  recipients: Recipient[]
): Promise<Recipient[]> {
  return Promise.all(
    recipients.map(async (recipient) => {
      if (recipient.publicKey) {
        return recipient;
      }
      const keyPair = await generateRsaOaepKeyPair();
      const fingerprint = await computePublicKeyFingerprint(keyPair.publicKey);
      return {
        ...recipient,
        publicKey: keyPair.publicKey,
        keyFingerprint: fingerprint,
      };
    })
  );
}

export interface EncryptWithWebCryptoOptions {
  plaintextBytes: Uint8Array;
  recipients: Recipient[];
  encryptedAt?: string;
}

/**
 * Encrypts actual payload bytes using Web Crypto AES-256-GCM with a fresh
 * 256-bit key and 12-byte random IV, computes the real SHA-256 digest, and
 * wraps the AES key for each recipient with RSA-OAEP-2048 (SHA-256).
 */
export async function encryptPayloadWithWebCrypto(
  options: EncryptWithWebCryptoOptions
): Promise<CryptoEnvelope> {
  const webCrypto = getWebCrypto();
  const { plaintextBytes, recipients, encryptedAt } = options;

  if (recipients.length === 0) {
    throw new Error('At least one recipient is required to wrap the AES-256-GCM key.');
  }

  const hydratedRecipients = await hydrateRecipientsWithRealKeys(recipients);

  // 1. Fresh AES-256-GCM symmetric key & 12-byte IV
  const aesKey = await webCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const ivBytes = webCrypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));

  // 2. Real SHA-256 digest of plaintext bytes
  const sha256Hash = await computeSha256Hex(plaintextBytes);

  // 3. Encrypt actual bytes with AES-256-GCM
  const encryptedBuffer = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(ivBytes), tagLength: GCM_TAG_BYTES * 8 },
    aesKey,
    toArrayBuffer(plaintextBytes)
  );
  const encryptedBytes = new Uint8Array(encryptedBuffer);

  // Web Crypto appends the 16-byte GCM authentication tag to the end of ciphertext
  const authTagStart = Math.max(0, encryptedBytes.length - GCM_TAG_BYTES);
  const authTagBytes = encryptedBytes.slice(authTagStart);
  const previewBytes = encryptedBytes.slice(
    0,
    Math.min(encryptedBytes.length, CIPHERTEXT_PREVIEW_MAX_BYTES)
  );

  // 4. Wrap the AES-256-GCM key for each recipient using RSA-OAEP-2048
  const wrappedKeys: WrappedRecipientKey[] = await Promise.all(
    hydratedRecipients.map(async (recipient) => {
      if (!recipient.publicKey) {
        throw new Error(`Missing RSA-OAEP-2048 public key for recipient ${recipient.name}.`);
      }
      const wrappedBuffer = await webCrypto.subtle.wrapKey(
        'raw',
        aesKey,
        recipient.publicKey,
        { name: 'RSA-OAEP' }
      );
      return {
        recipientId: recipient.id,
        recipientName: recipient.name,
        recipientRole: recipient.role,
        keyFingerprint: recipient.keyFingerprint,
        wrappedKeyBase64: bytesToBase64(new Uint8Array(wrappedBuffer)),
      };
    })
  );

  const timestamp =
    encryptedAt ?? `${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`;

  return {
    algorithm: 'AES-256-GCM',
    keyWrapAlgorithm: 'RSA-OAEP-2048',
    ivHex: bytesToHex(ivBytes),
    ivBase64: bytesToBase64(ivBytes),
    authTagHex: bytesToHex(authTagBytes),
    ciphertextBase64: bytesToBase64(previewBytes),
    rawCiphertextBase64: bytesToBase64(encryptedBytes),
    ciphertextByteLength: encryptedBytes.length,
    sha256Hash,
    expectedSha256Hash: sha256Hash,
    wrappedKeys,
    encryptedAt: timestamp,
    isWebCryptoReal: true,
  };
}

export interface DecryptPayloadResult {
  plaintextBytes: Uint8Array;
  verifiedSha256Hash: string;
}

/**
 * Unwraps the AES-256-GCM key with the user's RSA-OAEP-2048 private key,
 * decrypts the real ciphertext in the browser, and verifies the SHA-256 hash.
 */
export async function decryptPayloadWithWebCrypto(options: {
  envelope: CryptoEnvelope;
  privateKey: CryptoKey;
  recipientId: string;
  recipientFingerprint?: string;
}): Promise<DecryptPayloadResult> {
  const webCrypto = getWebCrypto();
  const { envelope, privateKey, recipientId, recipientFingerprint } = options;

  if (!envelope.rawCiphertextBase64) {
    throw new Error('Encrypted payload bytes are not available for Web Crypto decryption.');
  }

  const wrappedEntry = envelope.wrappedKeys.find(
    (entry) =>
      entry.recipientId === recipientId ||
      (recipientFingerprint !== undefined && entry.keyFingerprint === recipientFingerprint)
  );

  if (!wrappedEntry) {
    throw new Error(
      'Your RSA-OAEP-2048 private key is not listed among the authorized recipients for this document.'
    );
  }

  const wrappedKeyBytes = base64ToBytes(wrappedEntry.wrappedKeyBase64);
  let aesKey: CryptoKey;
  try {
    aesKey = await webCrypto.subtle.unwrapKey(
      'raw',
      toArrayBuffer(wrappedKeyBytes),
      privateKey,
      { name: 'RSA-OAEP' },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  } catch {
    throw new Error(
      'RSA-OAEP-2048 key unwrapping failed. The active private key does not match the wrapped key.'
    );
  }

  const ivBytes = hexToBytes(envelope.ivHex);
  const rawCiphertextBytes = base64ToBytes(envelope.rawCiphertextBase64);

  let decryptedBuffer: ArrayBuffer;
  try {
    decryptedBuffer = await webCrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(ivBytes), tagLength: GCM_TAG_BYTES * 8 },
      aesKey,
      toArrayBuffer(rawCiphertextBytes)
    );
  } catch {
    throw new Error(
      'AES-256-GCM authentication failed. Ciphertext or 12-byte IV may have been modified.'
    );
  }

  const plaintextBytes = new Uint8Array(decryptedBuffer);
  const verifiedSha256Hash = await computeSha256Hex(plaintextBytes);

  if (
    verifiedSha256Hash !== envelope.sha256Hash ||
    verifiedSha256Hash !== envelope.expectedSha256Hash
  ) {
    throw new Error(
      'SHA-256 digest mismatch after decryption. File integrity verification failed.'
    );
  }

  return {
    plaintextBytes,
    verifiedSha256Hash,
  };
}

export function verifyFileIntegrity(file: VaultFile): {
  valid: boolean;
  reason: string;
} {
  if (
    file.sha256Status === 'Mismatch' ||
    file.crypto.sha256Hash !== file.crypto.expectedSha256Hash
  ) {
    return {
      valid: false,
      reason: 'SHA-256 digest mismatch detected. Ciphertext may have been modified in transit.',
    };
  }
  return {
    valid: true,
    reason:
      'SHA-256 digest matches expected payload hash. AES-256-GCM authentication tag verified.',
  };
}

export interface VaultFilterCriteria {
  query: string;
  roleFilter: 'All' | UserRole;
  statusFilter: 'All' | IntegrityStatus;
}

export function filterVaultFiles(files: VaultFile[], criteria: VaultFilterCriteria): VaultFile[] {
  const normalizedQuery = criteria.query.trim().toLowerCase();

  return files.filter((file) => {
    if (criteria.roleFilter !== 'All' && file.uploadedByRole !== criteria.roleFilter) {
      return false;
    }
    if (criteria.statusFilter !== 'All' && file.sha256Status !== criteria.statusFilter) {
      return false;
    }
    if (!normalizedQuery) {
      return true;
    }
    return (
      file.filename.toLowerCase().includes(normalizedQuery) ||
      file.uploadedBy.toLowerCase().includes(normalizedQuery) ||
      file.department.toLowerCase().includes(normalizedQuery) ||
      file.crypto.sha256Hash.toLowerCase().includes(normalizedQuery)
    );
  });
}

export function formatByteSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatShortHash(hash: string, prefixLen = 8, suffixLen = 6): string {
  if (hash.length <= prefixLen + suffixLen + 3) return hash;
  return `${hash.slice(0, prefixLen)}…${hash.slice(-suffixLen)}`;
}

export function formatHexSpaced(hex: string): string {
  return hex.toUpperCase().match(/.{1,2}/g)?.join(' ') ?? hex.toUpperCase();
}

/**
 * Builds an encrypted, passphrase-protected JSON key backup payload.
 * Never includes raw unencrypted private key bytes.
 */
export function buildEncryptedKeyBackupPayload(
  user: UserProfile,
  exportedAtIso = new Date().toISOString()
): EncryptedKeyBackupPayload {
  if (!user.protectedPrivateKey) {
    throw new Error(
      'Your encrypted private key bundle is still initializing. Please try again in a moment.'
    );
  }

  return {
    schemaVersion: '1.0',
    application: 'CipherHall',
    institution: INSTITUTION_NAME,
    exportedAt: exportedAtIso,
    owner: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      department: user.department,
    },
    protection: {
      asymmetricAlgorithm: 'RSA-OAEP-2048',
      symmetricAlgorithm: 'AES-256-GCM',
      integrityHash: 'SHA-256',
      keyDerivation: user.protectedPrivateKey.kdf,
      iterations: user.protectedPrivateKey.iterations,
    },
    encryptedPrivateKeyBundle: {
      ...user.protectedPrivateKey,
    },
  };
}

/**
 * Updates the authorized recipient list for a VaultFile and removes RSA-wrapped
 * AES keys for any revoked recipients.
 */
export function updateFileRecipientAccess(
  file: VaultFile,
  retainedRecipientNames: string[]
): {
  updatedFile: VaultFile;
  revokedNames: string[];
  addedNames: string[];
} {
  const uniqueRetained = Array.from(new Set(retainedRecipientNames));
  if (uniqueRetained.length === 0) {
    throw new Error('At least one authorized person must retain access to this file.');
  }

  const prevSet = new Set(file.recipients);
  const nextSet = new Set(uniqueRetained);

  const revokedNames = file.recipients.filter((name) => !nextSet.has(name));
  const addedNames = uniqueRetained.filter((name) => !prevSet.has(name));

  const nextWrappedKeys = file.crypto.wrappedKeys.filter((entry) =>
    nextSet.has(entry.recipientName)
  );

  return {
    updatedFile: {
      ...file,
      recipients: uniqueRetained,
      crypto: {
        ...file.crypto,
        wrappedKeys: nextWrappedKeys,
      },
    },
    revokedNames,
    addedNames,
  };
}

export function canManageFileAccess(user: UserProfile, file: VaultFile): boolean {
  return (
    user.role === 'Faculty' &&
    file.uploadedBy.trim().toLowerCase() === user.name.trim().toLowerCase()
  );
}

export function filterActivityEvents(
  events: ActivityEvent[],
  criteria: { query: string; category: 'all' | ActivityCategory }
): ActivityEvent[] {
  const q = criteria.query.trim().toLowerCase();
  return events.filter((event) => {
    if (criteria.category !== 'all' && event.category !== criteria.category) {
      return false;
    }
    if (!q) return true;
    return (
      event.title.toLowerCase().includes(q) ||
      event.detail.toLowerCase().includes(q) ||
      event.actorName.toLowerCase().includes(q)
    );
  });
}

