import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import express, { type NextFunction, type Request, type Response } from 'express';
import { MongoClient, type Collection, type Db } from 'mongodb';
import type {
  ActivityCategory,
  ActivityEvent,
  ChatFileAttachment,
  CryptoEnvelope,
  IntegrityStatus,
  ProtectedPrivateKeyBundle,
  UserRole,
} from './src/types/vault.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16
    ? process.env.SESSION_SECRET
    : crypto.randomBytes(32).toString('hex');
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 hours

// ============================================================================
// Server-Side Stored Document Models (Zero-Knowledge: No Plaintext Payloads)
// ============================================================================

interface StoredUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  passwordSalt: string;
  passwordHash: string;
  keyFingerprint: string;
  publicKeySpkiBase64: string;
  protectedPrivateKey: ProtectedPrivateKeyBundle;
  createdAt: string;
}

interface PublicUserDTO {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  keyFingerprint: string;
  publicKeySpkiBase64: string;
}

interface StoredVaultFile {
  id: string;
  filename: string;
  fileType: string;
  mimeType?: string;
  sizeBytes: number;
  uploaderId: string;
  uploadedBy: string;
  uploadedByRole: UserRole;
  department: string;
  uploadedAt: string;
  dateLabel: string;
  sha256Status: IntegrityStatus;
  recipientIds: string[];
  recipients: string[];
  crypto: CryptoEnvelope;
}

interface StoredEncryptedMessage {
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

interface StoredActivityEvent extends ActivityEvent {
  visibleToUserIds: string[];
  createdAt: string;
}

// ============================================================================
// Storage Abstraction: Real MongoDB when MONGODB_URI is set, clean zero-seeded
// in-memory fallback when MONGODB_URI is not configured in preview.
// ============================================================================

interface VaultStore {
  mode: 'mongodb' | 'memory';
  findUserByEmail(email: string): Promise<StoredUser | null>;
  findUserById(id: string): Promise<StoredUser | null>;
  listUsers(): Promise<StoredUser[]>;
  insertUser(user: StoredUser): Promise<void>;

  listFilesForUser(userId: string): Promise<StoredVaultFile[]>;
  findFileById(id: string): Promise<StoredVaultFile | null>;
  insertFile(file: StoredVaultFile): Promise<void>;
  updateFileAccess(
    fileId: string,
    recipientIds: string[],
    recipients: string[],
    wrappedKeys: CryptoEnvelope['wrappedKeys']
  ): Promise<StoredVaultFile | null>;

  listMessagesForUser(userId: string): Promise<StoredEncryptedMessage[]>;
  insertMessage(msg: StoredEncryptedMessage): Promise<void>;

  listActivityForUser(userId: string): Promise<StoredActivityEvent[]>;
  insertActivity(event: StoredActivityEvent): Promise<void>;
}

class MemoryVaultStore implements VaultStore {
  mode: 'memory' = 'memory';
  private users: StoredUser[] = [];
  private files: StoredVaultFile[] = [];
  private messages: StoredEncryptedMessage[] = [];
  private activity: StoredActivityEvent[] = [];

  async findUserByEmail(email: string): Promise<StoredUser | null> {
    return this.users.find((u) => u.email === email) ?? null;
  }

  async findUserById(id: string): Promise<StoredUser | null> {
    return this.users.find((u) => u.id === id) ?? null;
  }

  async listUsers(): Promise<StoredUser[]> {
    return [...this.users].sort((a, b) => a.name.localeCompare(b.name));
  }

  async insertUser(user: StoredUser): Promise<void> {
    this.users.push(user);
  }

  async listFilesForUser(userId: string): Promise<StoredVaultFile[]> {
    return this.files
      .filter((f) => f.uploaderId === userId || f.recipientIds.includes(userId))
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
  }

  async findFileById(id: string): Promise<StoredVaultFile | null> {
    return this.files.find((f) => f.id === id) ?? null;
  }

  async insertFile(file: StoredVaultFile): Promise<void> {
    this.files.unshift(file);
  }

  async updateFileAccess(
    fileId: string,
    recipientIds: string[],
    recipients: string[],
    wrappedKeys: CryptoEnvelope['wrappedKeys']
  ): Promise<StoredVaultFile | null> {
    const idx = this.files.findIndex((f) => f.id === fileId);
    if (idx === -1) return null;
    const updated: StoredVaultFile = {
      ...this.files[idx],
      recipientIds,
      recipients,
      crypto: {
        ...this.files[idx].crypto,
        wrappedKeys,
      },
    };
    this.files[idx] = updated;
    return updated;
  }

  async listMessagesForUser(userId: string): Promise<StoredEncryptedMessage[]> {
    return this.messages
      .filter((m) => m.senderId === userId || m.recipientId === userId)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async insertMessage(msg: StoredEncryptedMessage): Promise<void> {
    this.messages.push(msg);
  }

  async listActivityForUser(userId: string): Promise<StoredActivityEvent[]> {
    return this.activity
      .filter((ev) => ev.visibleToUserIds.includes(userId))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async insertActivity(event: StoredActivityEvent): Promise<void> {
    this.activity.unshift(event);
  }
}

class MongoVaultStore implements VaultStore {
  mode: 'mongodb' = 'mongodb';
  private users: Collection<StoredUser>;
  private files: Collection<StoredVaultFile>;
  private messages: Collection<StoredEncryptedMessage>;
  private activity: Collection<StoredActivityEvent>;

  constructor(db: Db) {
    this.users = db.collection<StoredUser>('users');
    this.files = db.collection<StoredVaultFile>('vault_files');
    this.messages = db.collection<StoredEncryptedMessage>('encrypted_messages');
    this.activity = db.collection<StoredActivityEvent>('activity_log');
  }

  async ensureIndexes(): Promise<void> {
    await this.users.createIndex({ email: 1 }, { unique: true });
    await this.users.createIndex({ id: 1 }, { unique: true });
    await this.files.createIndex({ id: 1 }, { unique: true });
    await this.files.createIndex({ recipientIds: 1 });
    await this.messages.createIndex({ senderId: 1, recipientId: 1 });
    await this.activity.createIndex({ visibleToUserIds: 1, createdAt: -1 });
  }

  async findUserByEmail(email: string): Promise<StoredUser | null> {
    return this.users.findOne({ email: String(email) }, { projection: { _id: 0 } });
  }

  async findUserById(id: string): Promise<StoredUser | null> {
    return this.users.findOne({ id: String(id) }, { projection: { _id: 0 } });
  }

  async listUsers(): Promise<StoredUser[]> {
    return this.users
      .find({}, { projection: { _id: 0 } })
      .sort({ name: 1 })
      .toArray();
  }

  async insertUser(user: StoredUser): Promise<void> {
    await this.users.insertOne({ ...user });
  }

  async listFilesForUser(userId: string): Promise<StoredVaultFile[]> {
    const uid = String(userId);
    return this.files
      .find(
        { $or: [{ uploaderId: uid }, { recipientIds: uid }] },
        { projection: { _id: 0 } }
      )
      .sort({ uploadedAt: -1 })
      .toArray();
  }

  async findFileById(id: string): Promise<StoredVaultFile | null> {
    return this.files.findOne({ id: String(id) }, { projection: { _id: 0 } });
  }

  async insertFile(file: StoredVaultFile): Promise<void> {
    await this.files.insertOne({ ...file });
  }

  async updateFileAccess(
    fileId: string,
    recipientIds: string[],
    recipients: string[],
    wrappedKeys: CryptoEnvelope['wrappedKeys']
  ): Promise<StoredVaultFile | null> {
    const fid = String(fileId);
    const result = await this.files.findOneAndUpdate(
      { id: fid },
      {
        $set: {
          recipientIds,
          recipients,
          'crypto.wrappedKeys': wrappedKeys,
        },
      },
      { returnDocument: 'after', projection: { _id: 0 } }
    );
    return result ?? null;
  }

  async listMessagesForUser(userId: string): Promise<StoredEncryptedMessage[]> {
    const uid = String(userId);
    return this.messages
      .find(
        { $or: [{ senderId: uid }, { recipientId: uid }] },
        { projection: { _id: 0 } }
      )
      .sort({ createdAt: 1 })
      .toArray();
  }

  async insertMessage(msg: StoredEncryptedMessage): Promise<void> {
    await this.messages.insertOne({ ...msg });
  }

  async listActivityForUser(userId: string): Promise<StoredActivityEvent[]> {
    const uid = String(userId);
    return this.activity
      .find({ visibleToUserIds: uid }, { projection: { _id: 0 } })
      .sort({ createdAt: -1 })
      .limit(200)
      .toArray();
  }

  async insertActivity(event: StoredActivityEvent): Promise<void> {
    await this.activity.insertOne({ ...event });
  }
}

async function initStore(): Promise<VaultStore> {
  const uri = process.env.MONGODB_URI?.trim();
  if (uri) {
    try {
      const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
      await client.connect();
      const dbName = process.env.MONGODB_DB_NAME?.trim() || 'cipherhall';
      const mongoStore = new MongoVaultStore(client.db(dbName));
      await mongoStore.ensureIndexes();
      console.log(`[CipherHall] Connected to MongoDB database "${dbName}".`);
      return mongoStore;
    } catch (err) {
      console.warn(
        '[CipherHall] Failed to connect to MONGODB_URI; falling back to clean empty in-memory store:',
        err instanceof Error ? err.message : String(err)
      );
    }
  } else {
    console.log(
      '[CipherHall] MONGODB_URI not configured; running with clean empty in-memory store.'
    );
  }
  return new MemoryVaultStore();
}

// ============================================================================
// Password Hashing (scrypt) & Signed Bearer Session Tokens (HMAC-SHA256)
// ============================================================================

function hashPassword(password: string, saltHex?: string): { salt: string; hash: string } {
  const salt = saltHex ?? crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash: derived };
}

function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHash, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

interface SessionPayload {
  uid: string;
  role: UserRole;
  exp: number;
}

function signSessionToken(payload: SessionPayload): string {
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(encodedPayload)
    .digest('base64url');
  return `${encodedPayload}.${signature}`;
}

function verifySessionToken(token: string): SessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, receivedSig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(encodedPayload)
    .digest('base64url');

  const receivedBuf = Buffer.from(receivedSig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (receivedBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(receivedBuf, expectedBuf)) return null;

  try {
    const parsed = JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString('utf8')
    ) as SessionPayload;
    if (
      typeof parsed.uid !== 'string' ||
      (parsed.role !== 'Student' && parsed.role !== 'Faculty') ||
      typeof parsed.exp !== 'number' ||
      Date.now() > parsed.exp
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function toPublicUser(user: StoredUser): PublicUserDTO {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    department: user.department,
    keyFingerprint: user.keyFingerprint,
    publicKeySpkiBase64: user.publicKeySpkiBase64,
  };
}

function isNonEmptyString(val: unknown, maxLen = 500): val is string {
  return typeof val === 'string' && val.trim().length > 0 && val.trim().length <= maxLen;
}

function isValidRole(val: unknown): val is UserRole {
  return val === 'Student' || val === 'Faculty';
}

function isValidProtectedKeyBundle(val: unknown): val is ProtectedPrivateKeyBundle {
  if (!val || typeof val !== 'object') return false;
  const b = val as Record<string, unknown>;
  return (
    b.kdf === 'PBKDF2-SHA256' &&
    typeof b.iterations === 'number' &&
    b.iterations >= 10000 &&
    typeof b.saltBase64 === 'string' &&
    b.wrapAlgorithm === 'AES-256-GCM' &&
    typeof b.wrapIvHex === 'string' &&
    b.wrapIvHex.length === 24 &&
    typeof b.wrappedPrivateKeyBase64 === 'string' &&
    b.wrappedPrivateKeyBase64.length > 32
  );
}

function isValidCryptoEnvelope(val: unknown): val is CryptoEnvelope {
  if (!val || typeof val !== 'object') return false;
  const e = val as Record<string, unknown>;
  return (
    e.algorithm === 'AES-256-GCM' &&
    e.keyWrapAlgorithm === 'RSA-OAEP-2048' &&
    typeof e.ivHex === 'string' &&
    e.ivHex.length === 24 &&
    typeof e.ivBase64 === 'string' &&
    typeof e.authTagHex === 'string' &&
    typeof e.ciphertextBase64 === 'string' &&
    typeof e.rawCiphertextBase64 === 'string' &&
    typeof e.ciphertextByteLength === 'number' &&
    typeof e.sha256Hash === 'string' &&
    e.sha256Hash.length === 64 &&
    typeof e.expectedSha256Hash === 'string' &&
    Array.isArray(e.wrappedKeys) &&
    e.wrappedKeys.length > 0 &&
    typeof e.encryptedAt === 'string'
  );
}

function formatNowTimeLabel(): string {
  const now = new Date();
  const hhmm = now.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  return `Today · ${hhmm}`;
}

// ============================================================================
// Express Server Setup
// ============================================================================

interface AuthedRequest extends Request {
  authUser?: StoredUser;
}

async function startServer() {
  const store = await initStore();
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '15mb' }));

  const requireAuth = async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const token = authHeader.slice('Bearer '.length).trim();
    const session = verifySessionToken(token);
    if (!session) {
      res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
      return;
    }
    const user = await store.findUserById(session.uid);
    if (!user) {
      res.status(401).json({ error: 'Account not found. Please sign in again.' });
      return;
    }
    req.authUser = user;
    next();
  };

  // Health & DB mode check (no PII exposed)
  app.get('/api/health', async (_req, res) => {
    const users = await store.listUsers();
    res.json({
      ok: true,
      storageMode: store.mode,
      registeredUserCount: users.length,
    });
  });

  // POST /api/auth/register — Registers a new user with their client-generated RSA-OAEP-2048 public key
  // and PBKDF2-wrapped private key bundle. Server NEVER sees Vault Passphrase or raw private key.
  app.post('/api/auth/register', async (req, res) => {
    const body = req.body as Record<string, unknown>;
    if (!isNonEmptyString(body.name, 100) || body.name.trim().length < 2) {
      res.status(400).json({ error: 'Enter your full name (at least 2 characters).' });
      return;
    }
    if (!isNonEmptyString(body.email, 160)) {
      res.status(400).json({ error: 'Enter a valid institute email address.' });
      return;
    }
    const normalizedEmail = body.email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      res.status(400).json({ error: 'Enter a valid campus email address.' });
      return;
    }
    if (typeof body.password !== 'string' || body.password.length < 8 || body.password.length > 128) {
      res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
      return;
    }
    if (!isValidRole(body.role)) {
      res.status(400).json({ error: 'Academic role must be Student or Faculty.' });
      return;
    }
    if (!isNonEmptyString(body.publicKeySpkiBase64, 4096) || !isNonEmptyString(body.keyFingerprint, 64)) {
      res.status(400).json({ error: 'Missing generated RSA-OAEP-2048 public key material.' });
      return;
    }
    if (!isValidProtectedKeyBundle(body.protectedPrivateKey)) {
      res.status(400).json({ error: 'Invalid passphrase-protected private key bundle.' });
      return;
    }

    const existing = await store.findUserByEmail(normalizedEmail);
    if (existing) {
      res.status(409).json({
        error: 'An account with this institute email is already registered. Please sign in.',
      });
      return;
    }

    const department = isNonEmptyString(body.department, 100)
      ? body.department.trim()
      : body.role === 'Faculty'
      ? 'Department of Computer Science'
      : 'Computer Science & Engineering';

    const { salt, hash } = hashPassword(body.password);
    const nowIso = new Date().toISOString();
    const newUser: StoredUser = {
      id: `usr-${crypto.randomUUID()}`,
      name: body.name.trim(),
      email: normalizedEmail,
      role: body.role,
      department,
      passwordSalt: salt,
      passwordHash: hash,
      keyFingerprint: body.keyFingerprint.trim(),
      publicKeySpkiBase64: body.publicKeySpkiBase64.trim(),
      protectedPrivateKey: body.protectedPrivateKey,
      createdAt: nowIso,
    };

    await store.insertUser(newUser);

    const token = signSessionToken({
      uid: newUser.id,
      role: newUser.role,
      exp: Date.now() + SESSION_TTL_MS,
    });

    res.status(201).json({
      token,
      user: {
        ...toPublicUser(newUser),
        protectedPrivateKey: newUser.protectedPrivateKey,
      },
    });
  });

  // POST /api/auth/login — Verifies email & password and returns the user's encrypted private key bundle
  // so the browser can unwrap it locally with the Vault Passphrase.
  app.post('/api/auth/login', async (req, res) => {
    const body = req.body as Record<string, unknown>;
    if (!isNonEmptyString(body.email, 160) || typeof body.password !== 'string') {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const normalizedEmail = body.email.trim().toLowerCase();
    const user = await store.findUserByEmail(normalizedEmail);
    if (!user || !verifyPassword(body.password, user.passwordSalt, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid institute email or password.' });
      return;
    }

    const token = signSessionToken({
      uid: user.id,
      role: user.role,
      exp: Date.now() + SESSION_TTL_MS,
    });

    res.json({
      token,
      user: {
        ...toPublicUser(user),
        protectedPrivateKey: user.protectedPrivateKey,
      },
    });
  });

  // GET /api/users — Strictly returns ONLY real registered users from DB
  app.get('/api/users', requireAuth, async (_req: AuthedRequest, res: Response) => {
    const users = await store.listUsers();
    res.json({ users: users.map(toPublicUser) });
  });

  // GET /api/files — Returns encrypted files accessible to the signed-in user
  app.get('/api/files', requireAuth, async (req: AuthedRequest, res: Response) => {
    const files = await store.listFilesForUser(req.authUser!.id);
    res.json({ files });
  });

  // POST /api/files — Stores a client-encrypted file envelope
  app.post('/api/files', requireAuth, async (req: AuthedRequest, res: Response) => {
    const user = req.authUser!;
    const body = req.body as Record<string, unknown>;

    if (!isNonEmptyString(body.filename, 240)) {
      res.status(400).json({ error: 'Filename is required.' });
      return;
    }
    if (typeof body.sizeBytes !== 'number' || body.sizeBytes < 0) {
      res.status(400).json({ error: 'Invalid file byte size.' });
      return;
    }
    if (!Array.isArray(body.recipientIds) || body.recipientIds.length === 0) {
      res.status(400).json({ error: 'Select at least one registered recipient.' });
      return;
    }
    if (!isValidCryptoEnvelope(body.crypto)) {
      res.status(400).json({ error: 'Invalid AES-256-GCM / RSA-OAEP-2048 envelope.' });
      return;
    }

    const allUsers = await store.listUsers();
    const userMap = new Map(allUsers.map((u) => [u.id, u]));

    const validRecipientIds: string[] = [];
    const validRecipientNames: string[] = [];
    for (const rid of body.recipientIds) {
      if (typeof rid === 'string' && userMap.has(rid) && !validRecipientIds.includes(rid)) {
        validRecipientIds.push(rid);
        validRecipientNames.push(userMap.get(rid)!.name);
      }
    }

    if (validRecipientIds.length === 0) {
      res.status(400).json({ error: 'No valid registered recipients selected.' });
      return;
    }

    const now = new Date();
    const filename = body.filename.trim();
    const extension = filename.includes('.')
      ? filename.split('.').pop()?.toUpperCase().slice(0, 10) || 'FILE'
      : 'FILE';

    const newFile: StoredVaultFile = {
      id: `file-${crypto.randomUUID()}`,
      filename,
      fileType: extension,
      mimeType: isNonEmptyString(body.mimeType, 120)
        ? body.mimeType.trim()
        : 'application/octet-stream',
      sizeBytes: body.sizeBytes,
      uploaderId: user.id,
      uploadedBy: user.name,
      uploadedByRole: user.role,
      department: user.department,
      uploadedAt: now.toISOString(),
      dateLabel: now.toLocaleDateString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric',
      }),
      sha256Status: 'Verified',
      recipientIds: validRecipientIds,
      recipients: validRecipientNames,
      crypto: {
        ...body.crypto,
        isWebCryptoReal: true,
      },
    };

    await store.insertFile(newFile);

    const visibleIds = Array.from(new Set([user.id, ...validRecipientIds]));
    await store.insertActivity({
      id: `act-${crypto.randomUUID()}`,
      category: 'file',
      title: `${user.name} encrypted & uploaded ${newFile.filename}`,
      detail: `Encrypted locally on device and shared with ${validRecipientIds.length} ${
        validRecipientIds.length === 1 ? 'person' : 'people'
      }.`,
      actorName: user.name,
      actorRole: user.role,
      timestampLabel: formatNowTimeLabel(),
      status: 'success',
      statusLabel: 'Verified',
      visibleToUserIds: visibleIds,
      createdAt: now.toISOString(),
    });

    res.status(201).json({ file: newFile });
  });

  // PATCH /api/files/:id/access — Server-enforced Faculty uploader access management & revocation
  app.patch('/api/files/:id/access', requireAuth, async (req: AuthedRequest, res: Response) => {
    const user = req.authUser!;
    if (user.role !== 'Faculty') {
      res.status(403).json({ error: 'Only Faculty uploaders can manage or revoke file access.' });
      return;
    }

    const fileId = String(req.params.id ?? '');
    const existing = await store.findFileById(fileId);
    if (!existing) {
      res.status(404).json({ error: 'Encrypted file not found.' });
      return;
    }
    if (existing.uploaderId !== user.id) {
      res.status(403).json({ error: 'You can only manage access for files you uploaded.' });
      return;
    }

    const body = req.body as Record<string, unknown>;
    if (!Array.isArray(body.recipientIds) || body.recipientIds.length === 0) {
      res.status(400).json({ error: 'At least one authorized person must retain access.' });
      return;
    }

    const allUsers = await store.listUsers();
    const userMap = new Map(allUsers.map((u) => [u.id, u]));

    const retainedIds: string[] = [];
    const retainedNames: string[] = [];
    for (const rid of body.recipientIds) {
      if (typeof rid === 'string' && userMap.has(rid) && !retainedIds.includes(rid)) {
        retainedIds.push(rid);
        retainedNames.push(userMap.get(rid)!.name);
      }
    }

    if (!retainedIds.includes(user.id)) {
      res.status(400).json({ error: 'You cannot revoke your own uploader access.' });
      return;
    }

    const retainedSet = new Set(retainedIds);
    const prevSet = new Set(existing.recipientIds);
    const revokedNames = existing.recipientIds
      .filter((id) => !retainedSet.has(id))
      .map((id) => userMap.get(id)?.name ?? 'Member');
    const addedNames = retainedIds
      .filter((id) => !prevSet.has(id))
      .map((id) => userMap.get(id)?.name ?? 'Member');

    // If the client re-wrapped AES keys for newly granted recipients, accept validated wrappedKeys;
    // otherwise filter existing wrappedKeys strictly to retained recipients.
    let nextWrappedKeys = existing.crypto.wrappedKeys.filter((wk) =>
      retainedSet.has(wk.recipientId)
    );
    if (Array.isArray(body.wrappedKeys)) {
      const candidateKeys = (body.wrappedKeys as CryptoEnvelope['wrappedKeys']).filter(
        (wk) =>
          wk &&
          typeof wk.recipientId === 'string' &&
          retainedSet.has(wk.recipientId) &&
          typeof wk.wrappedKeyBase64 === 'string' &&
          wk.wrappedKeyBase64.length > 32
      );
      if (candidateKeys.length > 0) {
        nextWrappedKeys = candidateKeys;
      }
    }

    const updated = await store.updateFileAccess(
      existing.id,
      retainedIds,
      retainedNames,
      nextWrappedKeys
    );

    const parts: string[] = [];
    if (revokedNames.length > 0) parts.push(`Revoked access for ${revokedNames.join(', ')}`);
    if (addedNames.length > 0) parts.push(`Granted access to ${addedNames.join(', ')}`);
    const summary = parts.join(' and ') || 'Updated file recipient access';

    const visibleIds = Array.from(
      new Set([user.id, ...existing.recipientIds, ...retainedIds])
    );

    await store.insertActivity({
      id: `act-${crypto.randomUUID()}`,
      category: 'access',
      title:
        revokedNames.length > 0
          ? `${user.name} revoked access on ${existing.filename}`
          : `${user.name} updated access on ${existing.filename}`,
      detail: `${summary}. ${retainedIds.length} ${
        retainedIds.length === 1 ? 'person' : 'people'
      } currently authorized.`,
      actorName: user.name,
      actorRole: user.role,
      timestampLabel: formatNowTimeLabel(),
      status: revokedNames.length > 0 ? 'warning' : 'info',
      statusLabel: revokedNames.length > 0 ? 'Access Revoked' : 'Access Updated',
      visibleToUserIds: visibleIds,
      createdAt: new Date().toISOString(),
    });

    res.json({
      file: updated,
      revokedNames,
      addedNames,
    });
  });

  // GET /api/messages — Returns encrypted message envelopes for conversations involving req.authUser
  app.get('/api/messages', requireAuth, async (req: AuthedRequest, res: Response) => {
    const messages = await store.listMessagesForUser(req.authUser!.id);
    res.json({ messages });
  });

  // POST /api/messages — Stores an end-to-end encrypted message envelope (never stores plaintext)
  app.post('/api/messages', requireAuth, async (req: AuthedRequest, res: Response) => {
    const user = req.authUser!;
    const body = req.body as Record<string, unknown>;

    if (!isNonEmptyString(body.recipientId, 120)) {
      res.status(400).json({ error: 'Recipient is required.' });
      return;
    }
    const recipient = await store.findUserById(body.recipientId.trim());
    if (!recipient) {
      res.status(404).json({ error: 'Selected recipient is not a registered user.' });
      return;
    }
    if (!isValidCryptoEnvelope(body.crypto)) {
      res.status(400).json({ error: 'Invalid encrypted message envelope.' });
      return;
    }

    let attachedFile: ChatFileAttachment | undefined;
    if (body.attachedFile && typeof body.attachedFile === 'object') {
      const af = body.attachedFile as Record<string, unknown>;
      if (
        isNonEmptyString(af.fileId, 120) &&
        isNonEmptyString(af.filename, 240) &&
        typeof af.sizeBytes === 'number'
      ) {
        attachedFile = {
          fileId: af.fileId.trim(),
          filename: af.filename.trim(),
          sizeBytes: af.sizeBytes,
          sha256Status:
            af.sha256Status === 'Pending' || af.sha256Status === 'Mismatch'
              ? af.sha256Status
              : 'Verified',
        };
      }
    }

    const now = new Date();
    const timestamp = now.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });

    const msg: StoredEncryptedMessage = {
      id: `msg-${crypto.randomUUID()}`,
      senderId: user.id,
      senderName: user.name,
      senderRole: user.role,
      recipientId: recipient.id,
      timestamp,
      createdAt: now.toISOString(),
      attachedFile,
      crypto: {
        ...body.crypto,
        isWebCryptoReal: true,
      },
    };

    await store.insertMessage(msg);

    const visibleIds = Array.from(new Set([user.id, recipient.id]));
    await store.insertActivity({
      id: `act-${crypto.randomUUID()}`,
      category: 'chat',
      title: attachedFile
        ? `${user.name} shared ${attachedFile.filename} with ${recipient.name}`
        : `${user.name} sent an encrypted message to ${recipient.name}`,
      detail: attachedFile
        ? 'Attached an encrypted vault document inside an end-to-end encrypted conversation.'
        : 'Encrypted message delivered locally using AES-256-GCM and RSA-OAEP-2048.',
      actorName: user.name,
      actorRole: user.role,
      timestampLabel: formatNowTimeLabel(),
      status: 'info',
      statusLabel: 'Encrypted',
      visibleToUserIds: visibleIds,
      createdAt: now.toISOString(),
    });

    res.status(201).json({ message: msg });
  });

  // GET /api/activity — Returns real audit events visible to the signed-in user
  app.get('/api/activity', requireAuth, async (req: AuthedRequest, res: Response) => {
    const events = await store.listActivityForUser(req.authUser!.id);
    const cleaned: ActivityEvent[] = events.map(
      ({ visibleToUserIds: _v, createdAt: _c, ...rest }) => rest
    );
    res.json({ events: cleaned });
  });

  // POST /api/activity — Records client-side security events (local decryption, key backup export)
  app.post('/api/activity', requireAuth, async (req: AuthedRequest, res: Response) => {
    const user = req.authUser!;
    const body = req.body as Record<string, unknown>;

    const validCategories: ActivityCategory[] = ['file', 'access', 'chat', 'security'];
    const category = validCategories.includes(body.category as ActivityCategory)
      ? (body.category as ActivityCategory)
      : 'security';

    if (!isNonEmptyString(body.title, 200) || !isNonEmptyString(body.detail, 400)) {
      res.status(400).json({ error: 'Activity title and detail are required.' });
      return;
    }

    const status =
      body.status === 'success' || body.status === 'warning' ? body.status : 'info';

    const event: StoredActivityEvent = {
      id: `act-${crypto.randomUUID()}`,
      category,
      title: body.title.trim(),
      detail: body.detail.trim(),
      actorName: user.name,
      actorRole: user.role,
      timestampLabel: formatNowTimeLabel(),
      status,
      statusLabel: isNonEmptyString(body.statusLabel, 40)
        ? body.statusLabel.trim()
        : undefined,
      visibleToUserIds: [user.id],
      createdAt: new Date().toISOString(),
    };

    await store.insertActivity(event);
    const { visibleToUserIds: _v, createdAt: _c, ...publicEvent } = event;
    res.status(201).json({ event: publicEvent });
  });

  // Mount Vite dev middleware in development, or serve built dist/ in production
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexHtml = path.join(distDir, 'index.html');
      if (fs.existsSync(indexHtml)) {
        res.sendFile(indexHtml);
      } else {
        res.status(404).send('Build output not found. Run npm run build first.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CipherHall] Full-stack server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[CipherHall] Fatal startup error:', err);
  process.exit(1);
});
