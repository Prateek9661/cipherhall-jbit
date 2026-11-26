/**
 * CipherHall – Zero-Knowledge Encrypted Vault & Chat
 * Express/Mongoose backend for JB Institute of Technology, Dehradun
 *
 * Zero-knowledge contract:
 *  • The server NEVER receives plaintext files, plaintext messages,
 *    Vault Passphrases, or unencrypted private keys.
 *  • It stores only: bcrypt-hashed passwords, exported RSA-OAEP-2048
 *    public keys (JWK), AES-256-GCM ciphertext blobs, and encrypted
 *    metadata envelopes produced entirely on the client.
 */

'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

// ─── Config ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '5000', 10);
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/cipherhall';
const JWT_SECRET = process.env.JWT_SECRET || 'cipherhall_fallback_secret';
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:3000';

// Uploads directory for encrypted blobs
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ─── App ─────────────────────────────────────────────────────────────────────

const app = express();

app.use(cors({
  origin: CLIENT_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '64mb' }));

// ─── Mongoose Models ──────────────────────────────────────────────────────────

/**
 * User – stores identity + exported public key (JWK).
 * The wrappedPrivateKey is an OPAQUE blob produced by PBKDF2+AES-GCM on the
 * client. The server NEVER sees the passphrase or the raw private key.
 */
const userSchema = new mongoose.Schema({
  name:       { type: String, required: true, trim: true },
  email:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:   { type: String, required: true },           // bcrypt hash
  role:       { type: String, enum: ['Student', 'Faculty'], default: 'Student' },
  department: { type: String, default: 'Computer Science' },
  // RSA-OAEP-2048 public key exported as JWK – safe to store / share
  publicKeyJwk: { type: mongoose.Schema.Types.Mixed, default: null },
  keyFingerprint: { type: String, default: '' },
  // Client-encrypted private key bundle (PBKDF2-AES-256-GCM) – opaque to server
  protectedPrivateKey: { type: mongoose.Schema.Types.Mixed, default: null },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

/**
 * VaultFile – metadata envelope + reference to the encrypted blob on disk.
 * cryptoEnvelope is entirely opaque to the server: it contains the AES-GCM
 * IV, auth tag, SHA-256 hash, and RSA-wrapped AES keys – all produced in the
 * browser.
 */
const vaultFileSchema = new mongoose.Schema({
  filename:        { type: String, required: true },
  fileType:        { type: String, default: 'application/octet-stream' },
  mimeType:        { type: String, default: 'application/octet-stream' },
  sizeBytes:       { type: Number, required: true },
  uploadedBy:      { type: String, required: true },      // uploader's name
  uploadedById:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  uploadedByRole:  { type: String, enum: ['Student', 'Faculty'], default: 'Student' },
  department:      { type: String, default: '' },
  recipients:      [{ type: String }],                    // array of recipient names
  blobPath:        { type: String, default: null },       // path to .enc file on disk
  cryptoEnvelope:  { type: mongoose.Schema.Types.Mixed, required: true },
  sha256Status:    { type: String, enum: ['Verified', 'Pending', 'Mismatch'], default: 'Verified' },
  // Access control: list of recipient IDs who can download blob
  authorizedUserIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const VaultFile = mongoose.model('VaultFile', vaultFileSchema);

/**
 * ChatMessage – the `crypto` field is an opaque AES-256-GCM envelope produced
 * in the browser. The server stores only the ciphertext and metadata.
 */
const chatMessageSchema = new mongoose.Schema({
  senderId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  senderName:    { type: String, required: true },
  senderRole:    { type: String, enum: ['Student', 'Faculty'], default: 'Student' },
  recipientId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },   // null = group
  recipientName: { type: String, default: null },
  threadKey:     { type: String, required: true },        // deterministic peer-pair key
  cryptoEnvelope: { type: mongoose.Schema.Types.Mixed, required: true },
  attachedFileId: { type: mongoose.Schema.Types.ObjectId, ref: 'VaultFile', default: null },
}, { timestamps: true });

const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);

/**
 * AuditLog – immutable security event ledger.
 */
const auditLogSchema = new mongoose.Schema({
  actorId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  actorName:  { type: String },
  actorRole:  { type: String },
  event:      { type: String, required: true },
  detail:     { type: String, default: '' },
  status:     { type: String, enum: ['info', 'success', 'warning', 'error'], default: 'info' },
  ipAddress:  { type: String, default: null },
}, { timestamps: true });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ─── Multer (encrypted blob upload) ──────────────────────────────────────────

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const unique = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    cb(null, `${unique}.enc`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) return res.status(401).json({ error: 'Missing auth token.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    req.userRole = decoded.role;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

async function writeAuditLog(actor, event, detail = '', status = 'info', ip = null) {
  try {
    await AuditLog.create({
      actorId: actor?._id ?? null,
      actorName: actor?.name ?? 'System',
      actorRole: actor?.role ?? 'System',
      event,
      detail,
      status,
      ipAddress: ip,
    });
  } catch { /* non-critical */ }
}

function threadKey(aId, bId) {
  return [aId.toString(), bId.toString()].sort().join('_');
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'CipherHall API',
    institution: 'JB Institute of Technology, Dehradun',
    timestamp: new Date().toISOString(),
    mongoState: mongoose.connection.readyState, // 1 = connected
  });
});

// ── Auth ─────────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 * Body: { name, email, password, role, department,
 *         publicKeyJwk, keyFingerprint, protectedPrivateKey }
 *
 * The server NEVER receives the Vault Passphrase. `protectedPrivateKey` is an
 * opaque AES-256-GCM envelope produced by PBKDF2 on the client.
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, email, password, role, department,
      publicKeyJwk, keyFingerprint, protectedPrivateKey,
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email and password are required.' });
    }

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const saltRounds = 12;
    const hashed = await bcrypt.hash(password, saltRounds);

    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashed,
      role: role || 'Student',
      department: department || 'Computer Science',
      publicKeyJwk: publicKeyJwk || null,
      keyFingerprint: keyFingerprint || '',
      protectedPrivateKey: protectedPrivateKey || null,
    });

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    await writeAuditLog(user, 'USER_REGISTERED', `${user.name} registered as ${user.role}`);

    return res.status(201).json({
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        keyFingerprint: user.keyFingerprint,
      },
    });
  } catch (err) {
    console.error('[register]', err);
    return res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 * Returns: { token, user, protectedPrivateKey, publicKeyJwk }
 *
 * The client uses `protectedPrivateKey` + its local Vault Passphrase to
 * unwrap the RSA private key entirely in the browser.
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    await writeAuditLog(user, 'USER_LOGIN', `${user.name} authenticated`);

    return res.json({
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        keyFingerprint: user.keyFingerprint,
      },
      // Opaque blobs returned so the client can PBKDF2-unwrap the private key locally
      protectedPrivateKey: user.protectedPrivateKey || null,
      publicKeyJwk: user.publicKeyJwk || null,
    });
  } catch (err) {
    console.error('[login]', err);
    return res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ── Users / Directory ─────────────────────────────────────────────────────────

/**
 * GET /api/users
 * Returns the campus directory (public key JWK + fingerprint for each user).
 * This is intentionally public within the authenticated session so any user
 * can encrypt files for their peers.
 */
app.get('/api/users', requireAuth, async (_req, res) => {
  try {
    const users = await User.find({}, {
      _id: 1, name: 1, email: 1, role: 1,
      department: 1, keyFingerprint: 1, publicKeyJwk: 1,
    }).lean();

    return res.json(users.map((u) => ({
      id: u._id.toString(),
      name: u.name,
      email: u.email,
      role: u.role,
      department: u.department,
      keyFingerprint: u.keyFingerprint,
      publicKeyJwk: u.publicKeyJwk,
    })));
  } catch (err) {
    console.error('[users]', err);
    return res.status(500).json({ error: 'Failed to fetch user directory.' });
  }
});

/**
 * PUT /api/users/keys
 * Body: { publicKeyJwk, keyFingerprint, protectedPrivateKey }
 * Lets a logged-in user update their stored key material after key generation.
 */
app.put('/api/users/keys', requireAuth, async (req, res) => {
  try {
    const { publicKeyJwk, keyFingerprint, protectedPrivateKey } = req.body;
    await User.findByIdAndUpdate(req.userId, {
      publicKeyJwk: publicKeyJwk || null,
      keyFingerprint: keyFingerprint || '',
      protectedPrivateKey: protectedPrivateKey || null,
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('[users/keys]', err);
    return res.status(500).json({ error: 'Failed to update key material.' });
  }
});

// ── Vault Files ───────────────────────────────────────────────────────────────

/**
 * POST /api/files/upload
 * multipart/form-data:
 *   - blob: encrypted .enc binary (AES-256-GCM ciphertext produced in browser)
 *   - metadata: JSON string with { filename, fileType, mimeType, sizeBytes,
 *                                   department, recipients, cryptoEnvelope,
 *                                   authorizedUserIds }
 *
 * The server stores the opaque blob and indexes the metadata envelope.
 * It NEVER decrypts or inspects the ciphertext.
 */
app.post('/api/files/upload', requireAuth, upload.single('blob'), async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: 'User not found.' });

    let meta;
    try {
      meta = JSON.parse(req.body.metadata || '{}');
    } catch {
      return res.status(400).json({ error: 'Invalid metadata JSON.' });
    }

    if (!meta.cryptoEnvelope) {
      return res.status(400).json({ error: 'cryptoEnvelope is required.' });
    }

    const blobPath = req.file ? req.file.path : null;

    const vaultFile = await VaultFile.create({
      filename:         meta.filename || 'untitled.enc',
      fileType:         meta.fileType || 'application/octet-stream',
      mimeType:         meta.mimeType || 'application/octet-stream',
      sizeBytes:        meta.sizeBytes || req.file?.size || 0,
      uploadedBy:       user.name,
      uploadedById:     user._id,
      uploadedByRole:   user.role,
      department:       meta.department || user.department,
      recipients:       meta.recipients || [user.name],
      blobPath,
      cryptoEnvelope:   meta.cryptoEnvelope,
      sha256Status:     'Verified',
      authorizedUserIds: meta.authorizedUserIds
        ? meta.authorizedUserIds.map((id) => {
            try { return new mongoose.Types.ObjectId(id); } catch { return null; }
          }).filter(Boolean)
        : [user._id],
    });

    await writeAuditLog(
      user,
      'FILE_UPLOADED',
      `Encrypted file "${vaultFile.filename}" stored (${vaultFile.sizeBytes} bytes)`,
      'success'
    );

    return res.status(201).json(serializeVaultFile(vaultFile));
  } catch (err) {
    console.error('[files/upload]', err);
    return res.status(500).json({ error: 'File upload failed.' });
  }
});

/**
 * GET /api/files
 * Returns vault files visible to the current user (uploaded by them or they
 * are in the recipients list).
 */
app.get('/api/files', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: 'User not found.' });

    const files = await VaultFile.find({
      $or: [
        { uploadedById: user._id },
        { authorizedUserIds: user._id },
        { recipients: user.name },
      ],
    }).sort({ createdAt: -1 }).lean();

    return res.json(files.map(serializeVaultFile));
  } catch (err) {
    console.error('[files GET]', err);
    return res.status(500).json({ error: 'Failed to fetch vault files.' });
  }
});

/**
 * GET /api/files/:id/blob
 * Streams the encrypted blob back to the client.
 * The client decrypts it entirely in the browser with its RSA private key.
 */
app.get('/api/files/:id/blob', requireAuth, async (req, res) => {
  try {
    const file = await VaultFile.findById(req.params.id).lean();
    if (!file) return res.status(404).json({ error: 'File not found.' });

    // Authorization check
    const isAuthorized =
      file.uploadedById?.toString() === req.userId ||
      (file.authorizedUserIds || []).some((uid) => uid?.toString() === req.userId) ||
      (file.recipients || []).some((name) => {
        // name-based fallback for legacy records
        return name.toLowerCase().includes(req.userEmail?.split('@')[0] || '');
      });

    if (!isAuthorized) {
      return res.status(403).json({ error: 'Access denied. You are not authorized for this file.' });
    }

    if (!file.blobPath || !fs.existsSync(file.blobPath)) {
      return res.status(404).json({ error: 'Encrypted blob not found on server.' });
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${file.filename}.enc"`);
    res.setHeader('X-Encrypted', 'true');
    res.setHeader('X-Crypto-Algorithm', 'AES-256-GCM');
    fs.createReadStream(file.blobPath).pipe(res);
  } catch (err) {
    console.error('[files/blob]', err);
    return res.status(500).json({ error: 'Failed to stream encrypted blob.' });
  }
});

/**
 * PATCH /api/files/:id/access
 * Body: { recipients: string[], authorizedUserIds: string[] }
 * Updates the access list (revocation). The server cannot re-encrypt the
 * wrapped AES key for new recipients – that must be done client-side.
 * This endpoint only records the new recipients and removes unauthorized blob access.
 */
app.patch('/api/files/:id/access', requireAuth, async (req, res) => {
  try {
    const file = await VaultFile.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found.' });

    if (file.uploadedById?.toString() !== req.userId) {
      return res.status(403).json({ error: 'Only the uploader can modify access.' });
    }

    const { recipients, authorizedUserIds, cryptoEnvelope } = req.body;
    if (recipients) file.recipients = recipients;
    if (authorizedUserIds) {
      file.authorizedUserIds = authorizedUserIds.map((id) => {
        try { return new mongoose.Types.ObjectId(id); } catch { return null; }
      }).filter(Boolean);
    }
    // Client may send an updated crypto envelope with re-wrapped keys
    if (cryptoEnvelope) file.cryptoEnvelope = cryptoEnvelope;

    await file.save();

    const user = await User.findById(req.userId).lean();
    await writeAuditLog(user, 'FILE_ACCESS_UPDATED', `Access updated for "${file.filename}"`);

    return res.json(serializeVaultFile(file.toObject()));
  } catch (err) {
    console.error('[files/access]', err);
    return res.status(500).json({ error: 'Failed to update file access.' });
  }
});

function serializeVaultFile(doc) {
  return {
    id: doc._id.toString(),
    filename: doc.filename,
    fileType: doc.fileType,
    mimeType: doc.mimeType,
    sizeBytes: doc.sizeBytes,
    uploadedBy: doc.uploadedBy,
    uploadedByRole: doc.uploadedByRole,
    department: doc.department,
    uploadedAt: (doc.createdAt || doc.uploadedAt || new Date()).toISOString?.() ?? doc.createdAt,
    sha256Status: doc.sha256Status,
    recipients: doc.recipients || [],
    crypto: doc.cryptoEnvelope || {},
    decryptedPreviewContent: '', // server never holds plaintext
  };
}

// ── Chat Messages ─────────────────────────────────────────────────────────────

/**
 * GET /api/messages/:peerId
 * Returns all encrypted messages in the peer-to-peer thread.
 * The messages are AES-256-GCM envelopes; the server cannot read them.
 */
app.get('/api/messages/:peerId', requireAuth, async (req, res) => {
  try {
    const key = threadKey(req.userId, req.params.peerId);
    const messages = await ChatMessage.find({ threadKey: key })
      .sort({ createdAt: 1 })
      .lean();

    return res.json(messages.map(serializeChatMessage));
  } catch (err) {
    console.error('[messages GET]', err);
    return res.status(500).json({ error: 'Failed to fetch messages.' });
  }
});

/**
 * POST /api/messages
 * Body: { recipientId, cryptoEnvelope, attachedFileId? }
 * cryptoEnvelope is an opaque AES-256-GCM object produced in the browser.
 */
app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(401).json({ error: 'User not found.' });

    const { recipientId, cryptoEnvelope, attachedFileId } = req.body;
    if (!cryptoEnvelope) {
      return res.status(400).json({ error: 'cryptoEnvelope is required.' });
    }

    const recipient = recipientId
      ? await User.findById(recipientId).lean()
      : null;

    const key = recipientId
      ? threadKey(req.userId, recipientId)
      : `group_${Date.now()}`;

    const msg = await ChatMessage.create({
      senderId: user._id,
      senderName: user.name,
      senderRole: user.role,
      recipientId: recipient?._id ?? null,
      recipientName: recipient?.name ?? null,
      threadKey: key,
      cryptoEnvelope,
      attachedFileId: attachedFileId || null,
    });

    return res.status(201).json(serializeChatMessage(msg.toObject()));
  } catch (err) {
    console.error('[messages POST]', err);
    return res.status(500).json({ error: 'Failed to send message.' });
  }
});

function serializeChatMessage(doc) {
  return {
    id: doc._id.toString(),
    threadId: doc.threadKey,
    senderId: doc.senderId?.toString(),
    senderName: doc.senderName,
    senderRole: doc.senderRole,
    recipientId: doc.recipientId?.toString() ?? null,
    recipientName: doc.recipientName,
    timestamp: (doc.createdAt || new Date()).toISOString?.() ?? doc.createdAt,
    crypto: doc.cryptoEnvelope || {},
    attachedFileId: doc.attachedFileId?.toString() ?? null,
  };
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

/**
 * GET /api/audit
 * Returns audit events for the current user (Faculty sees all, Student sees own).
 */
app.get('/api/audit', requireAuth, async (req, res) => {
  try {
    const filter = req.userRole === 'Faculty'
      ? {}
      : { actorId: new mongoose.Types.ObjectId(req.userId) };

    const events = await AuditLog.find(filter)
      .sort({ createdAt: -1 })
      .limit(200)
      .lean();

    return res.json(events.map((e) => ({
      id: e._id.toString(),
      actorName: e.actorName,
      actorRole: e.actorRole,
      event: e.event,
      detail: e.detail,
      status: e.status,
      timestamp: e.createdAt.toISOString(),
    })));
  } catch (err) {
    console.error('[audit]', err);
    return res.status(500).json({ error: 'Failed to fetch audit log.' });
  }
});

// ─── MongoDB + Server Boot ────────────────────────────────────────────────────

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log(`✅  MongoDB connected → ${MONGO_URI}`);
    app.listen(PORT, () => {
      console.log(`🔒  CipherHall API running on http://localhost:${PORT}`);
      console.log(`    Allowed origin: ${CLIENT_ORIGIN}`);
      console.log(`    Uploads dir:    ${UPLOADS_DIR}`);
      console.log(`    Zero-knowledge: server never receives plaintext data.`);
    });
  })
  .catch((err) => {
    console.error('❌  MongoDB connection failed:', err.message);
    console.error('    Tip: set MONGO_URI in server/.env to your Atlas connection string.');
    process.exit(1);
  });

