import test from 'node:test';
import assert from 'node:assert/strict';
import {
  base64ToBytes,
  buildEncryptedKeyBackupPayload,
  bytesToBase64,
  canManageFileAccess,
  computeSha256Hex,
  decryptPayloadWithWebCrypto,
  encryptPayloadWithWebCrypto,
  evaluatePassphraseStrength,
  filterActivityEvents,
  filterVaultFiles,
  formatByteSize,
  formatHexSpaced,
  formatShortHash,
  generateUserKeyBundle,
  INSTITUTION_NAME,
  PBKDF2_ITERATIONS,
  unlockPrivateKeyWithPassphrase,
  updateFileRecipientAccess,
  validateAuthForm,
  verifyFileIntegrity,
} from './cryptoEngine';
import type { ActivityEvent, Recipient, UserProfile, VaultFile } from '../types/vault';

test('validateAuthForm rejects missing required fields and invalid email', () => {
  const emptyRegister = validateAuthForm({
    mode: 'register',
    name: '',
    email: 'not-an-email',
    password: '123',
    role: 'Student',
    passphrase: '',
  });
  assert.equal(emptyRegister.valid, false);
  assert.ok(emptyRegister.errors.name);
  assert.ok(emptyRegister.errors.email);
  assert.ok(emptyRegister.errors.password);
  assert.ok(emptyRegister.errors.passphrase);

  const validLogin = validateAuthForm({
    mode: 'login',
    name: '',
    email: 'm.lin@jbitdoon.edu.in',
    password: 'strongpassword123',
    role: 'Student',
    passphrase: 'orbit-cedar-cipher-9',
  });
  assert.equal(validLogin.valid, true);
  assert.deepEqual(validLogin.errors, {});
});

test('evaluatePassphraseStrength classifies passphrases accurately', () => {
  assert.equal(evaluatePassphraseStrength('').label, 'Empty');
  assert.equal(evaluatePassphraseStrength('abc').label, 'Weak');
  assert.equal(evaluatePassphraseStrength('campus99').label, 'Fair');
  assert.equal(evaluatePassphraseStrength('CampusVault2026!').label, 'Hardened');
});

test('generateUserKeyBundle creates real RSA-OAEP-2048 key pair protected by PBKDF2-SHA256 Vault Passphrase', async () => {
  const passphrase = 'cedar-lattice-vault-2026';
  const bundle = await generateUserKeyBundle(passphrase);

  assert.equal(bundle.publicKey.algorithm.name, 'RSA-OAEP');
  assert.equal(bundle.privateKey.algorithm.name, 'RSA-OAEP');
  assert.equal(bundle.protectedPrivateKey.kdf, 'PBKDF2-SHA256');
  assert.equal(bundle.protectedPrivateKey.iterations, PBKDF2_ITERATIONS);
  assert.equal(bundle.protectedPrivateKey.wrapAlgorithm, 'AES-256-GCM');
  assert.equal(bundle.protectedPrivateKey.wrapIvHex.length, 24);
  assert.match(bundle.keyFingerprint, /^([0-9A-F]{4}:){4}[0-9A-F]{4}$/);

  const unlocked = await unlockPrivateKeyWithPassphrase(
    bundle.protectedPrivateKey,
    passphrase
  );
  assert.equal(unlocked.type, 'private');

  await assert.rejects(
    () => unlockPrivateKeyWithPassphrase(bundle.protectedPrivateKey, 'wrong-passphrase'),
    /./
  );
});

test('encryptPayloadWithWebCrypto and decryptPayloadWithWebCrypto perform full real AES-256-GCM + RSA-OAEP-2048 round-trip', async () => {
  const aliceKeys = await generateUserKeyBundle('alice-passphrase-2026');
  const bobKeys = await generateUserKeyBundle('bob-passphrase-2026');
  const charlieKeys = await generateUserKeyBundle('charlie-passphrase-2026');

  const recipients: Recipient[] = [
    {
      id: 'usr-alice',
      name: 'Dr. Elena Vance',
      email: 'e.vance@jbitdoon.edu.in',
      role: 'Faculty',
      department: 'Applied Cryptography',
      keyFingerprint: aliceKeys.keyFingerprint,
      publicKey: aliceKeys.publicKey,
    },
    {
      id: 'usr-bob',
      name: 'Maya Lin',
      email: 'm.lin@jbitdoon.edu.in',
      role: 'Student',
      department: 'Computer Science',
      keyFingerprint: bobKeys.keyFingerprint,
      publicKey: bobKeys.publicKey,
    },
  ];

  const plaintextString = 'CS-410 Final Exam Key — Real Web Crypto AES-256-GCM + RSA-OAEP-2048!';
  const plaintextBytes = new TextEncoder().encode(plaintextString);
  const expectedSha256 = await computeSha256Hex(plaintextBytes);

  const envelope = await encryptPayloadWithWebCrypto({
    plaintextBytes,
    recipients,
  });

  assert.equal(envelope.algorithm, 'AES-256-GCM');
  assert.equal(envelope.keyWrapAlgorithm, 'RSA-OAEP-2048');
  assert.equal(envelope.isWebCryptoReal, true);
  assert.equal(envelope.ivHex.length, 24);
  assert.equal(envelope.ivBase64.length, 16);
  assert.equal(envelope.authTagHex.length, 32);
  assert.equal(envelope.sha256Hash, expectedSha256);
  assert.equal(envelope.wrappedKeys.length, 2);
  assert.equal(base64ToBytes(envelope.wrappedKeys[0].wrappedKeyBase64).length, 256);
  assert.notEqual(
    envelope.wrappedKeys[0].wrappedKeyBase64,
    envelope.wrappedKeys[1].wrappedKeyBase64
  );

  const decrypted = await decryptPayloadWithWebCrypto({
    envelope,
    privateKey: bobKeys.privateKey,
    recipientId: 'usr-bob',
    recipientFingerprint: bobKeys.keyFingerprint,
  });

  assert.equal(new TextDecoder().decode(decrypted.plaintextBytes), plaintextString);
  assert.equal(decrypted.verifiedSha256Hash, expectedSha256);

  await assert.rejects(
    () =>
      decryptPayloadWithWebCrypto({
        envelope,
        privateKey: charlieKeys.privateKey,
        recipientId: 'usr-charlie',
        recipientFingerprint: charlieKeys.keyFingerprint,
      }),
    /not listed among the authorized recipients/
  );

  const rawCipherBytes = base64ToBytes(envelope.rawCiphertextBase64!);
  rawCipherBytes[0] ^= 0xff;
  const tamperedEnvelope = {
    ...envelope,
    rawCiphertextBase64: bytesToBase64(rawCipherBytes),
  };

  await assert.rejects(
    () =>
      decryptPayloadWithWebCrypto({
        envelope: tamperedEnvelope,
        privateKey: bobKeys.privateKey,
        recipientId: 'usr-bob',
        recipientFingerprint: bobKeys.keyFingerprint,
      }),
    /AES-256-GCM authentication failed/
  );
});

test('buildEncryptedKeyBackupPayload exports PBKDF2-wrapped backup with JB Institute of Technology, Dehradun branding', async () => {
  const bundle = await generateUserKeyBundle('backup-passphrase-2026');
  const user: UserProfile = {
    id: 'usr-vance',
    name: 'Dr. Elena Vance',
    email: 'e.vance@jbitdoon.edu.in',
    role: 'Faculty',
    department: 'Applied Cryptography',
    keyFingerprint: bundle.keyFingerprint,
    vaultUnlockedAt: '07:20',
    publicKey: bundle.publicKey,
    privateKey: bundle.privateKey,
    protectedPrivateKey: bundle.protectedPrivateKey,
  };

  const payload = buildEncryptedKeyBackupPayload(user, '2026-11-25T15:20:00.000Z');
  assert.equal(payload.application, 'CipherHall');
  assert.equal(payload.institution, INSTITUTION_NAME);
  assert.equal(payload.owner.email, 'e.vance@jbitdoon.edu.in');
  assert.equal(payload.protection.asymmetricAlgorithm, 'RSA-OAEP-2048');
  assert.equal(payload.protection.symmetricAlgorithm, 'AES-256-GCM');
  assert.equal(payload.encryptedPrivateKeyBundle.kdf, 'PBKDF2-SHA256');
  assert.ok(payload.encryptedPrivateKeyBundle.wrappedPrivateKeyBase64.length > 100);

  // Backup bundle can still be unlocked with original passphrase
  const restored = await unlockPrivateKeyWithPassphrase(
    payload.encryptedPrivateKeyBundle,
    'backup-passphrase-2026'
  );
  assert.equal(restored.type, 'private');
});

test('canManageFileAccess and updateFileRecipientAccess enforce Faculty ownership and purge revoked keys', async () => {
  const facultyKeys = await generateUserKeyBundle('faculty-key-2026');
  const studentKeys = await generateUserKeyBundle('student-key-2026');

  const envelope = await encryptPayloadWithWebCrypto({
    plaintextBytes: new TextEncoder().encode('Confidential Rubric'),
    recipients: [
      {
        id: 'usr-vance',
        name: 'Dr. Elena Vance',
        email: 'e.vance@jbitdoon.edu.in',
        role: 'Faculty',
        department: 'Applied Cryptography',
        keyFingerprint: facultyKeys.keyFingerprint,
        publicKey: facultyKeys.publicKey,
      },
      {
        id: 'usr-lin',
        name: 'Maya Lin',
        email: 'm.lin@jbitdoon.edu.in',
        role: 'Student',
        department: 'Computer Science (M.S.)',
        keyFingerprint: studentKeys.keyFingerprint,
        publicKey: studentKeys.publicKey,
      },
    ],
  });

  const file: VaultFile = {
    id: 'f-rubric',
    filename: 'CS410_Rubric.pdf',
    fileType: 'PDF',
    sizeBytes: 12400,
    uploadedBy: 'Dr. Elena Vance',
    uploadedByRole: 'Faculty',
    department: 'Applied Cryptography',
    uploadedAt: '2026-11-25T10:00:00Z',
    dateLabel: 'Nov 25, 2026',
    sha256Status: 'Verified',
    decryptedPreviewContent: 'Confidential Rubric',
    recipients: ['Dr. Elena Vance', 'Maya Lin'],
    crypto: envelope,
  };

  const facultyUser: UserProfile = {
    id: 'usr-vance',
    name: 'Dr. Elena Vance',
    email: 'e.vance@jbitdoon.edu.in',
    role: 'Faculty',
    department: 'Applied Cryptography',
    keyFingerprint: facultyKeys.keyFingerprint,
    vaultUnlockedAt: '07:20',
  };
  const studentUser: UserProfile = {
    id: 'usr-lin',
    name: 'Maya Lin',
    email: 'm.lin@jbitdoon.edu.in',
    role: 'Student',
    department: 'Computer Science (M.S.)',
    keyFingerprint: studentKeys.keyFingerprint,
    vaultUnlockedAt: '07:20',
  };

  assert.equal(canManageFileAccess(facultyUser, file), true);
  assert.equal(canManageFileAccess(studentUser, file), false);

  const { updatedFile, revokedNames } = updateFileRecipientAccess(file, ['Dr. Elena Vance']);
  assert.deepEqual(revokedNames, ['Maya Lin']);
  assert.deepEqual(updatedFile.recipients, ['Dr. Elena Vance']);
  assert.equal(updatedFile.crypto.wrappedKeys.length, 1);
  assert.equal(updatedFile.crypto.wrappedKeys[0].recipientName, 'Dr. Elena Vance');

  // Revoked student can no longer decrypt
  await assert.rejects(
    () =>
      decryptPayloadWithWebCrypto({
        envelope: updatedFile.crypto,
        privateKey: studentKeys.privateKey,
        recipientId: 'usr-lin',
        recipientFingerprint: studentKeys.keyFingerprint,
      }),
    /not listed among the authorized recipients/
  );
});

test('verifyFileIntegrity, filterVaultFiles, and filterActivityEvents work accurately', async () => {
  const userKeys = await generateUserKeyBundle('filter-test-passphrase');
  const envelope = await encryptPayloadWithWebCrypto({
    plaintextBytes: new TextEncoder().encode('Sample syllabus'),
    recipients: [
      {
        id: 'rec-1',
        name: 'Dr. Elena Vance',
        email: 'e.vance@jbitdoon.edu.in',
        role: 'Faculty',
        department: 'Computer Science',
        keyFingerprint: userKeys.keyFingerprint,
        publicKey: userKeys.publicKey,
      },
    ],
  });

  const cleanFile: VaultFile = {
    id: 'f-1',
    filename: 'CS410_Midterm_Solutions.pdf',
    fileType: 'PDF',
    sizeBytes: 120000,
    uploadedBy: 'Dr. Elena Vance',
    uploadedByRole: 'Faculty',
    department: 'Computer Science',
    uploadedAt: '2026-11-25T09:00:00Z',
    dateLabel: 'Nov 25, 2026',
    sha256Status: 'Verified',
    decryptedPreviewContent: 'Solutions',
    recipients: ['Dr. Elena Vance'],
    crypto: envelope,
  };

  const tamperedFile: VaultFile = {
    ...cleanFile,
    id: 'f-2',
    filename: 'Thesis_Chapter3_Draft.docx',
    uploadedBy: 'Jordan Alvarez',
    uploadedByRole: 'Student',
    sha256Status: 'Mismatch',
    crypto: {
      ...envelope,
      expectedSha256Hash: '0'.repeat(64),
    },
  };

  assert.equal(verifyFileIntegrity(cleanFile).valid, true);
  assert.equal(verifyFileIntegrity(tamperedFile).valid, false);
  assert.equal(
    filterVaultFiles([cleanFile, tamperedFile], {
      query: 'midterm',
      roleFilter: 'All',
      statusFilter: 'All',
    }).length,
    1
  );

  const events: ActivityEvent[] = [
    {
      id: 'ev-1',
      category: 'security',
      title: 'Downloaded encrypted key backup',
      detail: 'Exported passphrase-protected backup file locally.',
      actorName: 'Dr. Elena Vance',
      actorRole: 'Faculty',
      timestampLabel: '07:20',
      status: 'success',
    },
    {
      id: 'ev-2',
      category: 'access',
      title: 'Revoked file access',
      detail: 'Removed Maya Lin from CS410_Midterm_Solutions.pdf.',
      actorName: 'Dr. Elena Vance',
      actorRole: 'Faculty',
      timestampLabel: '07:22',
      status: 'warning',
    },
  ];
  assert.equal(filterActivityEvents(events, { query: '', category: 'access' }).length, 1);
  assert.equal(filterActivityEvents(events, { query: 'backup', category: 'all' }).length, 1);
});

test('formatting helpers return expected strings', () => {
  assert.equal(formatByteSize(512), '512 B');
  assert.equal(formatByteSize(2048), '2.0 KB');
  assert.equal(formatByteSize(1572864), '1.50 MB');
  assert.equal(formatHexSpaced('a1b2c3'), 'A1 B2 C3');
  assert.equal(formatShortHash('0123456789abcdef0123456789abcdef', 6, 4), '012345…cdef');
});
