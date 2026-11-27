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
  exportPublicKeyToSpkiBase64,
  filterActivityEvents,
  filterVaultFiles,
  formatByteSize,
  formatHexSpaced,
  formatShortHash,
  generateUserKeyBundle,
  importPublicKeyFromSpkiBase64,
  INSTITUTION_NAME,
  PBKDF2_ITERATIONS,
  rewrapAesKeyForRecipients,
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
    email: 'student1@jbitdoon.edu.in',
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

test('generateUserKeyBundle creates real RSA-OAEP-2048 key pair with SPKI export protected by PBKDF2-SHA256', async () => {
  const passphrase = 'cedar-lattice-vault-2026';
  const bundle = await generateUserKeyBundle(passphrase);

  assert.equal(bundle.publicKey.algorithm.name, 'RSA-OAEP');
  assert.equal(bundle.privateKey.algorithm.name, 'RSA-OAEP');
  assert.ok(bundle.publicKeySpkiBase64.length > 200);
  assert.equal(bundle.protectedPrivateKey.kdf, 'PBKDF2-SHA256');
  assert.equal(bundle.protectedPrivateKey.iterations, PBKDF2_ITERATIONS);
  assert.equal(bundle.protectedPrivateKey.wrapAlgorithm, 'AES-256-GCM');
  assert.equal(bundle.protectedPrivateKey.wrapIvHex.length, 24);
  assert.match(bundle.keyFingerprint, /^([0-9A-F]{4}:){4}[0-9A-F]{4}$/);

  const reExported = await exportPublicKeyToSpkiBase64(bundle.publicKey);
  assert.equal(reExported, bundle.publicKeySpkiBase64);

  const importedPublic = await importPublicKeyFromSpkiBase64(bundle.publicKeySpkiBase64);
  assert.equal(importedPublic.algorithm.name, 'RSA-OAEP');

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

test('encryptPayloadWithWebCrypto imports SPKI public keys from registered users and decrypts end-to-end', async () => {
  const facultyKeys = await generateUserKeyBundle('faculty-passphrase-2026');
  const studentKeys = await generateUserKeyBundle('student-passphrase-2026');
  const outsiderKeys = await generateUserKeyBundle('outsider-passphrase-2026');

  // Pass SPKI base64 strings only (matching GET /api/users response from MongoDB)
  const recipients: Recipient[] = [
    {
      id: 'usr-fac-1',
      name: 'Test Faculty',
      email: 'faculty1@jbitdoon.edu.in',
      role: 'Faculty',
      department: 'Computer Science & Engineering',
      keyFingerprint: facultyKeys.keyFingerprint,
      publicKeySpkiBase64: facultyKeys.publicKeySpkiBase64,
    },
    {
      id: 'usr-stu-1',
      name: 'Test Student',
      email: 'student1@jbitdoon.edu.in',
      role: 'Student',
      department: 'Computer Science & Engineering',
      keyFingerprint: studentKeys.keyFingerprint,
      publicKeySpkiBase64: studentKeys.publicKeySpkiBase64,
    },
  ];

  const plaintextString = 'JBIT Operating Systems Lab Manual — Real Web Crypto AES-256-GCM + RSA-OAEP-2048!';
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

  // Student decrypts with their own RSA-OAEP-2048 private key
  const decrypted = await decryptPayloadWithWebCrypto({
    envelope,
    privateKey: studentKeys.privateKey,
    recipientId: 'usr-stu-1',
    recipientFingerprint: studentKeys.keyFingerprint,
  });

  assert.equal(new TextDecoder().decode(decrypted.plaintextBytes), plaintextString);
  assert.equal(decrypted.verifiedSha256Hash, expectedSha256);

  // Outsider cannot decrypt
  await assert.rejects(
    () =>
      decryptPayloadWithWebCrypto({
        envelope,
        privateKey: outsiderKeys.privateKey,
        recipientId: 'usr-outsider',
        recipientFingerprint: outsiderKeys.keyFingerprint,
      }),
    /not listed among the authorized recipients/
  );

  // Faculty grants access to outsider via rewrapAesKeyForRecipients and revokes student1
  const rewrapped = await rewrapAesKeyForRecipients({
    envelope,
    ownerPrivateKey: facultyKeys.privateKey,
    ownerRecipientId: 'usr-fac-1',
    ownerFingerprint: facultyKeys.keyFingerprint,
    targetRecipients: [
      recipients[0],
      {
        id: 'usr-outsider',
        name: 'Second Student',
        email: 'student2@jbitdoon.edu.in',
        role: 'Student',
        department: 'Computer Science & Engineering',
        keyFingerprint: outsiderKeys.keyFingerprint,
        publicKeySpkiBase64: outsiderKeys.publicKeySpkiBase64,
      },
    ],
  });
  const updatedEnvelope = { ...envelope, wrappedKeys: rewrapped };

  const outsiderDecrypted = await decryptPayloadWithWebCrypto({
    envelope: updatedEnvelope,
    privateKey: outsiderKeys.privateKey,
    recipientId: 'usr-outsider',
    recipientFingerprint: outsiderKeys.keyFingerprint,
  });
  assert.equal(new TextDecoder().decode(outsiderDecrypted.plaintextBytes), plaintextString);

  // Tampered ciphertext is rejected by AES-GCM tag verification
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
        privateKey: studentKeys.privateKey,
        recipientId: 'usr-stu-1',
        recipientFingerprint: studentKeys.keyFingerprint,
      }),
    /AES-256-GCM authentication failed/
  );
});

test('buildEncryptedKeyBackupPayload exports PBKDF2-wrapped backup with JB Institute of Technology, Dehradun branding', async () => {
  const bundle = await generateUserKeyBundle('backup-passphrase-2026');
  const user: UserProfile = {
    id: 'usr-fac-1',
    name: 'Test Faculty',
    email: 'faculty1@jbitdoon.edu.in',
    role: 'Faculty',
    department: 'Department of Computer Science',
    keyFingerprint: bundle.keyFingerprint,
    publicKeySpkiBase64: bundle.publicKeySpkiBase64,
    vaultUnlockedAt: '07:20',
    publicKey: bundle.publicKey,
    privateKey: bundle.privateKey,
    protectedPrivateKey: bundle.protectedPrivateKey,
  };

  const payload = buildEncryptedKeyBackupPayload(user, '2026-11-25T15:20:00.000Z');
  assert.equal(payload.application, 'CipherHall');
  assert.equal(payload.institution, INSTITUTION_NAME);
  assert.equal(payload.owner.email, 'faculty1@jbitdoon.edu.in');
  assert.equal(payload.protection.asymmetricAlgorithm, 'RSA-OAEP-2048');
  assert.equal(payload.protection.symmetricAlgorithm, 'AES-256-GCM');
  assert.equal(payload.encryptedPrivateKeyBundle.kdf, 'PBKDF2-SHA256');
  assert.ok(payload.encryptedPrivateKeyBundle.wrappedPrivateKeyBase64.length > 100);

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
        id: 'usr-fac-1',
        name: 'Test Faculty',
        email: 'faculty1@jbitdoon.edu.in',
        role: 'Faculty',
        department: 'Department of Computer Science',
        keyFingerprint: facultyKeys.keyFingerprint,
        publicKey: facultyKeys.publicKey,
      },
      {
        id: 'usr-stu-1',
        name: 'Test Student',
        email: 'student1@jbitdoon.edu.in',
        role: 'Student',
        department: 'Computer Science & Engineering',
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
    uploaderId: 'usr-fac-1',
    uploadedBy: 'Test Faculty',
    uploadedByRole: 'Faculty',
    department: 'Department of Computer Science',
    uploadedAt: '2026-11-25T10:00:00Z',
    dateLabel: 'Nov 25, 2026',
    sha256Status: 'Verified',
    recipientIds: ['usr-fac-1', 'usr-stu-1'],
    recipients: ['Test Faculty', 'Test Student'],
    crypto: envelope,
  };

  const facultyUser: UserProfile = {
    id: 'usr-fac-1',
    name: 'Test Faculty',
    email: 'faculty1@jbitdoon.edu.in',
    role: 'Faculty',
    department: 'Department of Computer Science',
    keyFingerprint: facultyKeys.keyFingerprint,
    vaultUnlockedAt: '07:20',
  };
  const studentUser: UserProfile = {
    id: 'usr-stu-1',
    name: 'Test Student',
    email: 'student1@jbitdoon.edu.in',
    role: 'Student',
    department: 'Computer Science & Engineering',
    keyFingerprint: studentKeys.keyFingerprint,
    vaultUnlockedAt: '07:20',
  };

  assert.equal(canManageFileAccess(facultyUser, file), true);
  assert.equal(canManageFileAccess(studentUser, file), false);

  const { updatedFile, revokedNames } = updateFileRecipientAccess(file, ['Test Faculty']);
  assert.deepEqual(revokedNames, ['Test Student']);
  assert.deepEqual(updatedFile.recipients, ['Test Faculty']);
  assert.equal(updatedFile.crypto.wrappedKeys.length, 1);
  assert.equal(updatedFile.crypto.wrappedKeys[0].recipientName, 'Test Faculty');

  await assert.rejects(
    () =>
      decryptPayloadWithWebCrypto({
        envelope: updatedFile.crypto,
        privateKey: studentKeys.privateKey,
        recipientId: 'usr-stu-1',
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
        name: 'Test Faculty',
        email: 'faculty1@jbitdoon.edu.in',
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
    uploaderId: 'rec-1',
    uploadedBy: 'Test Faculty',
    uploadedByRole: 'Faculty',
    department: 'Computer Science',
    uploadedAt: '2026-11-25T09:00:00Z',
    dateLabel: 'Nov 25, 2026',
    sha256Status: 'Verified',
    recipientIds: ['rec-1'],
    recipients: ['Test Faculty'],
    crypto: envelope,
  };

  const tamperedFile: VaultFile = {
    ...cleanFile,
    id: 'f-2',
    filename: 'Thesis_Chapter3_Draft.docx',
    uploaderId: 'rec-2',
    uploadedBy: 'Second Student',
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
      actorName: 'Test Faculty',
      actorRole: 'Faculty',
      timestampLabel: '07:20',
      status: 'success',
    },
    {
      id: 'ev-2',
      category: 'access',
      title: 'Revoked file access',
      detail: 'Removed Test Student from CS410_Midterm_Solutions.pdf.',
      actorName: 'Test Faculty',
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
