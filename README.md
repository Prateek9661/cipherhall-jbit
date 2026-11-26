# CipherHall — Zero-Knowledge Encrypted File & Chat Vault

**End-to-End Client-Side Cryptographic Platform for Academic Institutions**  
Built for **JB Institute of Technology, Dehradun** (`@jbitdoon.edu.in`)

> *"Your files and messages are encrypted on your device before leaving your browser. Not even campus IT admins can read them."*

---

## Overview

**CipherHall** is a full-stack, zero-knowledge file vault and encrypted campus messaging platform. Unlike conventional cloud drives that rely on server-side encryption, CipherHall executes all key generation, encryption, decryption, and cryptographic integrity checks locally inside the browser using the native **W3C Web Crypto API (`window.crypto.subtle`)**.

The Node.js/Express backend and MongoDB Atlas database act strictly as blind storage relays—they never receive plaintext files, plaintext chat messages, raw private keys, or the user's **Vault Passphrase**.

---

## Hybrid Cryptographic Architecture

CipherHall combines asymmetric and symmetric primitives to achieve fast multi-recipient encryption without sacrificing zero-knowledge guarantees:

| Security Layer | Algorithm & Parameters | Role in CipherHall |
| :--- | :--- | :--- |
| **User Identity** | **RSA-OAEP-2048** (`SHA-256`) | Asymmetric key pair generated per user in browser memory for multi-recipient key exchange |
| **Private Key Protection** | **PBKDF2-SHA256** (`100,000` iterations) + **AES-256-GCM** | Derives a local wrapping key from the user's Vault Passphrase so the raw private key never leaves the client |
| **File & Chat Encryption** | **AES-256-GCM** + **12-byte Random IV** | Authenticated symmetric encryption for file bytes and chat payloads |
| **Multi-Recipient Sharing** | **RSA-OAEP Key Wrapping** | Encrypts each file's unique AES-256 key separately for every authorized recipient |
| **Integrity Verification** | **SHA-256** Cryptographic Digest | Verifies exact file integrity prior to completing local browser decryption and blocks tampered files |

---

## Key Features & Academic Controls

* **Role-Based Campus Access:** Tailored authentication and collaboration workflows for **Student** and **Faculty** accounts (`@jbitdoon.edu.in`).
* **Zero-Knowledge Document Vault:** Client-side file encryption with multi-recipient sharing, one-click local **Decrypt & Download**, and clean status badges (**Verified**, **Pending**, **Integrity Alert**).
* **End-to-End Encrypted Chat:** Desktop split-view 1-on-1 faculty/student threads and Class Groups with inline Document Vault file sharing.
* **Faculty Access Governance:** `Manage / Revoke Access` modal allowing faculty members to revoke recipient key access on shared academic documents.
* **Encrypted Key Backup (`.json`):** `My Security & Key Backup` modal displays active RSA-2048 + AES-256 protection status and exports a passphrase-protected JSON key backup.
* **Human-Readable Activity Log:** Real-time audit trail recording encryption, sharing, verification, and download events without cluttering everyday screens with raw hex strings.
* **Toggleable Live Crypto Inspector:** Off by default for clean usability; opens on demand to inspect live 12-byte IVs, SHA-256 digests, and RSA-OAEP-2048 wrapped keys.

---

## System Architecture & Project Structure

* **Frontend (`Port 3000`):** React, TypeScript, Tailwind CSS, Vite, and native Web Crypto API (`src/utils/cryptoEngine.ts`).
* **Backend API (`Port 5000`):** Node.js & Express REST API with strict CORS origin validation, streaming raw `.enc` ciphertext blobs to `server/uploads/*.enc`.
* **Cloud Database:** MongoDB Atlas (`cipherhall`) storing campus roles, public JWKs, passphrase-wrapped `protectedPrivateKey` blobs, 12-byte IVs, SHA-256 hashes, and per-recipient `wrappedKeys`.

```text
cipherhall-jbit/
├── src/
│   ├── components/
│   │   ├── AuthScreen.tsx            # Sign-in, registration & local key unwrapping
│   │   ├── DocumentVault.tsx         # Encrypted file dashboard & SHA-256 verification
│   │   ├── EncryptedChat.tsx         # Split-view E2EE campus chat & inline vault sharing
│   │   ├── UploadEncryptModal.tsx    # Client-side AES-256-GCM + RSA key wrapping modal
│   │   ├── ManageAccessModal.tsx     # Faculty recipient access revocation
│   │   ├── SecurityBackupModal.tsx   # Encrypted .json private key backup export
│   │   ├── ActivityLog.tsx           # Human-readable cryptographic audit log
│   │   └── CryptoInspectorDrawer.tsx # Live technical inspection drawer (IV, hash, keys)
│   ├── utils/
│   │   ├── cryptoEngine.ts           # Native window.crypto.subtle cryptographic engine
│   │   └── apiClient.ts              # Express REST API client
│   └── types/
│       └── vault.ts                  # TypeScript interfaces for keys, files & messages
├── server/
│   ├── index.js                      # Zero-knowledge Express API & MongoDB persistence
│   ├── uploads/                      # Local .enc ciphertext blob storage (git-ignored)
│   └── .env                          # Environment configuration (git-ignored)
├── .env.example                      # Sample environment variables
└── vite.config.ts                    # Vite frontend configuration (port 3000)
