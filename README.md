# 🗲 E2EE-ZTAP-Protocol: Zero-Knowledge Terminal Architecture & Protocol

[![Security: IRONCLAD v3.1](https://img.shields.io/badge/Security-IRONCLAD_v3.1-brightgreen.svg)](https://github.com/Noir0x63/E2EE-ZTAP-Protocol)
[![Encryption: AES--256--GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-blue.svg)]()
[![PFS: ECDH--P256](https://img.shields.io/badge/PFS-ECDH--P256-blue.svg)]()
[![Network: Tor--Only](https://img.shields.io/badge/Network-Tor--Only-blueviolet.svg)]()
[![Keys: Encrypted--At--Rest](https://img.shields.io/badge/Keys-Encrypted--At--Rest-critical.svg)]()
[![Audit: Passed](https://img.shields.io/badge/Audit-Passed_(5%2F5_Fixed)-green.svg)]()

**ZTAP (Zero-Knowledge Terminal Architecture & Protocol)** is a high-security, volatile communication framework designed to operate over untrusted infrastructure (Tor Hidden Services, Blind Relays, or Compromised Nodes). 

The system ensures absolute confidentiality and mathematical immunity against forensic analysis, preventing data persistence at every layer of the stack.

---

## 🏗️ Protocol Topology & Data Flow

```mermaid
graph LR
    subgraph "CLIENT A (Browser)"
    A[WebCrypto Engine] --> B[PBKDF2 600k Iterations]
    B --> C[AES-256-GCM Encrypt]
    C --> D[4096B Strict Padding]
    end

    D -- "ECDH Ephemeral Channel (Tor/Onion)" --> E

    subgraph "BLIND RELAY (Node.js Server)"
    E[Memory-Only Buffer] --> F[Zero-Persistence Vault]
    F -- "Broadcast" --> G
    end

    G -- "Constant Bitrate Stream" --> H

    subgraph "CLIENT B (Admin/User)"
    H[Strict Frame Parsing] --> I[Web Worker Isolation]
    I --> J[AES-256-GCM Decrypt]
    J --> K[Volatile Memory Purge]
    end
```

---

## 🔒 Security Core (Hardening Features)

### 1. Autonomous Cryptographic Engine
The protocol implements a multi-layered encryption stack using the native **WebCrypto API**, eliminating third-party library dependencies and mitigating supply chain attacks.
*   **Key Exchange:** RSA-OAEP (4096-bit) with SHA-256 for identity authentication.
*   **Perfect Forward Secrecy:** ECDH (P-256) ephemeral keypair per session — compromising the master RSA key does **NOT** reveal historical traffic.
*   **Stream Security:** AES-256-GCM with unique Initialization Vectors (IV) per frame.
*   **Signature Scheme:** **RSA-PSS** (Probabilistic Signature Scheme) with 32-byte salt for identity verification (Admin Command & Control).
*   **Identity Derivation:** PBKDF2-HMAC-SHA256 with **600,000 iterations** and **high-entropy session salt** (32 bytes CSPRNG) to ensure brute-force resistance.

### 2. Encrypted-At-Rest Key Management
All cryptographic secrets are protected at rest — plaintext key material **never** persists on disk.
*   **Master Private Key:** Encrypted with AES-256-GCM, key derived via **PBKDF2** (600,000 iterations, SHA-256) from an admin passphrase. Stored as `master_private.enc`.
*   **Browser-Side Decryption:** The admin panel decrypts `master_private.enc` **entirely in the browser** using WebCrypto PBKDF2. The plaintext key exists only in volatile RAM — it never reaches the server.
*   **Admin HMAC Secret:** Derived deterministically from the admin passphrase via scrypt — no `admin_token.txt` file ever exists.
*   **Server Nonce:** A random 32-byte nonce generated per keygen cycle, adding entropy to admin route rotation and preventing prediction attacks.
*   **Legacy Purge:** On startup, the launcher securely overwrites and deletes any legacy plaintext files (`master_private.pem`, `admin_token.txt`) with random data before unlinking.

### 3. Traffic Analysis Mitigation (DPI Defense)
*   **Strict Padding:** Every payload is packed into a fixed-size **4096-byte** binary ArrayBuffer. This nullifies length-based side-channel analysis.
*   **Stochastic Chaffing:** Asynchronous injection of synthetic noise frames via randomized timers to obfuscate temporal patterns.
*   **Adaptive Proof of Work (PoW):** SHA-256 based PoW challenges with **dynamic difficulty** (16–24 bits) that scales with server connection load to prevent Asymmetric DoS attacks.

### 4. Volatile Anti-Forensics Layer
ZTAP is designed for **Zero-Persistence**.
*   **Memory Hygiene:** TypedArrays (`Uint8Array`) are used for plaintext processing and are sanitized using `.fill(0)` and CSPRNG noise injection immediately after use.
*   **Automatic 24h Purge:** The server implements a mandatory cleanup cycle that wipes the message vault (RAM and Disk) every 24 hours, ensuring ephemerality.
*   **Zero-Store Keys:** Session tokens and private keys never touch the server's disk; they reside only in the volatility of the browser's memory and the server's RAM during transport.
- **Volatile Identity Rotation**: Generación de una nueva dirección `.onion` en cada inicio del sistema (Onion Evasion) para evitar el rastreo a largo plazo.
- **EXIF/IPTC Stripping**: JPEG files sent via the admin panel have APP1 (EXIF) and APP13 (IPTC) metadata stripped before encryption — preventing de-anonymization via GPS, device info, or software fingerprints.

### 5. Session Governance & Access Control
*   **Session Expiry:** All sessions expire after 1 hour, requiring re-authentication.
*   **Concurrent Limits:** Maximum 2 connections per session ID, 500 total server-wide.
*   **Session Governance:** 1-hour session expiry and strict concurrent connection limits.
*   **Admin Route Rotation:** Hourly HMAC-derived admin paths with serverNonce entropy — routes cannot be pre-calculated even with leaked secrets.
*   **Input Sanitization:** All user-provided fields are validated and stripped of control characters before processing.
*   **Vault Write Mutex:** Promise-chained serialization prevents race conditions and JSON corruption under concurrent write pressure.

---

## 🛡️ Integrity & Build Pipeline
The client-side logic is hardened through integrity verification rather than security-through-obscurity:
*   **Kerckhoffs' Principle:** Obfuscation has been **removed** — security resides in the keys, not in hiding the algorithm. Code is minified, not obfuscated.
*   **Worker Integrity:** A `GOLD_HASH` (SHA-512) validation ensures the Web Worker hasn't been tampered with in transit (pre-spawning verification).
*   **Worker Attestation:** **Server-side** HMAC-based challenge-response attestation ensures runtime integrity of the cryptographic worker. The server — not the client — dictates and verifies attestation.
*   **Zero Dependencies for Crypto:** All cryptographic operations use the native WebCrypto API — no third-party libraries in the critical path.
*   **Framework Hardening:** `X-Powered-By` disabled, ETags suppressed, global error handler prevents path disclosure.

---

## 🔐 Admin Authentication Flow

The admin panel implements a **zero-trust, browser-side decryption** pipeline:

```mermaid
sequenceDiagram
    participant A as Admin Browser
    participant S as ZTAP Server
    
    Note over A: Navigate to hourly HMAC route
    A->>A: Upload master_private.enc
    A->>A: Enter passphrase
    A->>A: PBKDF2 (600k) → AES key
    A->>A: AES-256-GCM decrypt → RSA PEM (in RAM only)
    A->>A: Import RSA-OAEP + RSA-PSS keys
    A->>S: WebSocket HANDSHAKE
    S->>A: AUTH_CHALLENGE (random nonce)
    A->>A: RSA-PSS sign(nonce)
    A->>S: ADMIN_AUTH (signature)
    S->>S: RSA-PSS verify(signature, master_public.pem)
    S->>A: ✓ Authenticated → Dashboard
```

**Key principle:** The server **never** sees the private key or the passphrase. Authentication is proven via RSA-PSS challenge-response — the server only holds the public key.

---

## 🔍 Audit Results (v3.1)

A formal offensive cryptographic audit was performed under a **Zero Trust** mentality. All 5 findings have been remediated:

| # | Finding | Severity | CVSS | Status |
|---|---------|----------|------|--------|
| 1 | **Plaintext Token Leakage** — Token sent in cleartext in INIT/ASYNC_MSG frames | CRÍTICO | 9.8 | ✅ FIXED |
| 2 | **Weak Key Derivation Salt** — Username used as PBKDF2 salt (low entropy) | ALTO | 7.4 | ✅ FIXED |
| 3 | **Client-Side Attestation Flaw** — Client self-validated attestation challenges | CRÍTICO | 8.5 | ✅ FIXED |
| 4 | **EXIF Metadata Leakage** — JPEG files sent without stripping EXIF/IPTC | ALTO | 6.8 | ✅ FIXED |
| 5 | **Vault Race Condition** — Concurrent `fs.writeFile` calls corrupt `vault.json` | MEDIO | — | ✅ FIXED |

> Full report: [`Reportes de auditoria/reporte.tex`](Reportes%20de%20auditoria/reporte.tex)

---

## 🚀 Deployment (Zero-Config Operator Setup)
ZTAP v3.1 introduces a **Native Desktop Client** (Electron) designed to completely abstract the complexity of Tor, Node.js, and cryptographic key generation. This enables non-technical operators (journalists, activists) to deploy an IRONCLAD communication relay with zero command-line interaction.

### 🖥️ Native Desktop Features
1. **Automated Keygen:** Visual passphrase prompt for RSA-4096 key generation and encrypted-at-rest storage.
2. **Embedded Tor:** Bundles the Tor binary and dynamically generates `torrc` configurations, bypassing port collisions and read-only permission errors.
3. **Volatile Identity:** Automatically wipes previous hidden service keys and bootstraps a new `.onion` address upon every launch.
4. **Local Dashboard Bridge:** Securely routes the operator to their local, encrypted admin dashboard (`localhost:3000/route`) while clients connect via the `.onion` network.
5. **Cross-Platform Compilation:** Supports Windows `.exe` via NSIS and Linux `.AppImage` (the standard for **Tails OS**).

### Quick Start (Compiled Binary)
1. Download the compiled release for your OS (`.exe` for Windows, `.AppImage` for Linux/Tails).
2. Double-click to launch (no installation or terminal required).
3. Follow the UI prompt to create your Master Passphrase (min 12 characters).
4. Wait for the Tor subsystem to bootstrap (0% to 100%).
5. Click **Copy .onion Link** and send it to your contact over a secure channel.
6. Click **Open Admin Panel** to manage incoming messages locally in your browser.

> ⚠️ **Remember your passphrase.** There is no "forgot password" mechanism. Without it, the master identity is cryptographically irretrievable.

---

## 📊 Security Posture

| Layer | Mechanism | Standard |
|-------|-----------|----------|
| **Key Exchange** | RSA-4096 + ECDH P-256 | NIST SP 800-56A |
| **Stream Cipher** | AES-256-GCM | NIST SP 800-38D |
| **Key Derivation** | PBKDF2 (600k) + scrypt | OWASP 2025 |
| **KDF Salt** | sessionId (32 bytes CSPRNG) | High-entropy |
| **Signatures** | RSA-PSS (32-byte salt) | PKCS#1 v2.1 |
| **Key Storage** | AES-256-GCM + PBKDF2 (600k) | Encrypted-at-rest |
| **Admin Auth** | Browser-side decrypt + RSA-PSS C/R | Zero-trust |
| **Attestation** | Server-side HMAC + timingSafeEqual | Anti-tamper |
| **Forward Secrecy** | ECDH ephemeral per session | PFS compliant |
| **Anti-DoS** | Adaptive PoW (16–24 bit) | Dynamic scaling |
| **Anti-Forensics** | EXIF/IPTC strip + 24h vault purge | Zero-persistence |
| **Transport** | Tor Hidden Service | Onion routing |

---

## ⚖️ License

**GNU General Public License v3.0 (GPLv3)** — See [LICENSE](LICENSE).

This project is Free Software: you can redistribute it and/or modify it under the terms of the GNU GPLv3 as published by the Free Software Foundation.

---

## ⚖️ Auditing Disclaimer
> *"A 100% secure system does not exist; there are only systems that are prohibitively expensive to hack."*

ZTAP is built on the principle of **Attack Cost Maximization**. By combining encrypted-at-rest key management, Perfect Forward Secrecy, aggressive memory hygiene, traffic normalization, and adaptive proof-of-work, the infrastructure forces adversaries to expend computational resources they are unlikely to invest for standard interception.

---
**Developed and Hardened by Eduardo "Noir0x63" Camarillo** 🔒🎩
