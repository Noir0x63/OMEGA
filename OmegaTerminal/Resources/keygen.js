const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

function askPassphrase(prompt) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question(prompt, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

function encryptPrivateKey(pemString, passphrase) {
    const salt = crypto.randomBytes(32);
    const iterations = 600000;
    const key = crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(pemString, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const envelope = {
        version: 3,
        kdf: 'pbkdf2',
        kdfParams: { iterations: iterations, hash: 'SHA-256' },
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: encrypted.toString('hex')
    };
    return JSON.stringify(envelope, null, 2);
}

async function main() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║     OMEGA KEYGEN — RSA-4096 + ENCRYPTED-AT-REST            ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('');

    const passphrase = await askPassphrase('[KEYGEN] Enter master passphrase to encrypt private key: ');
    if (!passphrase || passphrase.length < 12) {
        console.error('[KEYGEN] ERROR: Passphrase must be at least 12 characters.');
        process.exit(1);
    }
    const confirm = await askPassphrase('[KEYGEN] Confirm passphrase: ');
    if (passphrase !== confirm) {
        console.error('[KEYGEN] ERROR: Passphrases do not match.');
        process.exit(1);
    }

    console.log('[KEYGEN] Generating RSA-4096 keypair...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    fs.writeFileSync('master_public.pem', publicKey);

    console.log('[KEYGEN] Encrypting private key with PBKDF2 (600k) + AES-256-GCM...');
    const encryptedBlob = encryptPrivateKey(privateKey, passphrase);
    fs.writeFileSync('master_private.enc', encryptedBlob);

    const adminSalt = crypto.randomBytes(32);
    const adminSecret = crypto.scryptSync(passphrase, Buffer.concat([adminSalt, Buffer.from('omega:admin:hmac')]), 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const serverNonce = crypto.randomBytes(32);
    const secretsEnvelope = {
        version: 2,
        adminSalt: adminSalt.toString('hex'),
        adminSecret: adminSecret.toString('hex'),
        serverNonce: serverNonce.toString('hex')
    };
    fs.writeFileSync('server_secrets.enc', JSON.stringify(secretsEnvelope, null, 2));

    console.log('');
    console.log('[KEYGEN] ✓ master_public.pem         — Public key (safe to distribute)');
    console.log('[KEYGEN] ✓ master_private.enc         — Encrypted private key (AES-256-GCM + PBKDF2)');
    console.log('[KEYGEN] ✓ server_secrets.enc         — Derived server secrets');
    console.log('[KEYGEN] ✗ master_private.pem         — NOT generated (never stored in plaintext)');
    console.log('[KEYGEN] ✗ admin_token.txt            — REMOVED (derived from passphrase)');
    console.log('');
    console.log('[KEYGEN] WARNING: Memorize your passphrase. There is no recovery without it.');
}

main().catch(e => { console.error(e); process.exit(1); });
