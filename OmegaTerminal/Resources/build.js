const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let adminToken;
let serverNonce;
try {
    const secrets = JSON.parse(fs.readFileSync('server_secrets.enc', 'utf8'));
    adminToken = secrets.adminSecret;
    serverNonce = secrets.serverNonce;
} catch (e) {
    console.error('[BUILD] FATAL: server_secrets.enc not found. Run: node keygen.js');
    process.exit(1);
}

const dayNonce = String(Math.floor(Date.now() / 86400000));
const hourlyNonce = String(Math.floor(Date.now() / 3600000));
const todayAdminPath = crypto.createHmac('sha256', adminToken)
    .update(dayNonce + ':' + hourlyNonce + ':' + serverNonce)
    .digest('hex');
const minutesLeft = Math.ceil((3600000 - (Date.now() % 3600000)) / 60000);

const masterPublicPem = fs.readFileSync('master_public.pem', 'utf8').trim();
const pemContents = masterPublicPem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .trim();

function minifyJS(code) {
    let result = '';
    let i = 0;
    while (i < code.length) {
        if (code[i] === "'" || code[i] === '"' || code[i] === '`') {
            const quote = code[i];
            result += code[i++];
            while (i < code.length && code[i] !== quote) {
                if (code[i] === '\\') { result += code[i++]; }
                if (i < code.length) result += code[i++];
            }
            if (i < code.length) result += code[i++];
        }
        else if (code[i] === '/' && code[i + 1] === '/') {
            while (i < code.length && code[i] !== '\n') i++;
        }
        else if (code[i] === '/' && code[i + 1] === '*') {
            i += 2;
            while (i < code.length - 1 && !(code[i] === '*' && code[i + 1] === '/')) i++;
            i += 2;
        }
        else {
            result += code[i++];
        }
    }
    return result
        .replace(/^\s+/gm, '')
        .replace(/\n{2,}/g, '\n')
        .trim();
}

const workerRaw = fs.readFileSync('src/omega-worker.js', 'utf8');
const workerMinified = minifyJS(workerRaw);
const goldHash = crypto.createHash('sha512').update(workerMinified).digest('hex');

const clientJsRaw = fs.readFileSync('src/client.js', 'utf8');
const clientJsInjected = clientJsRaw
    .replace('INJECT_MASTER_PUBLIC_KEY', pemContents)
    .replace('INJECT_EXPECTED_HASH', goldHash);
const clientMinified = minifyJS(clientJsInjected);

const adminClientRaw = fs.readFileSync('src/admin-client.js', 'utf8');
const adminClientMinified = minifyJS(adminClientRaw);

fs.mkdirSync('public', { recursive: true });
fs.writeFileSync('public/omega-worker.js', workerMinified);
fs.writeFileSync('public/client.js', clientMinified);
fs.writeFileSync('public/admin-client.js', adminClientMinified);
fs.copyFileSync('src/index.html', 'public/index.html');
fs.copyFileSync('src/admin.html', 'public/admin.html');
fs.writeFileSync('public/GOLD_HASH.txt', goldHash);

console.log('');
console.log('══════════════════════════════════════════════════════════════════');
console.log('  BUILD COMPLETE — PROTOCOLO OMEGA IRONCLAD v3.1');
console.log('══════════════════════════════════════════════════════════════════');
console.log('');
console.log('  [ADMIN] Active route (hourly rotation + serverNonce):');
console.log(`  /${todayAdminPath}`);
console.log(`  (Expires in ${minutesLeft} min)`);
console.log('');
console.log('  [HARDENING] Active security mitigations:');
console.log('  1. Private key encrypted at rest (scrypt + AES-256-GCM).');
console.log('  2. admin_token.txt removed (derived from passphrase).');
console.log('  3. Admin routes use serverNonce (anti-prediction).');
console.log('  4. Obfuscation removed (Kerckhoffs principle).');
console.log('  5. Ephemeral ECDH for PFS per session.');
console.log('  6. Granular rate limiting + adaptive PoW.');
console.log('  7. Input sanitization + error handling.');
console.log('  8. Worker integrity: GOLD_HASH pre-spawning.');
console.log('');
console.log('  GOLD_HASH: ' + goldHash.slice(0, 32) + '...');
console.log('══════════════════════════════════════════════════════════════════');
console.log('');
