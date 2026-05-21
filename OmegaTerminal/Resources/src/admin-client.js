let ws = null;
let masterPrivateKey = null;
let masterSignKey = null;
let users = {};
let hashToId = {};
let selectedSessionId = null;
let messages = [];
let sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');

// PFS-FIX: Almacén de secretos ECDH efímeros por sesión.
// El Admin ahora computa los secretos compartidos localmente en su navegador
// mediante un intercambio ECDH E2EE con cada cliente. El servidor solo retransmite
// las claves públicas sin acceso al material criptográfico.
const sessionECDHSecrets = {};

function bufferToBase64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBuffer(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function importKeys(pem) {
    const clean = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----|\s/g, '');
    const binary = base64ToBuffer(clean);
    masterPrivateKey = await crypto.subtle.importKey('pkcs8', binary.buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    masterSignKey = await crypto.subtle.importKey('pkcs8', binary.buffer, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
    crypto.getRandomValues(binary); // PARCHE AUDITORIA: Destruir llave privada en binario tras importación
}

function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
}

async function decryptEncryptedKey(envelopeJson, passphrase) {
    const envelope = JSON.parse(envelopeJson);
    if (envelope.kdf !== 'pbkdf2') throw new Error('Unsupported KDF: ' + envelope.kdf);
    const enc = new TextEncoder();
    const salt = hexToBuffer(envelope.salt);
    const iv = hexToBuffer(envelope.iv);
    const authTag = hexToBuffer(envelope.authTag);
    const ciphertext = hexToBuffer(envelope.ciphertext);
    const encryptedWithTag = new Uint8Array(ciphertext.length + authTag.length);
    encryptedWithTag.set(ciphertext, 0);
    encryptedWithTag.set(authTag, ciphertext.length);
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: envelope.kdfParams.iterations, hash: envelope.kdfParams.hash },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, aesKey, encryptedWithTag);
    return new TextDecoder().decode(decrypted);
}

// PFS-FIX: Generación y cómputo ECDH local para E2EE con cada cliente.
// Estas funciones son el espejo exacto de generateClientECDH() y
// computeECDHSharedSecret() en client.js, garantizando compatibilidad
// criptográfica bilateral sobre la curva P-256 (NIST/FIPS).
async function generateAdminECDH() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const publicKeyHex = Array.from(new Uint8Array(publicKeyRaw)).map(b => b.toString(16).padStart(2, '0')).join('');
    return { keyPair, publicKeyHex };
}

async function computeAdminECDHSecret(adminKeyPair, clientPublicKeyHex) {
    const clientKeyBytes = new Uint8Array(clientPublicKeyHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const clientKey = await crypto.subtle.importKey(
        'raw', clientKeyBytes, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: clientKey }, adminKeyPair.privateKey, 256
    );
    return Array.from(new Uint8Array(sharedBits));
}

let pendingEncFile = null;

document.getElementById('file-input').onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const text = await f.text();
    if (f.name.endsWith('.enc') || text.trim().startsWith('{')) {
        pendingEncFile = text;
        document.getElementById('upload-status').textContent = 'ENCRYPTED KEY LOADED — ENTER PASSPHRASE';
        document.getElementById('passphrase-input').style.display = 'block';
        document.getElementById('passphrase-input').focus();
        document.getElementById('auth-btn').disabled = false;
    } else {
        try {
            await importKeys(text);
            document.getElementById('upload-status').textContent = 'KEY READY (PLAINTEXT)';
            document.getElementById('auth-btn').disabled = false;
            pendingEncFile = null;
        } catch (err) { alert('Invalid Key Format'); }
    }
};

document.getElementById('pem-upload').onclick = () => document.getElementById('file-input').click();

// PARCHE VULN-1: KDF de dos etapas PBKDF2 → HKDF (idéntico al Worker del cliente).
// Combina la resistencia a fuerza bruta de PBKDF2 con el secreto ECDH efímero via HKDF.
async function deriveKey(token, salt, ecdhSecret) {
    const enc = new TextEncoder();
    const saltBuf = enc.encode(salt);

    // Etapa 1: PBKDF2 — deriva bits intermedios
    const pbkdfBase = await crypto.subtle.importKey('raw', enc.encode(token), 'PBKDF2', false, ['deriveBits']);
    const pbkdfBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBuf, iterations: 600000, hash: 'SHA-256' },
        pbkdfBase,
        256
    );

    // Etapa 2: HKDF — ata el secreto ECDH efímero para PFS real
    const hkdfSalt = (ecdhSecret && ecdhSecret.length > 0) ? new Uint8Array(ecdhSecret) : new Uint8Array(32);
    const hkdfBase = await crypto.subtle.importKey('raw', pbkdfBits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            salt: hkdfSalt,
            info: new TextEncoder().encode('omega-v3-msg-key'),
            hash: 'SHA-256'
        },
        hkdfBase,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function decryptAesGcm(buf, key) {
    const iv = buf.slice(0, 12);
    const c = buf.slice(12);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, c));
}

async function encryptAesGcm(buf, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf);
    const r = new Uint8Array(iv.length + c.byteLength);
    r.set(iv, 0); r.set(new Uint8Array(c), iv.length);
    return r;
}

function sendStrictFrame(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const bytes = new TextEncoder().encode(JSON.stringify(obj));
    if (bytes.length > 4092) return;
    const frame = new Uint8Array(4096);
    window.crypto.getRandomValues(frame);
    new DataView(frame.buffer).setUint32(0, bytes.length, true);
    frame.set(bytes, 4);
    ws.send(frame);
}

document.getElementById('auth-btn').onclick = async () => {
    if (pendingEncFile) {
        const passphrase = document.getElementById('passphrase-input').value;
        if (!passphrase) {
            document.getElementById('upload-status').textContent = 'ERROR: PASSPHRASE REQUIRED';
            return;
        }
        try {
            document.getElementById('upload-status').textContent = 'DECRYPTING KEY (PBKDF2 600k)...';
            document.getElementById('auth-btn').disabled = true;
            await new Promise(r => setTimeout(r, 50));
            const pemString = await decryptEncryptedKey(pendingEncFile, passphrase);
            await importKeys(pemString);
            pendingEncFile = null;
            document.getElementById('upload-status').textContent = 'KEY DECRYPTED — CONNECTING...';
        } catch (err) {
            document.getElementById('upload-status').textContent = 'ERROR: WRONG PASSPHRASE OR CORRUPT FILE';
            document.getElementById('auth-btn').disabled = false;
            return;
        }
    }
    document.getElementById('login-screen').classList.remove('active');
    document.getElementById('admin-dashboard').classList.add('active');
    connectAdmin();
};

function connectAdmin() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}`);
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => {
        sendStrictFrame({ type: 'HANDSHAKE', sessionId: sessionId });
        sendStrictFrame({ type: 'REQ_CHALLENGE' });
    };
    ws.onmessage = async (e) => {
        try {
            const view = new DataView(e.data);
            const len = view.getUint32(0, true);
            if (len === 0) return;
            const frame = JSON.parse(new TextDecoder().decode(new Uint8Array(e.data, 4, len)));

            if (frame.type === 'AUTH_CHALLENGE') {
                // PATCH VULN-03: Domain Separation — Prevents Blind Signing Oracle.
                const separatedNonce = 'OMEGA_ADMIN_AUTH:' + frame.nonce;
                const sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, masterSignKey, new TextEncoder().encode(separatedNonce));
                sendStrictFrame({ type: 'ADMIN_AUTH', signature: bufferToBase64(sig) });
            }

            // PFS-FIX: ECDH_EXCHANGE — Recibe la clave pública de un cliente (retransmitida
            // por el servidor). El Admin genera un par ECDH efímero para esta sesión,
            // computa el secreto compartido localmente y devuelve su clave pública.
            // El servidor NUNCA ve ni toca el secreto compartido.
            if (frame.type === 'ECDH_EXCHANGE' && frame.sessionId && frame.publicKey) {
                try {
                    const { keyPair, publicKeyHex } = await generateAdminECDH();
                    const sharedSecret = await computeAdminECDHSecret(keyPair, frame.publicKey);
                    sessionECDHSecrets[frame.sessionId] = sharedSecret;
                    sendStrictFrame({
                        type: 'ECDH_EXCHANGE',
                        publicKey: publicKeyHex,
                        targetSession: frame.sessionId
                    });
                } catch (err) { }
            }

            if (frame.type === 'HISTORY' || frame.type === 'NEW_MESSAGE') {
                const msg = frame.data ? frame.data.content : frame.content;
                if (!msg) return;

                if (msg.type === 'INIT') {
                    try {
                        const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, masterPrivateKey, base64ToBuffer(msg.data).buffer);
                        const initData = JSON.parse(new TextDecoder().decode(decrypted));
                        const sessId = msg.sessionId;
                        const existing = users[sessId];
                        if (existing && initData.ts <= existing.lastInitTs) return;
                        if (Math.abs(Date.now() - initData.ts) > 600000) return;

                        // PFS-FIX: Usar el secreto ECDH computado localmente (E2EE)
                        // en lugar de extraerlo del payload RSA. Si no existe un
                        // secreto ECDH local para esta sesión, rechazar el INIT.
                        const ecdhSecret = sessionECDHSecrets[sessId];
                        if (!ecdhSecret || !Array.isArray(ecdhSecret) || ecdhSecret.length < 32) {
                            return; // No hay ECDH E2EE completado para esta sesión.
                        }

                        users[sessId] = {
                            username: initData.username,
                            // PFS-FIX: deriveKey ahora usa el secreto ECDH E2EE local,
                            // NO el que viajaba dentro del RSA. PFS real.
                            symmetricKey: await deriveKey(initData.token, initData.sessionId || sessId, ecdhSecret),
                            receiveCounter: 0,
                            sendCounter: 0,
                            lastInitTs: initData.ts
                        };
                        if (msg.sessionHash) hashToId[msg.sessionHash] = sessId;
                        updateUserList();
                    } catch (err) { }
                } else if (msg.type === 'ASYNC_MSG') {
                    try {
                        const sessHash = msg.s;
                        const sessId = hashToId[sessHash] || sessHash;
                        const u = users[sessId];
                        if (!u || !u.symmetricKey) return;
                        const decBuf = await decryptAesGcm(base64ToBuffer(msg.payload), u.symmetricKey);
                        const decodedObj = JSON.parse(new TextDecoder().decode(decBuf));
                        crypto.getRandomValues(decBuf); // PARCHE VULN: Aislamiento de Memoria (destruir datos tras parseo, más robusto que fill(0))
                        if (decodedObj.c <= u.receiveCounter) return;
                        u.receiveCounter = decodedObj.c;
                        let text = decodedObj.p;
                        try { text = JSON.parse(text).text || text; } catch (e) { }
                        messages.push({ from: sessId, text });
                        if (selectedSessionId === sessId || selectedSessionId === null) renderMessages();
                    } catch (err) { }
                }
            } else if (frame.type === 'NUKE_EVENT') { location.reload(); }
        } catch (err) { }
    };
}

function updateUserList() {
    const list = document.getElementById('user-list');
    list.innerHTML = '';
    for (let sid in users) {
        const d = document.createElement('div');
        d.className = 'user-item' + (selectedSessionId === sid ? ' selected' : '');
        d.textContent = (users[sid].username || sid.slice(0, 12)) + ' (ON)';
        d.onclick = () => {
            selectedSessionId = sid;
            document.getElementById('chat-title').textContent = `MESSAGES: ${users[sid].username || sid.slice(0, 16)}`;
            updateUserList(); renderMessages();
        };
        list.appendChild(d);
    }
}

function renderMessages() {
    const div = document.getElementById('messages');
    div.innerHTML = '';
    const rel = messages.filter(m => selectedSessionId === null || m.from === selectedSessionId || m.to === selectedSessionId);
    rel.forEach(m => {
        const msg = document.createElement('div');
        msg.style.color = (m.from === 'ADMIN') ? '#aaa' : '#fff';
        const name = (m.from === 'ADMIN' ? 'YOU' : (users[m.from] ? users[m.from].username : m.from.slice(0, 8)));
        msg.textContent = `> ${name}: ` + m.text;
        div.appendChild(msg);
    });
    div.scrollTop = div.scrollHeight;
}

document.getElementById('send-btn').onclick = async () => {
    const input = document.getElementById('msg-input');
    const text = input.value.trim();
    if (!text || !selectedSessionId) return;
    const u = users[selectedSessionId];
    if (!u || !u.symmetricKey) return;
    input.value = '';
    messages.push({ from: 'ADMIN', to: selectedSessionId, text });
    u.sendCounter++;
    const payload = JSON.stringify({ user: 'ADMIN', text });
    const wrapped = JSON.stringify({ p: payload, c: u.sendCounter, t: Date.now() });
    const plainBuf = new TextEncoder().encode(wrapped);
    const encBuf = await encryptAesGcm(plainBuf, u.symmetricKey);
    crypto.getRandomValues(plainBuf); // PARCHE VULN: Aislamiento de Memoria (sobreescritura de buffer en texto plano)
    sendStrictFrame({ type: 'SERVER_MSG', targetSession: selectedSessionId, payload: bufferToBase64(encBuf) });
    renderMessages();
};

document.getElementById('broadcast-btn').onclick = () => {
    selectedSessionId = null;
    document.getElementById('chat-title').textContent = 'MESSAGES: BROADCAST';
    updateUserList(); renderMessages();
};

document.getElementById('nuke-btn').onclick = async () => {
    if (!confirm('PURGE ALL DATA?')) return;
    try { sendStrictFrame({ type: 'NUKE' }); } catch (err) { }
};

document.getElementById('zip-upload').onchange = async (e) => {
    const file = e.target.files[0];
    if (!file || !selectedSessionId) { e.target.value = ''; return; }
    const u = users[selectedSessionId];
    if (!u || !u.symmetricKey) { e.target.value = ''; return; }
    await sendFileToUser(file, selectedSessionId, u.symmetricKey);
    e.target.value = '';
};

function stripExifData(arrayBuffer) {
    const view = new DataView(arrayBuffer);
    if (arrayBuffer.byteLength < 4 || view.getUint8(0) !== 0xFF || view.getUint8(1) !== 0xD8) return arrayBuffer;
    const chunks = [];
    chunks.push(new Uint8Array(arrayBuffer, 0, 2));
    let offset = 2;
    while (offset < arrayBuffer.byteLength - 1) {
        if (view.getUint8(offset) !== 0xFF) break;
        const marker = view.getUint8(offset + 1);
        if (marker === 0xDA) { chunks.push(new Uint8Array(arrayBuffer, offset)); break; }
        if (marker === 0xD9) { chunks.push(new Uint8Array(arrayBuffer, offset, 2)); break; }
        if (offset + 3 >= arrayBuffer.byteLength) break;
        const segLen = view.getUint16(offset + 2);
        if (marker === 0xE1 || marker === 0xED) { offset += 2 + segLen; continue; }
        chunks.push(new Uint8Array(arrayBuffer, offset, 2 + segLen));
        offset += 2 + segLen;
    }
    let totalLen = 0;
    for (const c of chunks) totalLen += c.byteLength;
    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const c of chunks) { result.set(c, pos); pos += c.byteLength; }
    return result.buffer;
}

async function sendFileToUser(file, targetSession, symmetricKey) {
    const CHUNK_SIZE = 2048;
    let arrayBuffer = await file.arrayBuffer();
    if (/\.(jpe?g)$/i.test(file.name)) {
        arrayBuffer = stripExifData(arrayBuffer);
    }
    const totalBytes = arrayBuffer.byteLength;
    const totalChunks = Math.ceil(totalBytes / CHUNK_SIZE) || 1;
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    messages.push({ from: 'ADMIN', to: targetSession, text: `Sending: ${safeName}` });
    if (selectedSessionId === targetSession) renderMessages();
    sendStrictFrame({ type: 'FILE_META', targetSession, filename: safeName, totalChunks, fileSize: totalBytes });
    for (let i = 0; i < totalChunks; i++) {
        const offset = i * CHUNK_SIZE;
        const chunk = new Uint8Array(arrayBuffer, offset, Math.min(CHUNK_SIZE, totalBytes - offset));
        const encrypted = await encryptAesGcm(chunk, symmetricKey);
        sendStrictFrame({ type: 'FILE_CHUNK', targetSession, filename: safeName, chunkIndex: i, totalChunks, encData: bufferToBase64(encrypted) });
        if (i % 10 === 9) await new Promise(r => setTimeout(r, 10));
    }
}