let localKey = null;
let adminPublicKey = null;
let attestSignKey = null; // PARCHE HALLAZGO-D: Llave privada ECDSA (nunca se exporta)
let initResolver;
const initPromise = new Promise(resolve => { initResolver = resolve; });

let sendCounter = 0;
let receiveCounter = 0;

function secureBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBuffer(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
}

// PARCHE VULN-1: KDF de dos etapas PBKDF2 → HKDF para PFS real.
// Etapa 1 (PBKDF2): Resistencia a fuerza bruta sobre el token del usuario.
// Etapa 2 (HKDF): Amarra el secreto ECDH efímero. Sin él, la clave AES es irrecuperable.
async function deriveKey(token, salt, ecdhSecret) {
    const enc = new TextEncoder();
    const tokenBuf = enc.encode(token);
    const saltBuf = enc.encode(salt);

    // Etapa 1: PBKDF2 — deriva bits intermedios (no una clave AES directamente)
    const pbkdfBase = await crypto.subtle.importKey('raw', tokenBuf, 'PBKDF2', false, ['deriveBits']);
    const pbkdfBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBuf, iterations: 600000, hash: 'SHA-256' },
        pbkdfBase,
        256
    );

    // Etapa 2: HKDF — ata el secreto ECDH efímero como sal para PFS real
    // Si ecdhSecret no está disponible, se usa un buffer cero (degradación segura)
    const hkdfSalt = ecdhSecret ? new Uint8Array(ecdhSecret) : new Uint8Array(32);
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

// PARCHE HALLAZGO-D: Par asimétrico ECDSA. La privada queda aislada en el Worker.
async function generateAttestKeyPair() {
    return await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, // privateKey.extractable = false
        ['sign', 'verify']
    );
}

async function aesGcmEncrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(iv, 0); result.set(new Uint8Array(ciphertext), 12);
    return result;
}

async function aesGcmDecrypt(key, encryptedData) {
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext));
}

async function solvePoW(challenge, difficulty) {
    let nonce = 0;
    const enc = new TextEncoder();
    while (true) {
        const candidate = nonce.toString(16) + challenge;
        const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(candidate));
        const hash = new Uint8Array(hashBuf);
        let zeroBits = 0;
        let solved = false;
        for (const byte of hash) {
            if (byte === 0) { zeroBits += 8; }
            else {
                let b = byte;
                while ((b & 0x80) === 0) { zeroBits++; b <<= 1; }
                break;
            }
            if (zeroBits >= difficulty) { solved = true; break; }
        }
        if (solved) return nonce.toString(16);
        nonce++;
        if (nonce % 2000 === 0) await new Promise(r => setTimeout(r, 0));
    }
}

self.onmessage = async (e) => {
    const d = e.data;
    try {
        if (d.type === 'INIT') {
            // PARCHE HALLAZGO-B: Fallo duro si no hay secreto ECDH efímero.
            if (!d.ecdhSecret || !Array.isArray(d.ecdhSecret) || d.ecdhSecret.length < 32) {
                self.postMessage({ type: 'ERROR', error: 'SEC_FAULT_NO_ECDH' });
                return;
            }

            localKey = await deriveKey(d.token, d.sessionId, d.ecdhSecret);

            // PARCHE HALLAZGO-D: Generar par ECDSA efímero. Privada aislada en Worker.
            const attestKeyPair = await generateAttestKeyPair();
            attestSignKey = attestKeyPair.privateKey;

            const pemContents = d.masterPublicPem.replace(/-----(BEGIN|END) PUBLIC KEY-----|\s/g, '');
            const binaryDer = base64ToBuffer(pemContents);
            adminPublicKey = await crypto.subtle.importKey('spki', binaryDer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);

            const enc = new TextEncoder();
            // PFS-FIX: El ecdhSecret ya NO se incluye en el payload RSA.
            // Incluirlo antes destruía el PFS, ya que un compromiso futuro de la
            // clave RSA privada permitía extraer el secreto efímero y descifrar
            // todas las sesiones pasadas. Ahora el ECDH es estrictamente E2EE
            // entre Cliente y Admin — el secreto compartido NUNCA sale de la memoria.
            const initPayloadBuf = enc.encode(JSON.stringify({
                token: d.token,
                username: d.username,
                sessionId: d.sessionId,
                ts: Date.now()
            }));
            const encInit = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, adminPublicKey, initPayloadBuf);
            crypto.getRandomValues(initPayloadBuf); // PARCHE AUDITORIA: Destruir buffer de handshake (contiene token)

            // PARCHE HALLAZGO-D: Exportar SOLO la llave PÚBLICA (SPKI).
            const attestPubSpki = await crypto.subtle.exportKey('spki', attestKeyPair.publicKey);

            initResolver();
            self.postMessage({ type: 'INITIALIZED', payload: secureBufferToBase64(encInit), attestKey: secureBufferToBase64(attestPubSpki) });
            return;
        }

        if (d.type === 'ATTEST_CHALLENGE') {
            await initPromise;
            const challengeBuf = new TextEncoder().encode(d.challenge);
            // PARCHE HALLAZGO-D: Firmar con ECDSA (llave privada aislada).
            const sig = await crypto.subtle.sign(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                attestSignKey,
                challengeBuf
            );
            self.postMessage({ type: 'ATTEST_RESPONSE', signature: secureBufferToBase64(sig), challenge: d.challenge });
            return;
        }

        if (d.type === 'SOLVE_POW') {
            const nonce = await solvePoW(d.challenge, d.difficulty);
            self.postMessage({ type: 'POW_SOLVED', nonce, challenge: d.challenge });
            return;
        }

        await initPromise;

        if (d.type === 'ENCRYPT_MSG') {
            const enc = new TextEncoder();
            sendCounter++;
            const payloadWithCounter = JSON.stringify({ p: d.payload, c: sendCounter, t: Date.now() });
            const plainBuf = enc.encode(payloadWithCounter);
            const encData = await aesGcmEncrypt(localKey, plainBuf);
            crypto.getRandomValues(plainBuf); // PARCHE VULN: Aislamiento de Memoria (sobreescritura de buffer en texto plano)
            self.postMessage({ type: 'ENCRYPT_VAULT_RESULT', payload: secureBufferToBase64(encData), msgId: d.msgId });

        } else if (d.type === 'DECRYPT_MSG') {
            const decBuf = await aesGcmDecrypt(localKey, new Uint8Array(d.payload));
            const decodedObj = JSON.parse(new TextDecoder().decode(decBuf));
            crypto.getRandomValues(decBuf); // PARCHE VULN: Aislamiento de Memoria (destruir datos tras parseo)
            if (decodedObj.c <= receiveCounter) throw new Error('REPLAY');
            receiveCounter = decodedObj.c;
            self.postMessage({ type: 'DECRYPT_MSG_RESULT', payload: decodedObj.p, msgId: d.msgId });

        } else if (d.type === 'DECRYPT_FILE_CHUNK') {
            const decBuf = await aesGcmDecrypt(localKey, new Uint8Array(d.payload));
            self.postMessage({ type: 'DECRYPT_FILE_CHUNK_RESULT', chunkIndex: d.chunkIndex, totalChunks: d.totalChunks, filename: d.filename, payload: decBuf.buffer }, [decBuf.buffer]);
        }
    } catch (err) { self.postMessage({ type: 'ERROR', error: 'SEC_FAULT_0x1' }); }
};