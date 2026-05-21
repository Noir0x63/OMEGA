const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

let messageVault = [];
let adminSocket = null;
const activeSessionIds = new Set();

const dataDir = process.env.ZTAP_DATA_DIR || path.join(__dirname, '..');
const VAULT_FILE = path.join(dataDir, 'vault.json');
const MAX_VAULT_SIZE = 5000;
const CHALLENGE_TTL = 30000;
const MSG_RATE_LIMIT = 50;
const BROADCAST_LIMIT_MS = 500;
const HANDSHAKE_TIMEOUT = 20000;
const MAX_CONN_PER_ID = 2;
const MAX_TOTAL_CONN = 500;
const SESSION_MAX_AGE = 3600000;
const MAX_INPUT_LENGTH = 4096;

let HMAC_SECRET = null;
let SERVER_NONCE = null;
try {
    const secrets = JSON.parse(fsSync.readFileSync(path.join(dataDir, 'server_secrets.enc'), 'utf8'));
    HMAC_SECRET = secrets.adminSecret;
    SERVER_NONCE = secrets.serverNonce;
} catch (e) {
    console.error('[SERVER] CRITICAL: server_secrets.enc not found. Run keygen.js first.');
}

function computeAdminPath(dayOffset = 0) {
    if (!HMAC_SECRET || !SERVER_NONCE) return null;
    const dayNonce = String(Math.floor(Date.now() / 86400000) + dayOffset);
    const hourlyNonce = String(Math.floor(Date.now() / 3600000));
    return crypto.createHmac('sha256', HMAC_SECRET)
        .update(dayNonce + ':' + hourlyNonce + ':' + SERVER_NONCE)
        .digest('hex');
}

function isValidAdminPath(token) {
    if (!HMAC_SECRET || !token || typeof token !== 'string') return false;
    const current = computeAdminPath(0);
    if (!current) return false;
    const lastHour = crypto.createHmac('sha256', HMAC_SECRET)
        .update(String(Math.floor(Date.now() / 86400000)) + ':' + String(Math.floor(Date.now() / 3600000) - 1) + ':' + SERVER_NONCE)
        .digest('hex');
    try {
        const tBuf = Buffer.from(token.padEnd(64, '0').slice(0, 64));
        const cBuf = Buffer.from(current.padEnd(64, '0').slice(0, 64));
        const lBuf = Buffer.from(lastHour.padEnd(64, '0').slice(0, 64));
        return crypto.timingSafeEqual(tBuf, cBuf) || crypto.timingSafeEqual(tBuf, lBuf);
    } catch (e) {
        return false;
    }
}

const POW_BASE_DIFFICULTY = 16;
const POW_MAX_DIFFICULTY = 24;
const powChallenges = new Map();

function getAdaptiveDifficulty() {
    const connectionLoad = wss ? wss.clients.size / MAX_TOTAL_CONN : 0;
    if (connectionLoad > 0.8) return POW_MAX_DIFFICULTY;
    if (connectionLoad > 0.5) return POW_BASE_DIFFICULTY + 4;
    return POW_BASE_DIFFICULTY;
}

function generatePoWChallenge(ws) {
    const challenge = crypto.randomBytes(16).toString('hex');
    const difficulty = getAdaptiveDifficulty();
    powChallenges.set(ws, { challenge, ts: Date.now(), difficulty });
    return { challenge, difficulty };
}

function verifyPoW(ws, nonce) {
    const stored = powChallenges.get(ws);
    if (!stored || Date.now() - stored.ts > 60000) return false;
    if (typeof nonce !== 'string' || nonce.length > 32) return false;
    const hash = crypto.createHash('sha256').update(nonce + stored.challenge).digest();
    let zeroBits = 0;
    for (const byte of hash) {
        if (byte === 0) { zeroBits += 8; }
        else {
            let b = byte;
            while ((b & 0x80) === 0) { zeroBits++; b <<= 1; }
            break;
        }
        if (zeroBits >= stored.difficulty) break;
    }
    if (zeroBits >= stored.difficulty) {
        powChallenges.delete(ws);
        return true;
    }
    return false;
}

const sessionECDH = new Map();

function generateECDHKeyPair() {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return ecdh;
}

const sessionSockets = new Map();
const challenges = new Map();
const activeSessions = new Map();
const connRateLimit = new Map();
const ipBanList = new Map();

function isSessionExpired(sessionId) {
    const session = activeSessions.get(sessionId);
    if (!session) return true;
    return (Date.now() - session.createdAt) > SESSION_MAX_AGE;
}

async function loadVault() {
    try {
        const data = await fs.readFile(VAULT_FILE, 'utf8');
        messageVault = JSON.parse(data).slice(-MAX_VAULT_SIZE);
    } catch (e) { messageVault = []; }
}
loadVault();

let vaultMutex = Promise.resolve();

function saveVault() {
    vaultMutex = vaultMutex.then(async () => {
        try { await fs.writeFile(VAULT_FILE, JSON.stringify(messageVault, null, 2)); } catch (e) { }
    }).catch(() => {});
    return vaultMutex;
}

setInterval(async () => {
    messageVault = [];
    await saveVault();

    if (adminSocket && adminSocket.readyState === 1) {
        try {
            const bytes = Buffer.from(JSON.stringify({ type: 'NEW_MESSAGE', data: { timestamp: Date.now(), content: { type: 'BROADCAST', user: 'SYSTEM', payload: 'VAULT_PURGE_SUCCESSFUL' } } }), 'utf8');
            const frame = Buffer.alloc(4096);
            crypto.randomFillSync(frame);
            frame.writeUint32LE(bytes.length, 0);
            bytes.copy(frame, 4);
            adminSocket.send(frame);
        } catch (e) { }
    }
}, 86400000);

setInterval(() => {
    const now = Date.now();
    for (const [sessionId, session] of activeSessions) {
        if (now - session.createdAt > SESSION_MAX_AGE) {
            const sockets = sessionSockets.get(sessionId);
            if (sockets) {
                for (const s of sockets) {
                    try { sendStrictFrame(s, { type: 'SESSION_EXPIRED' }); } catch (e) { }
                    try { s.close(1008, 'Session expired'); } catch (e) { }
                }
                sessionSockets.delete(sessionId);
            }
            activeSessions.delete(sessionId);
            sessionECDH.delete(sessionId);
        }
    }
    for (const [ip, expiry] of ipBanList) {
        if (now > expiry) ipBanList.delete(ip);
    }
}, 60000);

function hashField(val) {
    if (typeof val !== 'string') return '';
    if (!HMAC_SECRET) throw new Error('[SERVER] CRITICAL: Cannot hash field without HMAC_SECRET.');
    const salt = crypto.createHash('sha256').update(HMAC_SECRET).digest('hex').slice(0, 16);
    return crypto.createHash('sha256').update(String(val) + salt).digest('hex');
}

async function getMasterPublicKey() {
    try {
        return await fs.readFile(path.join(dataDir, 'master_public.pem'), 'utf8');
    } catch (e) {
        try { return await fs.readFile('master_public.pem', 'utf8'); } catch { return null; }
    }
}

function sanitizeString(input, maxLen = 256) {
    if (typeof input !== 'string') return '';
    return input.slice(0, maxLen).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

function validateSessionId(id) {
    if (typeof id !== 'string') return false;
    if (id.length !== 32) return false;
    return /^[a-f0-9]{32}$/.test(id);
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

app.disable('x-powered-by');
app.set('etag', false);
app.use(cors());

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' blob: 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss: blob: data:; img-src 'self' data:; media-src 'self' data:; frame-ancestors 'none';");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("X-XSS-Protection", "0");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.get('/:token', (req, res, next) => {
    if (isValidAdminPath(req.params.token)) return res.sendFile(path.join(__dirname, '../public/admin.html'));
    next();
});
app.use(express.static(path.join(__dirname, '../public')));

app.use((err, req, res, next) => {
    res.status(500).end();
});

server.on('upgrade', (request, socket, head) => {
    const ip = request.socket.remoteAddress;
    const now = Date.now();

    if (ipBanList.has(ip) && now < ipBanList.get(ip)) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
    }

    const rateEntry = connRateLimit.get(ip) || { lastTime: 0, count: 0, windowStart: now };
    if (now - rateEntry.windowStart > 60000) {
        rateEntry.count = 0;
        rateEntry.windowStart = now;
    }
    rateEntry.count++;
    rateEntry.lastTime = now;
    connRateLimit.set(ip, rateEntry);

    if (rateEntry.count > 30) {
        const banDuration = Math.min(rateEntry.count * 10000, 600000);
        ipBanList.set(ip, now + banDuration);
        socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
        socket.destroy();
        return;
    }

    if (now - rateEntry.lastTime < 500 && rateEntry.count > 5) {
        socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
        socket.destroy();
        return;
    }

    if (wss.clients.size >= MAX_TOTAL_CONN) {
        socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
        socket.destroy();
        return;
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

function sendStrictFrame(ws, payloadObj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
        const payloadBytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
        if (payloadBytes.length > 4092) return;
        const frame = Buffer.alloc(4096);
        crypto.randomFillSync(frame);
        frame.writeUint32LE(payloadBytes.length, 0);
        payloadBytes.copy(frame, 4);
        ws.send(frame);
    } catch (e) { }
}

wss.on('connection', (ws) => {
    ws.msgCount = 0;
    ws.lastReset = Date.now();
    ws.sessionId = null;
    ws.lastBroadcast = 0;
    ws.authenticated = false;
    ws.attestKey = null;
    ws.attestChallenge = null;
    ws.attestTimeout = null;
    ws.attestFailCount = 0;
    ws.attestInterval = null;

    const hTimeout = setTimeout(() => { if (!ws.sessionId) ws.close(1008); }, HANDSHAKE_TIMEOUT);

    ws.on('message', async (message) => {
        const now = Date.now();

        if (now - ws.lastReset > 10000) { ws.msgCount = 0; ws.lastReset = now; }
        if (++ws.msgCount > MSG_RATE_LIMIT) return ws.close(1008);
        if (message.length !== 4096) return;

        try {
            const len = message.readUint32LE(0);
            if (len === 0) return;
            if (len > 4092) return;
            const rawJson = message.subarray(4, 4 + len).toString('utf8');
            const data = JSON.parse(rawJson);

            if (!data || typeof data.type !== 'string') return;

            if (!ws.sessionId && data.type !== 'HANDSHAKE') return ws.close(1008);

            if (ws.sessionId && isSessionExpired(ws.sessionId)) {
                sendStrictFrame(ws, { type: 'SESSION_EXPIRED' });
                return ws.close(1008);
            }

            if (data.type === 'HANDSHAKE') {
                if (ws.sessionId) return;
                if (!validateSessionId(data.sessionId)) return ws.close(1008);
                const sessionInfo = activeSessions.get(data.sessionId);
                const count = sessionInfo ? sessionInfo.count : 0;
                if (count >= MAX_CONN_PER_ID) return ws.close(1008);
                clearTimeout(hTimeout);
                ws.sessionId = data.sessionId;

                if (!sessionECDH.has(data.sessionId)) {
                    const ecdh = generateECDHKeyPair();
                    sessionECDH.set(data.sessionId, { ecdh, sharedKey: null });
                }
                const ecdhData = sessionECDH.get(data.sessionId);
                const serverECDHPublic = ecdhData.ecdh.getPublicKey('hex');

                activeSessions.set(ws.sessionId, {
                    count: count + 1,
                    createdAt: sessionInfo ? sessionInfo.createdAt : now
                });

                sendStrictFrame(ws, {
                    type: 'ECDH_EXCHANGE',
                    serverPublicKey: serverECDHPublic
                });
                return;
            }

            if (data.type === 'ECDH_CLIENT_KEY') {
                if (!data.clientPublicKey || typeof data.clientPublicKey !== 'string') return ws.close(1008);
                if (data.clientPublicKey.length > 256) return ws.close(1008);
                const ecdhData = sessionECDH.get(ws.sessionId);
                if (!ecdhData) return ws.close(1008);
                try {
                    const sharedSecret = ecdhData.ecdh.computeSecret(Buffer.from(data.clientPublicKey, 'hex'));
                    ecdhData.sharedKey = crypto.createHash('sha256')
                        .update(sharedSecret)
                        .update(Buffer.from(ws.sessionId, 'hex'))
                        .digest();
                    sendStrictFrame(ws, { type: 'ECDH_COMPLETE', status: 'ok' });
                } catch (e) {
                    ws.close(1008);
                }
                return;
            }

            if (data.type === 'REQ_POW') {
                const { challenge, difficulty } = generatePoWChallenge(ws);
                return sendStrictFrame(ws, { type: 'POW_CHALLENGE', challenge, difficulty });
            }

            if (data.type === 'REQ_CHALLENGE') {
                const nonce = crypto.randomBytes(32).toString('hex');
                challenges.set(ws, { nonce, ts: Date.now() });
                return sendStrictFrame(ws, { type: 'AUTH_CHALLENGE', nonce });
            }

            if (data.type === 'ADMIN_AUTH') {
                const stored = challenges.get(ws);
                if (!stored || Date.now() - stored.ts > CHALLENGE_TTL) return ws.close(1008);
                if (!data.signature || typeof data.signature !== 'string') return ws.close(1008);
                const pubKey = await getMasterPublicKey();
                if (!pubKey) return ws.close(1008);
                try {
                    const isValid = crypto.verify('sha256', Buffer.from(stored.nonce), {
                        key: pubKey,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: 32
                    }, Buffer.from(data.signature, 'base64'));
                    if (isValid) {
                        if (adminSocket && adminSocket.readyState === WebSocket.OPEN) adminSocket.close(1000);
                        adminSocket = ws;
                        ws.authenticated = true;
                        challenges.delete(ws);
                        for (let msg of messageVault) sendStrictFrame(ws, { type: 'HISTORY', data: msg });
                        for (let [sid, sockets] of sessionSockets) {
                            for (let s of sockets) {
                                if (s.initData) { sendStrictFrame(ws, { type: 'NEW_MESSAGE', data: { timestamp: Date.now(), content: s.initData } }); break; }
                            }
                        }
                    } else { ws.close(1008); }
                } catch (e) {
                    ws.close(1008);
                }
                return;
            }

            if (data.type === 'INIT') {
                if (!data.powNonce || !verifyPoW(ws, data.powNonce)) {
                    const { challenge, difficulty } = generatePoWChallenge(ws);
                    return sendStrictFrame(ws, { type: 'POW_CHALLENGE', challenge, difficulty });
                }
                if (!data.user || typeof data.user !== 'string') return ws.close(1008);
                const sanitizedUser = sanitizeString(data.user, 64);
                if (!sanitizedUser) return ws.close(1008);
                ws.username = sanitizedUser;
                ws.initData = { ...data, user: sanitizedUser, sessionId: ws.sessionId };
                if (!sessionSockets.has(ws.sessionId)) sessionSockets.set(ws.sessionId, new Set());
                sessionSockets.get(ws.sessionId).add(ws);
                const sessHash = hashField(ws.sessionId);
                const history = messageVault.filter(m => m.content.s === sessHash || m.content.ts === sessHash);
                history.forEach(m => sendStrictFrame(ws, { type: 'HISTORY', data: m }));
                if (adminSocket) {
                    const adminInit = { ...ws.initData, sessionHash: hashField(ws.sessionId) };
                    sendStrictFrame(adminSocket, { type: 'NEW_MESSAGE', data: { timestamp: Date.now(), content: adminInit } });
                }

                if (data.attestKey && typeof data.attestKey === 'string' && data.attestKey.length <= 256) {
                    ws.attestKey = Buffer.from(data.attestKey, 'base64');
                    ws.attestInterval = setInterval(() => {
                        if (ws.readyState !== WebSocket.OPEN) {
                            clearInterval(ws.attestInterval);
                            return;
                        }
                        const challenge = crypto.randomBytes(16).toString('hex');
                        ws.attestChallenge = challenge;
                        ws.attestTimeout = setTimeout(() => {
                            ws.attestFailCount++;
                            ws.attestChallenge = null;
                            if (ws.attestFailCount >= 3) {
                                try { ws.close(1008, 'Attestation timeout'); } catch (e) { }
                            }
                        }, 5000);
                        sendStrictFrame(ws, { type: 'ATTEST_CHALLENGE', challenge });
                    }, 30000);
                }
                return;
            }

            if (data.type === 'ATTEST_RESPONSE') {
                if (!ws.attestKey || !ws.attestChallenge) return;
                if (!data.signature || typeof data.signature !== 'string') return ws.close(1008);
                try {
                    const expectedSig = crypto.createHmac('sha256', ws.attestKey)
                        .update(ws.attestChallenge).digest();
                    const actualSig = Buffer.from(data.signature, 'base64');
                    if (expectedSig.length !== actualSig.length ||
                        !crypto.timingSafeEqual(expectedSig, actualSig)) {
                        ws.attestFailCount++;
                        if (ws.attestFailCount >= 3) return ws.close(1008, 'Attestation failed');
                    } else {
                        clearTimeout(ws.attestTimeout);
                        ws.attestChallenge = null;
                        ws.attestFailCount = 0;
                    }
                } catch (e) {
                    ws.attestFailCount++;
                    if (ws.attestFailCount >= 3) return ws.close(1008);
                }
                return;
            }

            if (data.type === 'ASYNC_MSG' || data.type === 'SERVER_MSG' || data.type === 'FILE_META' || data.type === 'FILE_CHUNK' || data.type === 'BROADCAST') {
                const isFromAdmin = (ws === adminSocket);

                if (!isFromAdmin && now - ws.lastBroadcast < BROADCAST_LIMIT_MS) return;
                ws.lastBroadcast = now;

                if (!isFromAdmin && (data.targetSession === 'ALL' || data.type === 'BROADCAST')) return;

                // Override data.user with the authenticated socket's username to prevent spoofing
                data.user = isFromAdmin ? 'ADMIN' : ws.username;

                if (data.targetSession && typeof data.targetSession === 'string' && data.targetSession !== 'ALL' && data.targetSession !== 'ADMIN') {
                    if (!validateSessionId(data.targetSession)) return;
                }

                const needsVaultWrite = data.type !== 'FILE_CHUNK' && data.type !== 'FILE_META';
                if (needsVaultWrite && !isFromAdmin) {
                    if (!data.powNonce || !verifyPoW(ws, data.powNonce)) {
                        const { challenge, difficulty } = generatePoWChallenge(ws);
                        return sendStrictFrame(ws, { type: 'POW_CHALLENGE', challenge, difficulty });
                    }
                }

                const safeContent = { ...data };
                delete safeContent.powNonce;
                safeContent.s = isFromAdmin ? 'ADMIN' : hashField(ws.sessionId);
                if (safeContent.targetSession && safeContent.targetSession !== 'ALL') safeContent.ts = hashField(safeContent.targetSession);

                const record = { timestamp: Date.now(), content: safeContent };
                if (needsVaultWrite) {
                    messageVault.push(record);
                    if (messageVault.length > MAX_VAULT_SIZE) messageVault.shift();
                    await saveVault();
                }

                if (adminSocket && !isFromAdmin) {
                    const adminRecord = { ...record, content: { ...record.content, s: ws.sessionId } };
                    sendStrictFrame(adminSocket, { type: 'NEW_MESSAGE', data: adminRecord });
                }

                if (data.targetSession === 'ALL' || data.type === 'BROADCAST') {
                    for (let [, sockets] of sessionSockets) {
                        for (let s of sockets) if (s !== ws && s.readyState === WebSocket.OPEN) sendStrictFrame(s, { type: 'NEW_MESSAGE', data: record });
                    }
                } else if (data.targetSession && data.targetSession !== 'ADMIN') {
                    const sockets = sessionSockets.get(data.targetSession);
                    if (sockets) for (let s of sockets) if (s.readyState === WebSocket.OPEN) sendStrictFrame(s, { type: 'NEW_MESSAGE', data: record });
                }
            }
        } catch (e) { }
    });

    ws.on('close', () => {
        clearTimeout(hTimeout);
        if (ws.attestInterval) clearInterval(ws.attestInterval);
        if (ws.attestTimeout) clearTimeout(ws.attestTimeout);
        if (ws.sessionId) {
            const sockets = sessionSockets.get(ws.sessionId);
            if (sockets) { sockets.delete(ws); if (sockets.size === 0) sessionSockets.delete(ws.sessionId); }
            const session = activeSessions.get(ws.sessionId);
            if (session) {
                if (session.count <= 1) {
                    activeSessions.delete(ws.sessionId);
                    sessionECDH.delete(ws.sessionId);
                } else {
                    session.count--;
                }
            }
        }
        if (ws === adminSocket) adminSocket = null;
        challenges.delete(ws);
        powChallenges.delete(ws);
    });
});

server.listen(process.env.PORT || 3000);