const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn } = require('child_process');

let mainWindow;
let torProcess;
let serverProcess;

function getResourcePath(relPath) {
    const packagedPath = path.join(process.resourcesPath, relPath);
    if (app.isPackaged && fs.existsSync(packagedPath)) return packagedPath;
    return path.join(__dirname, relPath);
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 750, height: 550, backgroundColor: '#050505',
        resizable: false, autoHideMenuBar: true,
        webPreferences: {
            preload: path.join(__dirname, 'electron-preload.js'),
            contextIsolation: true, nodeIntegration: false
        }
    });
    mainWindow.loadFile('electron-ui.html');
    mainWindow.webContents.on('did-finish-load', () => checkKeysAndBoot());
}

function encryptPrivateKey(pemString, passphrase) {
    const salt = crypto.randomBytes(32);
    const iterations = 600000;
    const key = crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(pemString, 'utf8'), cipher.final()]);
    return JSON.stringify({
        version: 3, kdf: 'pbkdf2', kdfParams: { iterations, hash: 'SHA-256' },
        salt: salt.toString('hex'), iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'),
        ciphertext: encrypted.toString('hex')
    }, null, 2);
}

async function handleKeygen(passphrase) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const dataDir = app.isPackaged ? app.getPath('userData') : __dirname;
    fs.writeFileSync(path.join(dataDir, 'master_public.pem'), publicKey);
    fs.writeFileSync(path.join(dataDir, 'master_private.enc'), encryptPrivateKey(privateKey, passphrase));

    const adminSalt = crypto.randomBytes(32);
    const adminSecret = crypto.scryptSync(passphrase, Buffer.concat([adminSalt, Buffer.from('ztap:admin:hmac')]), 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const serverNonce = crypto.randomBytes(32);
    fs.writeFileSync(path.join(dataDir, 'server_secrets.enc'), JSON.stringify({
        version: 2, adminSalt: adminSalt.toString('hex'), adminSecret: adminSecret.toString('hex'), serverNonce: serverNonce.toString('hex')
    }, null, 2));
    return true;
}

function checkKeysAndBoot() {
    const dataDir = app.isPackaged ? app.getPath('userData') : __dirname;
    if (!fs.existsSync(path.join(dataDir, 'master_public.pem'))) {
        mainWindow.webContents.send('needs-keygen');
    } else {
        bootSystem(dataDir);
    }
}

ipcMain.handle('submit-passphrase', async (event, passphrase) => {
    await handleKeygen(passphrase);
    bootSystem(app.isPackaged ? app.getPath('userData') : __dirname);
    return true;
});

ipcMain.handle('open-dashboard', (event, url) => shell.openExternal(url));

function bootSystem(dataDir) {
    // 1. Start Server (In-Process)
    process.env.ZTAP_DATA_DIR = dataDir;
    try {
        require(path.join(__dirname, 'src/server.js'));
    } catch (err) {
        console.error('Failed to start server:', err);
    }

    // 2. Identity Rotation (Anti-Forensic)
    const torOnionDir = path.join(dataDir, 'onion_service');
    if (fs.existsSync(torOnionDir)) {
        const files = fs.readdirSync(torOnionDir);
        for (const file of files) {
            try {
                const filePath = path.join(torOnionDir, file);
                if (fs.statSync(filePath).isFile()) {
                    fs.writeFileSync(filePath, crypto.randomBytes(fs.statSync(filePath).size));
                    fs.unlinkSync(filePath);
                }
            } catch(e) {}
        }
    } else { fs.mkdirSync(torOnionDir, { recursive: true }); }

    // 3. Start Tor
    const torDataDir = path.join(dataDir, 'tor_data');
    if (!fs.existsSync(torDataDir)) fs.mkdirSync(torDataDir, { recursive: true });

    const dynamicTorrcPath = path.join(dataDir, 'torrc.txt');
    const torrcContent = `
HiddenServiceDir ${torOnionDir}
HiddenServicePort 80 127.0.0.1:3000
DataDirectory ${torDataDir}
`;
    fs.writeFileSync(dynamicTorrcPath, torrcContent.trim());

    const torExe = getResourcePath('Tor/tor.exe');
    torProcess = spawn(torExe, ['-f', dynamicTorrcPath]);

    let torReady = false;
    torProcess.stdout.on('data', (data) => {
        const text = data.toString();

        const match = text.match(/Bootstrapped (\d+)%/);
        if (match) {
            const percent = parseInt(match[1]);
            let status = 'Connecting to nodes...';
            if (percent > 10) status = 'Negotiating circuits...';
            if (percent > 80) status = 'Publishing hidden service...';
            if (percent === 100) status = 'Service active';
            mainWindow.webContents.send('tor-status', { percent, status });
            if (percent === 100 && !torReady) {
                torReady = true;
                setTimeout(() => finalizeBoot(dataDir), 2000);
            }
        }
    });

    torProcess.stderr.on('data', (data) => console.error('TOR STDERR:', data.toString().trim()));
}

function finalizeBoot(dataDir) {
    const hostnamePath = path.join(dataDir, 'onion_service', 'hostname');
    let onion = fs.existsSync(hostnamePath) ? fs.readFileSync(hostnamePath, 'utf8').trim() : 'error.onion';

    const secretsPath = path.join(dataDir, 'server_secrets.enc');
    let adminPath = 'route';
    if (fs.existsSync(secretsPath)) {
        const secrets = JSON.parse(fs.readFileSync(secretsPath, 'utf8'));
        const dayNonce = String(Math.floor(Date.now() / 86400000));
        const hourlyNonce = String(Math.floor(Date.now() / 3600000));
        adminPath = crypto.createHmac('sha256', secrets.adminSecret).update(dayNonce + ':' + hourlyNonce + ':' + secrets.serverNonce).digest('hex');
    }
    mainWindow.webContents.send('system-ready', { onion, adminPath });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (torProcess) torProcess.kill();
    app.quit();
});
