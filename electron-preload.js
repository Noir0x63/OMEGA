const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Escuchar eventos desde el backend
    onTorStatus: (callback) => ipcRenderer.on('tor-status', (_event, value) => callback(value)),
    onSystemReady: (callback) => ipcRenderer.on('system-ready', (_event, value) => callback(value)),
    onNeedsKeygen: (callback) => ipcRenderer.on('needs-keygen', () => callback()),
    
    // Enviar acciones al backend
    submitPassphrase: (passphrase) => ipcRenderer.invoke('submit-passphrase', passphrase),
    openDashboard: (url) => ipcRenderer.invoke('open-dashboard', url),
    toggleSessions: (status) => ipcRenderer.invoke('toggle-sessions', status),
    selfDestruct: () => ipcRenderer.invoke('self-destruct')
});
