# INFORME DE AUDITORÍA CRIPTOGRÁFICA RED TEAM: ZTAP v3.1 IRONCLAD

**OBJETIVO:** Evaluación agresiva (Zero Trust) de la implementación E2EE, mecanismos de atestación y manejo de llaves.
**RESULTADO GENERAL:** Múltiples vulnerabilidades de severidad CRÍTICA que destruyen completamente las garantías de confidencialidad a largo plazo (Forward Secrecy), autenticidad e integridad del protocolo. El sistema no debe ser utilizado en producción bajo el modelo actual.

A continuación, el desglose línea por línea de las vulnerabilidades descubiertas siguiendo los mandatos de auditoría:

---

### VULNERABILIDAD 1: Teatro de Seguridad en Perfect Forward Secrecy (PFS) y ECDH Inerte

DICTAMEN: CRÍTICO

VULNERABILIDAD DESCUBIERTA: Falsa implementación de Perfect Forward Secrecy (PFS) y dependencia de cifrado asimétrico estático. El protocolo simula realizar una ceremonia ECDH entre el cliente y el servidor (creando `ecdhSharedSecret`), pero **este secreto jamás se utiliza** para inicializar los motores de cifrado AES-GCM. La llave simétrica real End-to-End (`localKey`) se deriva de forma puramente determinista (vía PBKDF2) usando el `token` del usuario y el `sessionId`. Estos dos valores estáticos se transmiten al servidor en el mensaje `INIT` envueltos con la llave pública RSA estática del administrador (`adminPublicKey`).

VECTOR DE EXPLOTACIÓN (PoC):
1. El atacante intercepta y guarda todo el tráfico pasivo de la red (WebSocket / Tor).
2. En un evento de compromiso post-incidente (Post-Compromise), el atacante obtiene la `masterPrivateKey` (la llave RSA a largo plazo del administrador).
3. Utilizando la llave RSA, el atacante descifra retrospectivamente los payloads `INIT` capturados y extrae el `token` y el `sessionId`.
4. El atacante ejecuta el mismo algoritmo del Worker (`deriveKey(token, sessionId)`) para regenerar exactamente la misma llave `localKey` AES-GCM.
5. El atacante descifra todo el historial de mensajes de AES-GCM capturados, destruyendo por completo cualquier ilusión de Forward Secrecy.

IMPACTO (CVSS Estimado): 9.8 (Crítico). Destrucción retroactiva de la Confidencialidad total si la llave maestra asimétrica es comprometida.

EL PARCHE (Diff/Código):
```javascript
// Debido a que el protocolo es asíncrono y el admin no siempre está en línea para 
// un verdadero ECDH E2E, la solución inmediata (sin reescribir todo el protocolo 
// al modelo Signal) requiere integrar criptografía híbrida atada a la sesión del lado del admin.
// Sin embargo, para forzar PFS real, el Admin DEBE usar llaves efímeras.
// Parche conceptual mínimo para mitigar el engaño actual (Eliminar el falso ECDH):

// En src/client.js: ELIMINAR todo el código relacionado con ECDH que da una falsa sensación de seguridad.
- async function generateClientECDH() { ... }
- async function computeECDHSharedSecret(serverPublicKeyHex) { ... }

// El parche real requiere implementar "Double Ratchet" o "PreKeys" (Signal Protocol) 
// donde el Admin sube Ephemeral Public Keys al servidor, y el cliente deriva 
// la localKey usando una combinación del Token + la llave Efímera del Admin, 
// no usando RSA-OAEP para envolver un secreto estático.
```

JUSTIFICACIÓN DEL PARCHE: El código actual es "Seguridad por Oscuridad" y "Teatro de Seguridad". Generar un secreto ECDH y no usarlo, mientras la encriptación principal depende de un secreto transmitido vía RSA estático, es la antítesis del Forward Secrecy. La mitigación real requiere una reestructuración profunda de la arquitectura de llaves (X3DH).

---

### VULNERABILIDAD 2: Fuga de Material Criptográfico (Llave Privada de Atestación) y Ruptura de Zero Trust

DICTAMEN: CRÍTICO

VULNERABILIDAD DESCUBIERTA: Fuga intencionada de Llave Privada Simétrica. En la rutina de atestación (`src/ztap-worker.js`), el cliente deriva una llave HMAC estática (`attestHmacKey`), la marca explícitamente con `extractable=true` (bajo el falso comentario `AUDIT FIX 3`), y la exporta en texto plano en formato 'raw'. Luego, transmite esta llave simétrica privada por la red hacia el servidor en el paquete JSON `INIT` (`attestKey: secureBufferToBase64(rawAttestKey)`) para que el servidor "valide" los desafíos. Compartir la llave privada simétrica anula el modelo Challenge-Response. El servidor (o cualquier atacante MITM) obtiene el secreto y puede falsificar las atestaciones del cliente indefinidamente.

VECTOR DE EXPLOTACIÓN (PoC):
1. Un atacante se posiciona como MITM o compromete el nodo WebSocket del servidor.
2. Intercepta el paquete inicial no cifrado E2E: `{"type":"INIT", "user":"victima", "attestKey":"<LLAVE_EN_BASE64>"}`.
3. El atacante almacena la `attestKey`.
4. El servidor emite un desafío `ATTEST_CHALLENGE`.
5. El atacante, sin conocer el token real del usuario, firma el desafío utilizando la `attestKey` robada, suplantando perfectamente la identidad del cliente legítimo y burlando todos los controles anti-bot/atestación.

IMPACTO (CVSS Estimado): 8.5 (Alto). Compromiso total de la Autenticidad e Integridad de la identidad de la sesión.

EL PARCHE (Diff/Código):
```javascript
// Archivo: src/ztap-worker.js
// Reescritura para usar Criptografía Asimétrica (ECDSA) en lugar de HMAC simétrico.

// 1. Eliminar deriveAttestKey y reemplazar por generación de par ECDSA efímero
async function generateAttestKeyPair() {
    return await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, // Solo se exportará la PÚBLICA
        ['sign', 'verify']
    );
}

// 2. En onmessage 'INIT':
            localKey = await deriveKey(d.token, d.sessionId);
            
            // Generar par asimétrico
            const attestKeyPair = await generateAttestKeyPair();
            attestHmacKey = attestKeyPair.privateKey; // Usamos esto para mantener la compatibilidad de variable
            
            // Exportar ÚNICAMENTE la llave PÚBLICA
            const rawAttestPubKey = await crypto.subtle.exportKey('raw', attestKeyPair.publicKey);
            // ... [resto del código RSA] ...
            
            // Enviar solo la pública al servidor
            self.postMessage({ type: 'INITIALIZED', payload: secureBufferToBase64(encInit), attestKey: secureBufferToBase64(rawAttestPubKey) });

// 3. En onmessage 'ATTEST_CHALLENGE':
        if (d.type === 'ATTEST_CHALLENGE') {
            await initPromise;
            const challengeBuf = new TextEncoder().encode(d.challenge);
            
            // Firmar con ECDSA y la llave privada aislada
            const sig = await crypto.subtle.sign(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                attestHmacKey,
                challengeBuf
            );
            self.postMessage({ type: 'ATTEST_RESPONSE', signature: secureBufferToBase64(sig), challenge: d.challenge });
            return;
        }
```

JUSTIFICACIÓN DEL PARCHE: Transmitir una llave HMAC destruye la asimetría requerida para Zero Trust. Al migrar a `ECDSA`, el cliente genera un par de llaves en memoria, conserva celosamente la llave privada en el Worker, y solo transmite la llave pública al servidor. El servidor puede validar matemáticamente las firmas, pero es criptográficamente incapaz de falsificarlas.

---

### VULNERABILIDAD 3: Oráculo de Firma Ciega (Blind Signing Oracle) en Autenticación de Admin

DICTAMEN: CRÍTICO

VULNERABILIDAD DESCUBIERTA: El cliente administrador (`admin-client.js`) firma de forma ciega y automática cualquier carga útil recibida en el campo `nonce` del mensaje `AUTH_CHALLENGE` proveniente del servidor, utilizando la llave privada RSA a largo plazo (`masterSignKey`) bajo el esquema RSA-PSS. No existe ningún prefijo de contexto (domain separation) ni validación de la estructura del nonce antes de firmarlo.

VECTOR DE EXPLOTACIÓN (PoC):
1. Un atacante compromete el servidor o realiza un MITM contra la conexión del administrador.
2. El atacante envía un mensaje JSON malicioso al Admin: `{"type": "AUTH_CHALLENGE", "nonce": "<CARGA_ÚTIL_MALICIOSA>"}`.
3. El cliente del administrador ejecuta `crypto.subtle.sign` sobre la carga útil y devuelve la firma.
4. Si la `masterSignKey` se reutiliza en el ecosistema (por ejemplo, para firmar actualizaciones de software, binarios, o tokens en otros protocolos), el atacante acaba de utilizar al administrador como un oráculo de firma para falsificar firmas RSA válidas sobre datos arbitrarios.

IMPACTO (CVSS Estimado): 7.5 (Alto). Falsificación de firmas, compromiso cruzado de protocolos.

EL PARCHE (Diff/Código):
```javascript
// Archivo: src/admin-client.js
// 1. Modificar el bloque de firma de AUTH_CHALLENGE para incluir separación de dominio
            if (frame.type === 'AUTH_CHALLENGE') {
                // Forzar separación de dominio (Domain Separation)
                const contextPrefix = "ZTAP_ADMIN_AUTH_V3:";
                if (typeof frame.nonce !== 'string' || frame.nonce.length > 64) return;
                
                const dataToSign = new TextEncoder().encode(contextPrefix + frame.nonce);
                const sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, masterSignKey, dataToSign);
                sendStrictFrame({ type: 'ADMIN_AUTH', signature: bufferToBase64(sig) });
            }

// Archivo: src/server.js
// 2. Modificar la verificación en el servidor
            if (data.type === 'ADMIN_AUTH') {
                // ...
                const contextPrefix = "ZTAP_ADMIN_AUTH_V3:";
                try {
                    const isValid = crypto.verify('sha256', Buffer.from(contextPrefix + stored.nonce), {
                        key: pubKey,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: 32
                    }, Buffer.from(data.signature, 'base64'));
                // ...
```

JUSTIFICACIÓN DEL PARCHE: Al prefijar un string de contexto estricto (`ZTAP_ADMIN_AUTH_V3:`), nos aseguramos de que las firmas generadas por este flujo nunca puedan ser reutilizadas o interpretadas erróneamente en otros contextos del sistema que dependan de la misma llave asimétrica, previniendo ataques de tipo Cross-Protocol o Blind Signing Oracle.

---

### CONCLUSIÓN DEL RED TEAM
El protocolo ZTAP v3.1 exhibe deficiencias graves en la arquitectura de cifrado. La ilusión de Perfect Forward Secrecy combinada con la exfiltración silenciosa de llaves simétricas hacia componentes no confiables (Zero Trust) revela que la implementación actual depende de una confidencialidad engañosa. Se requiere la paralización de su uso hasta refactorizar la derivación de llaves para integrar entropía efímera de manera asimétrica.
