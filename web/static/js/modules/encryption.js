/**
 * Módulo 1c, 1d: Cifrado RSA y Simétrico
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // --- Actualizar Estado de Claves (Sincronizado o Independiente) ---
    async function updateEncKeyStatus() {
        const res = await api.get('/api/encryption/key-status');
        if (res) {
            const dotPriv = document.getElementById('enc-dot-priv');
            const dotPub = document.getElementById('enc-dot-pub');
            
            if (dotPriv) {
                dotPriv.className = res.has_private_key ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('enc-lbl-priv').textContent = res.has_private_key ? 'Clave Privada: OK' : 'Clave Privada: No';
            }
            if (dotPub) {
                dotPub.className = res.has_public_key ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('enc-lbl-pub').textContent = res.has_public_key ? 'Clave Pública: OK' : 'Clave Pública: No';
            }
        }
    }
    
    // Para simplificar la demo, podemos tener un botón que genera claves directamente en este módulo
    const btnSyncKeys = document.getElementById('btn-enc-sync-keys');
    if (btnSyncKeys) {
        btnSyncKeys.addEventListener('click', async () => {
            ui.setLoading('btn-enc-sync-keys', true);
            // Genera claves nuevas directamente para el módulo de cifrado
            await api.post('/api/encryption/generate-keys', { key_size: 2048 });
            await updateEncKeyStatus();
            ui.setLoading('btn-enc-sync-keys', false);
        });
    }
    
    // Cargar estado inicial
    updateEncKeyStatus();

    // --- 1. RSA Cifrado Público (1d) ---
    const btnEncPub = document.getElementById('btn-enc-pub-enc');
    const btnDecPriv = document.getElementById('btn-enc-pub-dec');
    
    if (btnEncPub) {
        btnEncPub.addEventListener('click', async () => {
            const msg = document.getElementById('enc-pub-msg').value;
            const out = document.getElementById('enc-pub-cipher');
            
            if (!msg) return;
            
            ui.setLoading('btn-enc-pub-enc', true);
            const res = await api.post('/api/encryption/encrypt-public', { message: msg });
            ui.setLoading('btn-enc-pub-enc', false);
            
            if (res.success) {
                out.value = res.data.ciphertext_base64;
                ui.showAlert('enc-pub-alert', `Mensaje cifrado con éxito (${res.data.method})`, 'success');
            } else {
                ui.showAlert('enc-pub-alert', `Error: ${res.error}`, 'error');
            }
        });
    }
    
    if (btnDecPriv) {
        btnDecPriv.addEventListener('click', async () => {
            const cipher = document.getElementById('enc-pub-cipher').value;
            
            if (!cipher) {
                ui.showAlert('enc-pub-alert', 'No hay texto cifrado para descifrar', 'warning');
                return;
            }
            
            ui.setLoading('btn-enc-pub-dec', true);
            const res = await api.post('/api/encryption/decrypt-private', { ciphertext_base64: cipher });
            ui.setLoading('btn-enc-pub-dec', false);
            
            if (res.success) {
                ui.showAlert('enc-pub-alert', `DESCIFRADO EXITOSO: ${res.data.plaintext}`, 'info');
            } else {
                ui.showAlert('enc-pub-alert', `Error: ${res.error}`, 'error');
            }
        });
    }

    // --- 2. RSA Cifrado Privado (1c) ---
    const btnEncPriv = document.getElementById('btn-enc-priv-enc');
    const btnDecPub = document.getElementById('btn-enc-priv-dec');
    
    if (btnEncPriv) {
        btnEncPriv.addEventListener('click', async () => {
            const msg = document.getElementById('enc-priv-msg').value;
            const out = document.getElementById('enc-priv-cipher');
            
            if (!msg) return;
            
            ui.setLoading('btn-enc-priv-enc', true);
            const res = await api.post('/api/encryption/encrypt-private', { message: msg, hash_algorithm: 'SHA256' });
            ui.setLoading('btn-enc-priv-enc', false);
            
            if (res.success) {
                out.value = res.data.ciphertext_base64;
                ui.showAlert('enc-priv-alert', `Mensaje "cifrado" (Firmado) con éxito (${res.data.method})`, 'success');
            } else {
                ui.showAlert('enc-priv-alert', `Error: ${res.error}`, 'error');
            }
        });
    }
    
    if (btnDecPub) {
        btnDecPub.addEventListener('click', async () => {
            const msg = document.getElementById('enc-priv-msg').value;
            const cipher = document.getElementById('enc-priv-cipher').value;
            
            if (!cipher) {
                ui.showAlert('enc-priv-alert', 'No hay texto cifrado para procesar', 'warning');
                return;
            }
            
            ui.setLoading('btn-enc-priv-dec', true);
            // La verificación necesita el mensaje original para RSA PKCS1v15
            const res = await api.post('/api/encryption/decrypt-public', { 
                ciphertext_base64: cipher, 
                original_message: msg,
                hash_algorithm: 'SHA256'
            });
            ui.setLoading('btn-enc-priv-dec', false);
            
            if (res.success && res.data.valid) {
                ui.showAlert('enc-priv-alert', `VERIFICACIÓN/DESCIFRADO EXITOSO. El mensaje original es: ${res.data.plaintext}`, 'info');
            } else if (res.success && !res.data.valid) {
                ui.showAlert('enc-priv-alert', `FALLO AL VERIFICAR: ${res.data.message}`, 'error');
            } else {
                ui.showAlert('enc-priv-alert', `Error: ${res.error}`, 'error');
            }
        });
    }

    // --- 3. Cifrado Simétrico ---
    const btnSymEnc = document.getElementById('btn-sym-enc');
    const btnSymDec = document.getElementById('btn-sym-dec');
    
    if (btnSymEnc) {
        btnSymEnc.addEventListener('click', async () => {
            const algo = document.getElementById('sym-algo').value;
            const msg = document.getElementById('sym-msg').value;
            const key = document.getElementById('sym-key').value;
            const out = document.getElementById('sym-out');
            const ivInput = document.getElementById('sym-iv');
            
            if (!msg || !key) return;
            
            const endpoint = `/api/encryption/${algo}-encrypt`;
            
            ui.setLoading('btn-sym-enc', true);
            const res = await api.post(endpoint, { plaintext: msg, key: key });
            ui.setLoading('btn-sym-enc', false);
            
            if (res.success) {
                const d = res.data;
                // Save IV if needed
                if (d.iv_base64) {
                    ivInput.value = d.iv_base64;
                }
                
                // Store cipher in dataset for decryption
                out.dataset.cipher = d.ciphertext_base64;
                
                let text = `Algoritmo: ${d.method}\n`;
                if (d.warning) text += `${d.warning}\n`;
                if (d.iv_hex) text += `IV (Hex): ${d.iv_hex}\n`;
                text += `=========================================\n\n`;
                text += `Cifrado (Base64):\n${d.ciphertext_base64}`;
                
                out.className = d.warning ? "output-area output-warning" : "output-area";
                out.style.color = d.warning ? "" : "#fbbf24";
                out.textContent = text;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}\nRevisa la longitud de la clave para este algoritmo.`;
            }
        });
    }
    
    if (btnSymDec) {
        btnSymDec.addEventListener('click', async () => {
            const algo = document.getElementById('sym-algo').value;
            const key = document.getElementById('sym-key').value;
            const out = document.getElementById('sym-out');
            const iv = document.getElementById('sym-iv').value;
            const cipher = out.dataset.cipher;
            
            if (!cipher) {
                out.textContent = "Primero debes cifrar un mensaje.";
                out.className = "output-area output-warning";
                return;
            }
            
            const endpoint = `/api/encryption/${algo}-decrypt`;
            
            ui.setLoading('btn-sym-dec', true);
            const res = await api.post(endpoint, { 
                ciphertext_base64: cipher, 
                key: key,
                iv_base64: iv 
            });
            ui.setLoading('btn-sym-dec', false);
            
            if (res.success) {
                out.className = "output-area output-info";
                out.textContent = `=== DESCIFRADO EXITOSO ===\n\n${res.data.plaintext}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error al descifrar: ${res.error}\nProbablemente la clave es incorrecta o el IV se perdió.`;
            }
        });
    }

    // --- 4. Híbrido ---
    const btnHybEnc = document.getElementById('btn-hyb-enc');
    const btnHybDec = document.getElementById('btn-hyb-dec');
    
    if (btnHybEnc) {
        btnHybEnc.addEventListener('click', async () => {
            const msg = document.getElementById('hyb-msg').value;
            const out = document.getElementById('hyb-out');
            
            if (!msg) return;
            
            ui.setLoading('btn-hyb-enc', true);
            const res = await api.post('/api/encryption/hybrid-encrypt', { plaintext: msg });
            ui.setLoading('btn-hyb-enc', false);
            
            if (res.success) {
                const d = res.data;
                
                // Store in hidden fields
                document.getElementById('hyb-sess-key').value = d.encrypted_session_key_b64;
                document.getElementById('hyb-cipher').value = d.ciphertext_b64;
                document.getElementById('hyb-nonce').value = d.nonce_b64;
                document.getElementById('hyb-tag').value = d.tag_b64;
                
                out.className = "output-area";
                out.style.color = "#a8ff78";
                out.textContent = `1. Clave de sesión AES generada aleatoriamente.\n` +
                                  `2. Mensaje cifrado con AES-GCM (Cipher + Tag).\n` +
                                  `3. Clave AES cifrada con RSA Pública.\n\n` +
                                  `--- DATOS DEL SOBRE ---\n` +
                                  `Clave AES Cifrada (RSA):\n${d.encrypted_session_key_b64.substring(0,60)}...\n\n` +
                                  `Mensaje Cifrado (AES):\n${d.ciphertext_b64.substring(0,60)}...\n\n` +
                                  `Nonce: ${d.nonce_b64}\nTag: ${d.tag_b64}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}\n\nNota: Debes tener o generar claves RSA primero (usa el botón 'Sincronizar claves').`;
            }
        });
    }
    
    if (btnHybDec) {
        btnHybDec.addEventListener('click', async () => {
            const out = document.getElementById('hyb-out');
            
            const sessKey = document.getElementById('hyb-sess-key').value;
            const cipher = document.getElementById('hyb-cipher').value;
            const nonce = document.getElementById('hyb-nonce').value;
            const tag = document.getElementById('hyb-tag').value;
            
            if (!cipher) {
                out.textContent = "No hay sobre digital para abrir.";
                out.className = "output-area output-warning";
                return;
            }
            
            ui.setLoading('btn-hyb-dec', true);
            const res = await api.post('/api/encryption/hybrid-decrypt', {
                encrypted_session_key_b64: sessKey,
                ciphertext_b64: cipher,
                nonce_b64: nonce,
                tag_b64: tag
            });
            ui.setLoading('btn-hyb-dec', false);
            
            if (res.success) {
                out.className = "output-area output-info";
                out.textContent = `=== SOBRE ABIERTO EXITOSAMENTE ===\n\n` +
                                  `1. Clave RSA Privada descifró la clave AES.\n` +
                                  `2. Clave AES descifró y autenticó el mensaje original.\n\n` +
                                  `CONTENIDO:\n${res.data.plaintext}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }
});
