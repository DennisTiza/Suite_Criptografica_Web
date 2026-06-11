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

    // --- 0. Generación de claves ---
    const btnEncGen = document.getElementById('btn-enc-gen-keys');
    if (btnEncGen) {
        btnEncGen.addEventListener('click', async () => {
            const keySize = document.getElementById('enc-key-size').value;
            ui.setLoading('btn-enc-gen-keys', true);
            const res = await api.post('/api/encryption/generate-keys', { key_size: parseInt(keySize) });
            ui.setLoading('btn-enc-gen-keys', false);
            
            if (res.success) {
                updateEncKeyStatus();
                
                const privInput = document.getElementById('enc-gen-priv');
                if (privInput) privInput.value = res.data.private_key_pem;
                const pubInput = document.getElementById('enc-gen-pub');
                if (pubInput) pubInput.value = res.data.public_key_pem;
                
                ui.showAlert('enc-gen-alert', `Claves RSA (${res.data.key_size} bits) generadas correctamente.`, 'success');
            } else {
                ui.showAlert('enc-gen-alert', `Error: ${res.error}`, 'error');
            }
        });
    }

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
            const cipher = document.getElementById('enc-pub-cipher-input').value;

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


});
