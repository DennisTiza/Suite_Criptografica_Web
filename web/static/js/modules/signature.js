/**
 * Módulo 1b: Firma Digital (RSA)
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // Actualizar estado de las claves en la UI
    async function updateKeyStatus() {
        const res = await api.get('/api/signature/key-status');
        if (res) {
            const dotPriv = document.getElementById('sig-dot-priv');
            const dotPub = document.getElementById('sig-dot-pub');
            const dotCert = document.getElementById('sig-dot-cert');
            
            if (dotPriv) {
                dotPriv.className = res.has_private_key ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('sig-lbl-priv').textContent = res.has_private_key ? 'Clave Privada: OK' : 'Clave Privada: No';
            }
            if (dotPub) {
                dotPub.className = res.has_public_key ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('sig-lbl-pub').textContent = res.has_public_key ? 'Clave Pública: OK' : 'Clave Pública: No';
            }
            if (dotCert) {
                dotCert.className = res.has_certificate ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('sig-lbl-cert').textContent = res.has_certificate ? 'Certificado: OK' : 'Certificado: No';
            }
        }
    }
    
    // Llamar inicial al cargar
    updateKeyStatus();
    
    // --- 1. Generar Claves ---
    const btnGenKeys = document.getElementById('btn-sig-gen-keys');
    if (btnGenKeys) {
        btnGenKeys.addEventListener('click', async () => {
            const size = document.querySelector('input[name="sig_key_size"]:checked').value;
            
            ui.setLoading('btn-sig-gen-keys', true);
            const res = await api.post('/api/signature/generate-keys', { key_size: parseInt(size) });
            ui.setLoading('btn-sig-gen-keys', false);
            
            if (res.success) {
                ui.showAlert('sig-keys-alert', `Par de claves RSA de ${size} bits generado exitosamente.`, 'success');
                updateKeyStatus();
            } else {
                ui.showAlert('sig-keys-alert', `Error: ${res.error}`, 'error');
            }
        });
    }

    // --- 2. Generar Certificado ---
    const btnGenCert = document.getElementById('btn-sig-gen-cert');
    if (btnGenCert) {
        btnGenCert.addEventListener('click', async () => {
            const data = {
                common_name: document.getElementById('cert-cn').value,
                organization: document.getElementById('cert-o').value,
                country: document.getElementById('cert-c').value,
                validity_days: parseInt(document.getElementById('cert-days').value)
            };
            
            if (!data.common_name) {
                ui.showAlert('sig-keys-alert', 'El Common Name (CN) es obligatorio.', 'warning');
                return;
            }
            
            ui.setLoading('btn-sig-gen-cert', true);
            const res = await api.post('/api/signature/generate-cert', data);
            ui.setLoading('btn-sig-gen-cert', false);
            
            if (res.success) {
                ui.showAlert('sig-keys-alert', `Certificado auto-firmado generado. (Serial: ${res.data.serial_number})`, 'success');
                updateKeyStatus();
            } else {
                ui.showAlert('sig-keys-alert', `Error: ${res.error} (¿Olvidaste generar claves primero?)`, 'error');
            }
        });
    }

    // --- 3. Firmar Mensaje ---
    const btnSign = document.getElementById('btn-sig-sign');
    if (btnSign) {
        btnSign.addEventListener('click', async () => {
            const msg = document.getElementById('sig-sign-msg').value;
            const algo = document.querySelector('input[name="sig_hash_algo"]:checked').value;
            const out = document.getElementById('sig-sign-out');
            
            if (!msg) return;
            
            ui.setLoading('btn-sig-sign', true);
            const res = await api.post('/api/signature/sign', { message: msg, hash_algorithm: algo });
            ui.setLoading('btn-sig-sign', false);
            
            if (res.success) {
                out.value = res.data.signature_base64;
                // Auto-fill verifier to make testing easy
                const verifyMsg = document.getElementById('sig-verify-msg');
                const verifySig = document.getElementById('sig-verify-sig');
                if (verifyMsg) verifyMsg.value = msg;
                if (verifySig) verifySig.value = res.data.signature_base64;
            } else {
                out.value = `Error: ${res.error}\n\nNota: Debes generar claves primero en la pestaña "Claves y Certificado"`;
            }
        });
    }

    // --- 4. Verificar Firma ---
    const btnVerify = document.getElementById('btn-sig-verify');
    if (btnVerify) {
        btnVerify.addEventListener('click', async () => {
            const msg = document.getElementById('sig-verify-msg').value;
            const sig = document.getElementById('sig-verify-sig').value;
            
            if (!msg || !sig) {
                ui.showAlert('sig-verify-alert', 'El mensaje y la firma son requeridos.', 'warning');
                return;
            }
            
            ui.setLoading('btn-sig-verify', true);
            const res = await api.post('/api/signature/verify', { message: msg, signature_base64: sig });
            ui.setLoading('btn-sig-verify', false);
            
            if (res.success && res.data.valid) {
                ui.showAlert('sig-verify-alert', `✅ FIRMA VÁLIDA. El mensaje es auténtico. (Hash usado: ${res.data.hash_algorithm_used})`, 'success');
            } else if (res.success && !res.data.valid) {
                ui.showAlert('sig-verify-alert', `❌ FIRMA INVÁLIDA. El mensaje fue alterado o la firma no corresponde.`, 'error');
            } else {
                ui.showAlert('sig-verify-alert', `Error del servidor: ${res.error}`, 'warning');
            }
        });
    }

    // --- 5. Textbook RSA (Educativo) ---
    const btnTbSign = document.getElementById('btn-sig-tb-sign');
    const btnTbVerify = document.getElementById('btn-sig-tb-verify');
    
    if (btnTbSign) {
        btnTbSign.addEventListener('click', async () => {
            const msg = document.getElementById('sig-tb-msg').value;
            const hash = document.getElementById('sig-tb-hash').value;
            const out = document.getElementById('sig-tb-out');
            
            if (!msg) return;
            
            ui.setLoading('btn-sig-tb-sign', true);
            const res = await api.post('/api/signature/sign-textbook', { message: msg, hash_algorithm: hash });
            ui.setLoading('btn-sig-tb-sign', false);
            
            if (res.success) {
                const d = res.data;
                // Guarda la firma en un dataset para verificación fácil
                document.getElementById('sig-tb-msg').dataset.lastSig = d.signature_base64;
                
                out.className = "output-area";
                out.innerHTML = `<span style="color:#ff8888">=== OPERACIÓN DE FIRMA ===</span>\n` +
                                `M = Mensaje original\n` +
                                `H = Hash(${d.hash_algorithm}, M)\n` +
                                `  = <span style="color:#88bbff">${d.hash_int}</span>\n\n` +
                                `Clave Privada (d, n)\n` +
                                `Firma S = H^d mod n\n` +
                                `  = <span style="color:#88ffbb">${d.signature_int}</span>\n\n` +
                                `Firma Base64: ${d.signature_base64}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }
    
    if (btnTbVerify) {
        btnTbVerify.addEventListener('click', async () => {
            const msg = document.getElementById('sig-tb-msg').value;
            const sigInput = document.getElementById('sig-tb-msg');
            const sig = sigInput.dataset.lastSig; // Obtiene la última firma generada
            const hash = document.getElementById('sig-tb-hash').value;
            const out = document.getElementById('sig-tb-out');
            
            if (!sig) {
                out.className = "output-area output-warning";
                out.textContent = "Debes firmar un mensaje primero.";
                return;
            }
            
            ui.setLoading('btn-sig-tb-verify', true);
            const res = await api.post('/api/signature/verify-textbook', { message: msg, signature_base64: sig, hash_algorithm: hash });
            ui.setLoading('btn-sig-tb-verify', false);
            
            if (res.success) {
                const d = res.data;
                const statusColor = d.valid ? '#88ffbb' : '#ff8888';
                
                out.className = "output-area";
                out.innerHTML = `<span style="color:#88bbff">=== OPERACIÓN DE VERIFICACIÓN ===</span>\n` +
                                `Clave Pública (e, n)\n\n` +
                                `Paso 1: Calcular Hash del mensaje proveído\n` +
                                `H_orig = Hash(${d.hash_algorithm}, M)\n` +
                                `       = <span style="color:#ccc">${d.hash_original}</span>\n\n` +
                                `Paso 2: Recuperar Hash desde la Firma\n` +
                                `H_recup = S^e mod n\n` +
                                `        = <span style="color:${statusColor}">${d.hash_from_signature}</span>\n\n` +
                                `Paso 3: Comparar H_orig == H_recup\n` +
                                `<span style="color:${statusColor}; font-size:1.1em; font-weight:bold">${d.message}</span>`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }
});
