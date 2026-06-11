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
                const txtPriv = document.getElementById('sig-keys-priv');
                const txtPub = document.getElementById('sig-keys-pub');
                if (txtPriv) txtPriv.value = res.data.private_key_pem;
                if (txtPub) txtPub.value = res.data.public_key_pem;
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
                const txtCert = document.getElementById('sig-cert-pem');
                if (txtCert) txtCert.value = res.data.certificate_pem;
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


});
