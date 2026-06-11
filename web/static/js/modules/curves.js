/**
 * Módulo 1e: Curvas Elípticas (ECDSA y Ed25519)
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // Actualizar Estado de Claves
    async function updateEccKeyStatus() {
        const res = await api.get('/api/curves/key-status');
        if (res) {
            const dotEcdsa = document.getElementById('ecc-dot-ecdsa');
            const dotEd = document.getElementById('ecc-dot-ed25519');
            
            if (dotEcdsa) {
                const active = res.ecdsa.has_private_key && res.ecdsa.has_public_key;
                dotEcdsa.className = active ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('ecc-lbl-ecdsa').textContent = active ? `ECDSA (${res.ecdsa.current_curve})` : 'ECDSA: No';
            }
            if (dotEd) {
                const active = res.ed25519.has_private_key && res.ed25519.has_public_key;
                dotEd.className = active ? 'key-dot active' : 'key-dot inactive';
                document.getElementById('ecc-lbl-ed25519').textContent = active ? 'Ed25519: OK' : 'Ed25519: No';
            }
        }
    }
    
    // Cargar inicial
    updateEccKeyStatus();

    // --- 1. ECDSA ---
    const btnEcdsaGen = document.getElementById('btn-ecdsa-gen');
    const btnEcdsaSign = document.getElementById('btn-ecdsa-sign');
    const btnEcdsaVerify = document.getElementById('btn-ecdsa-verify');
    
    if (btnEcdsaGen) {
        btnEcdsaGen.addEventListener('click', async () => {
            const curve = document.getElementById('ecdsa-curve').value;
            const out = document.getElementById('ecdsa-out');
            
            ui.setLoading('btn-ecdsa-gen', true);
            const res = await api.post('/api/curves/generate-ecdsa', { curve: curve });
            ui.setLoading('btn-ecdsa-gen', false);
            
            if (res.success) {
                updateEccKeyStatus();
                out.className = "output-area";
                out.textContent = `✅ Claves ECDSA generadas en la curva: ${res.data.curve}\n` +
                                  `Tamaño: ${res.data.key_size} bits\n\n` +
                                  `La criptografía de curva elíptica ofrece la misma seguridad que RSA pero con claves mucho más pequeñas.`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }
    
    if (btnEcdsaSign) {
        btnEcdsaSign.addEventListener('click', async () => {
            const msg = document.getElementById('ecdsa-msg').value;
            const hash = document.querySelector('input[name="ecdsa_hash"]:checked').value;
            const out = document.getElementById('ecdsa-out');
            
            if (!msg) return;
            
            ui.setLoading('btn-ecdsa-sign', true);
            const res = await api.post('/api/curves/sign-ecdsa', { message: msg, hash_algorithm: hash });
            ui.setLoading('btn-ecdsa-sign', false);
            
            if (res.success) {
                const d = res.data;
                document.getElementById('ecdsa-sig-b64').value = d.signature_base64;
                
                out.className = "output-area";
                out.style.color = "var(--accent-cyan)";
                out.textContent = `Firma ECDSA (${d.curve} + ${d.hash_algorithm})\n` +
                                  `=========================================\n\n` +
                                  `${d.signature_base64}\n\n` +
                                  `(Representación Hexadecimal):\n${d.signature_hex.substring(0,64)}...`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}\nGenera claves primero.`;
            }
        });
    }
    
    if (btnEcdsaVerify) {
        btnEcdsaVerify.addEventListener('click', async () => {
            const msg = document.getElementById('ecdsa-msg').value;
            const hash = document.querySelector('input[name="ecdsa_hash"]:checked').value;
            const sig = document.getElementById('ecdsa-sig-b64').value;
            const out = document.getElementById('ecdsa-out');
            
            if (!sig) {
                out.textContent = "Firma primero el mensaje.";
                return;
            }
            
            ui.setLoading('btn-ecdsa-verify', true);
            const res = await api.post('/api/curves/verify-ecdsa', { 
                message: msg, 
                signature_base64: sig,
                hash_algorithm: hash
            });
            ui.setLoading('btn-ecdsa-verify', false);
            
            if (res.success) {
                out.className = res.data.valid ? "output-area output-info" : "output-area output-error";
                out.textContent = res.data.message;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error del servidor: ${res.error}`;
            }
        });
    }

    // --- 2. Ed25519 ---
    const btnEdGen = document.getElementById('btn-ed-gen');
    const btnEdSign = document.getElementById('btn-ed-sign');
    const btnEdVerify = document.getElementById('btn-ed-verify');
    
    if (btnEdGen) {
        btnEdGen.addEventListener('click', async () => {
            const out = document.getElementById('ed-out');
            
            ui.setLoading('btn-ed-gen', true);
            const res = await api.post('/api/curves/generate-ed25519', {});
            ui.setLoading('btn-ed-gen', false);
            
            if (res.success) {
                updateEccKeyStatus();
                out.className = "output-area";
                out.textContent = `✅ Claves Ed25519 generadas instantáneamente.\n\n` +
                                  `Clave Pública (Hex - 32 bytes):\n${res.data.public_key_hex}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }
    
    if (btnEdSign) {
        btnEdSign.addEventListener('click', async () => {
            const msg = document.getElementById('ed-msg').value;
            const out = document.getElementById('ed-out');
            
            if (!msg) return;
            
            ui.setLoading('btn-ed-sign', true);
            const t0 = performance.now();
            const res = await api.post('/api/curves/sign-ed25519', { message: msg });
            const t1 = performance.now();
            ui.setLoading('btn-ed-sign', false);
            
            if (res.success) {
                document.getElementById('ed-sig-hex').value = res.data.signature_hex;
                
                out.className = "output-area";
                out.style.color = "var(--accent-purple)";
                out.textContent = `Firma Ed25519 (Hexadecimal):\n` +
                                  `=========================================\n` +
                                  `${res.data.signature_hex}\n\n` +
                                  `Tiempo de respuesta (red incluida): ${(t1-t0).toFixed(2)}ms`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}\nGenera claves primero.`;
            }
        });
    }
    
    if (btnEdVerify) {
        btnEdVerify.addEventListener('click', async () => {
            const msg = document.getElementById('ed-msg').value;
            const sig = document.getElementById('ed-sig-hex').value;
            const out = document.getElementById('ed-out');
            
            if (!sig) {
                out.textContent = "Firma primero el mensaje.";
                return;
            }
            
            ui.setLoading('btn-ed-verify', true);
            const t0 = performance.now();
            const res = await api.post('/api/curves/verify-ed25519', { 
                message: msg, 
                signature_hex: sig 
            });
            const t1 = performance.now();
            ui.setLoading('btn-ed-verify', false);
            
            if (res.success) {
                out.className = res.data.valid ? "output-area output-info" : "output-area output-error";
                out.style.color = res.data.valid ? "var(--accent-purple)" : "var(--accent-red)";
                out.textContent = `${res.data.message}\nTiempo de verificación (red incl.): ${(t1-t0).toFixed(2)}ms`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error del servidor: ${res.error}`;
            }
        });
    }
});
