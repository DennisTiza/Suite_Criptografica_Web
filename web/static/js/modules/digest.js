/**
 * Módulo 1a: Message Digest
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // --- 1. Generador Hash Básico ---
    const btnGenDigest = document.getElementById('btn-generate-digest');
    if (btnGenDigest) {
        btnGenDigest.addEventListener('click', async () => {
            const msg = document.getElementById('digest-input-msg').value;
            const algo = document.querySelector('input[name="digest_algo"]:checked').value;
            const out = document.getElementById('digest-output');
            
            if (!msg) {
                out.textContent = "El mensaje no puede estar vacío.";
                out.className = "output-area output-error";
                return;
            }
            
            ui.setLoading('btn-generate-digest', true);
            
            const res = await api.post('/api/digest/generate', { message: msg, algorithm: algo });
            
            ui.setLoading('btn-generate-digest', false);
            
            if (res.success) {
                const d = res.data;
                out.className = "output-area output-info";
                out.textContent = `Algoritmo: ${d.algorithm}\n` +
                                  `Tamaño: ${d.digest_size} bytes (${d.digest_size_bits} bits)\n` +
                                  `============================================================\n\n` +
                                  `${d.digest_hex}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }

    // --- 2. HMAC ---
    const btnGenHmac = document.getElementById('btn-generate-hmac');
    if (btnGenHmac) {
        btnGenHmac.addEventListener('click', async () => {
            const msg = document.getElementById('hmac-input-msg').value;
            const key = document.getElementById('hmac-key').value;
            const algo = document.querySelector('input[name="hmac_algo"]:checked').value;
            const out = document.getElementById('hmac-output');
            
            if (!msg || !key) {
                out.textContent = "El mensaje y la clave son obligatorios.";
                out.className = "output-area output-error";
                return;
            }
            
            ui.setLoading('btn-generate-hmac', true);
            const res = await api.post('/api/digest/hmac', { message: msg, key: key, algorithm: algo });
            ui.setLoading('btn-generate-hmac', false);
            
            if (res.success) {
                const d = res.data;
                out.className = "output-area";
                out.style.color = "#fbbf24";
                out.textContent = `${d.algorithm}\n` +
                                  `Tamaño: ${d.digest_size} bytes\n` +
                                  `============================================================\n\n` +
                                  `${d.hmac_hex}`;
            } else {
                out.className = "output-area output-error";
                out.textContent = `Error: ${res.error}`;
            }
        });
    }

    // --- 4. Comparación ---
    const btnCompare = document.getElementById('btn-compare');
    if (btnCompare) {
        btnCompare.addEventListener('click', async () => {
            const msg1 = document.getElementById('compare-msg1').value;
            const msg2 = document.getElementById('compare-msg2').value;
            const out = document.getElementById('compare-output');
            
            if (!msg1 || !msg2) return;
            
            ui.setLoading('btn-compare', true);
            const res = await api.post('/api/digest/compare', { message1: msg1, message2: msg2 });
            ui.setLoading('btn-compare', false);
            
            if (res.success) {
                const d = res.data;
                let text = `COMPARACIÓN DE MENSAJES\n============================================================\n\n`;
                
                ['md5', 'sha1', 'sha256', 'sha512'].forEach(algo => {
                    if (d[algo]) {
                        text += `${d[algo].algorithm}:\n`;
                        text += `  Msg 1: ${d[algo].hash1}\n`;
                        text += `  Msg 2: ${d[algo].hash2}\n`;
                        text += `  Match: ${d[algo].match ? '✓ SÍ' : '✗ NO'}\n\n`;
                    }
                });
                
                text += `============================================================\n`;
                text += `RESULTADO FINAL: ${d.messages_identical ? 'IDÉNTICOS ✓' : 'DIFERENTES ✗'}`;
                
                out.className = d.messages_identical ? "output-area output-info" : "output-area output-warning";
                out.textContent = text;
            } else {
                out.textContent = `Error: ${res.error}`;
                out.className = "output-area output-error";
            }
        });
    }
});
