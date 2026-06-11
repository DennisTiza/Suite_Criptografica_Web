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

    // --- 3. Efecto Avalancha ---
    const btnAvalanche = document.getElementById('btn-analyze-avalanche');
    if (btnAvalanche) {
        btnAvalanche.addEventListener('click', async () => {
            const msg = document.getElementById('avalanche-input').value;
            if (!msg) return;
            
            ui.setLoading('btn-analyze-avalanche', true);
            const res = await api.post('/api/digest/avalanche', { message: msg, algorithm: 'sha256' });
            ui.setLoading('btn-analyze-avalanche', false);
            
            if (res.success) {
                drawAvalancheCanvas(res.data);
            } else {
                alert(`Error: ${res.error}`);
            }
        });
    }
    
    function drawAvalancheCanvas(data) {
        const canvas = document.getElementById('avalanche-canvas');
        if (!canvas) return;
        
        // Ajustar tamaño
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width - 32; // padding
        canvas.height = 260;
        
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        const w = canvas.width;
        
        // Textos info
        ctx.font = 'bold 16px Inter';
        ctx.fillStyle = '#88ffbb';
        ctx.textAlign = 'center';
        ctx.fillText(`Bits cambiados: ${data.bits_changed}/${data.total_bits} (${data.percentage.toFixed(2)}%)`, w/2, 30);
        
        ctx.font = '12px Inter';
        ctx.fillStyle = '#fff';
        ctx.fillText(`Original: "${data.original_message}"  →  Modificado: "${data.modified_message}"`, w/2, 60);
        
        const barH = 40;
        const padding = 20;
        const barW = w - (padding * 2);
        
        // Original Hash Bar
        ctx.textAlign = 'left';
        ctx.fillText("Hash Original (SHA-256):", padding, 100);
        drawHashBar(ctx, data.original_hash, padding, 110, barW, barH, [0, 120, 212]); // Azul
        
        // Modified Hash Bar
        ctx.fillText("Hash Modificado:", padding, 180);
        drawHashBar(ctx, data.modified_hash, padding, 190, barW, barH, [255, 68, 68]); // Rojo
    }
    
    function drawHashBar(ctx, hashStr, x, y, width, height, baseColor) {
        const segW = width / hashStr.length;
        
        for (let i = 0; i < hashStr.length; i++) {
            // Intensidad basada en valor hex (0-F)
            const val = parseInt(hashStr[i], 16);
            const intensity = val / 15.0;
            
            // Variar ligeramente el color base
            const r = Math.floor(baseColor[0] * intensity + 40);
            const g = Math.floor(baseColor[1] * intensity + 40);
            const b = Math.floor(baseColor[2] * intensity + 40);
            
            ctx.fillStyle = `rgb(${r},${g},${b})`;
            ctx.fillRect(x + (i * segW), y, segW + 0.5, height); // +0.5 to fix gaps
        }
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
