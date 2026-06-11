/**
 * Suite Criptográfica - Módulo de SQL Injection
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnVulnLogin = document.getElementById('btn-sqli-vuln-login');
    const inputVulnUser = document.getElementById('sqli-vuln-user');
    const inputVulnPass = document.getElementById('sqli-vuln-pass');
    const outVuln = document.getElementById('sqli-vuln-out');

    const btnSecureLogin = document.getElementById('btn-sqli-secure-login');
    const inputSecureUser = document.getElementById('sqli-secure-user');
    const inputSecurePass = document.getElementById('sqli-secure-pass');
    const outSecure = document.getElementById('sqli-secure-out');

    const btnRefreshMonitor = document.getElementById('btn-sqli-refresh-monitor');
    const tableMonitor = document.getElementById('sqli-monitor-table');

    // --- Tab 1: Login Vulnerable ---
    if (btnVulnLogin) {
        btnVulnLogin.addEventListener('click', async () => {
            const username = inputVulnUser.value;
            const password = inputVulnPass.value;

            if (!username) {
                outVuln.innerHTML = '<span style="color:var(--accent-red)">El usuario es requerido.</span>';
                return;
            }

            ui.setLoading('btn-sqli-vuln-login', true);
            outVuln.textContent = "Ejecutando...";

            const res = await api.post('/api/sqli/login-vulnerable', { username, password });

            ui.setLoading('btn-sqli-vuln-login', false);

            if (res && res.success) {
                let html = `<div style="color: var(--accent-green); font-weight: bold;">${res.message}</div>`;
                html += `<div style="margin-top: 10px; font-size: 0.85rem; color: var(--text-3);">Query Ejecutado:</div>`;
                html += `<div style="font-family: monospace; background: rgba(255,255,255,0.05); padding: 5px;">${res.query}</div>`;
                if (res.users) {
                    html += `<pre style="margin-top: 10px; font-size: 0.8rem;">${JSON.stringify(res.users, null, 2)}</pre>`;
                }
                outVuln.innerHTML = html;
            } else {
                let html = `<div style="color: var(--accent-red);">${res?.error || res?.message || 'Error'}</div>`;
                if (res?.query) {
                    html += `<div style="margin-top: 10px; font-size: 0.85rem; color: var(--text-3);">Query Ejecutado:</div>`;
                    html += `<div style="font-family: monospace; background: rgba(255,255,255,0.05); padding: 5px;">${res.query}</div>`;
                }
                outVuln.innerHTML = html;
            }
        });
    }

    // --- Tab 3: Login Seguro ---
    if (btnSecureLogin) {
        btnSecureLogin.addEventListener('click', async () => {
            const username = inputSecureUser.value;
            const password = inputSecurePass.value;

            if (!username) {
                outSecure.innerHTML = '<span style="color:var(--accent-red)">El usuario es requerido.</span>';
                return;
            }

            ui.setLoading('btn-sqli-secure-login', true);
            outSecure.textContent = "Validando y ejecutando...";

            const res = await api.post('/api/sqli/login-secure', { username, password });

            ui.setLoading('btn-sqli-secure-login', false);

            if (res && res.success) {
                outSecure.innerHTML = `<span style="color: var(--accent-green)">${res.message}</span>`;
            } else {
                outSecure.innerHTML = `<span style="color: var(--accent-red)">${res?.error || res?.message || 'Error'}</span>`;
            }
        });
    }

    // --- Tab 4: Monitor ---
    async function loadMonitorLogs() {
        if (!tableMonitor) return;

        tableMonitor.innerHTML = '<tr><td colspan="4" style="padding: 10px; text-align: center;">Cargando logs...</td></tr>';

        const res = await api.get('/api/sqli/monitor');

        if (res && res.success && res.data) {
            if (res.data.length === 0) {
                tableMonitor.innerHTML = '<tr><td colspan="5" style="padding: 10px; text-align: center;">No hay registros de ataque aún.</td></tr>';
                return;
            }

            let html = '';
            res.data.forEach(log => {
                let typeColor = 'var(--text-2)';
                let accessStatus = '';
                let accessColor = '';

                if (log.attack_type === 'SQLi Vulnerable Bypass (Exitoso)') {
                    typeColor = 'var(--accent-red)';
                    accessStatus = 'ACCESO VULNERADO';
                    accessColor = 'var(--accent-red)';
                } else if (log.attack_type === 'SQLi Attempt Blocked (Patrón Detectado)') {
                    typeColor = 'var(--accent-green)';
                    accessStatus = 'BLOQUEADO';
                    accessColor = 'var(--accent-green)';
                } else if (log.attack_type === 'Login Normal' || log.attack_type === 'Login Seguro Exitoso') {
                    typeColor = 'var(--accent-cyan)';
                    accessStatus = 'ACCESO CONCEDIDO';
                    accessColor = 'var(--accent-cyan)';
                } else if (log.attack_type === 'SQLi Syntax Error') {
                    typeColor = '#f39c12';
                    accessStatus = 'ERROR DE SINTAXIS';
                    accessColor = '#f39c12';
                } else {
                    typeColor = 'var(--text-3)';
                    accessStatus = 'DENEGADO / FALLIDO';
                    accessColor = 'var(--text-3)';
                }

                html += `
                    <tr style="border-bottom: 1px solid var(--bg-3);">
                        <td style="padding: 10px;">${log.attack_time}</td>
                        <td style="padding: 10px;">${log.ip_address}</td>
                        <td style="padding: 10px; color: ${typeColor}; font-weight: bold;">${log.attack_type}</td>
                        <td style="padding: 10px; color: ${accessColor}; font-weight: bold;">${accessStatus}</td>
                        <td style="padding: 10px; font-family: monospace; font-size: 0.8rem; word-break: break-all;">${log.query_executed}</td>
                    </tr>
                `;
            });
            tableMonitor.innerHTML = html;
        } else {
            tableMonitor.innerHTML = `<tr><td colspan="5" style="padding: 10px; text-align: center; color: var(--accent-red);">Error al cargar: ${res?.error || 'Desconocido'}</td></tr>`;
        }
    }

    if (btnRefreshMonitor) {
        btnRefreshMonitor.addEventListener('click', loadMonitorLogs);
    }

    // Cargar monitor cuando se hace clic en su pestaña
    const monitorTabBtn = document.querySelector('button[data-tab="sqli-monitor"]');
    if (monitorTabBtn) {
        monitorTabBtn.addEventListener('click', loadMonitorLogs);
    }
});
