/**
 * Suite Criptográfica - App Principal
 * Lógica de navegación SPA y utilidades generales
 */

// Utilidad para peticiones HTTP
const api = {
    async post(endpoint, data) {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            return await response.json();
        } catch (error) {
            console.error(`Error en ${endpoint}:`, error);
            return { success: false, error: 'Error de conexión con el servidor.' };
        }
    },
    
    async get(endpoint) {
        try {
            const response = await fetch(endpoint);
            return await response.json();
        } catch (error) {
            console.error(`Error en ${endpoint}:`, error);
            return null;
        }
    }
};

// Utilidades UI
const ui = {
    formatOutput(obj) {
        if (typeof obj === 'string') return obj;
        return JSON.stringify(obj, null, 2);
    },
    
    setLoading(btnId, isLoading) {
        const btn = document.getElementById(btnId);
        if (!btn) return;
        
        if (isLoading) {
            btn.classList.add('loading');
            if (!btn.dataset.originalText) {
                btn.dataset.originalText = btn.innerHTML;
            }
            btn.innerHTML = '<div class="spinner"></div>';
        } else {
            btn.classList.remove('loading');
            if (btn.dataset.originalText) {
                btn.innerHTML = btn.dataset.originalText;
            }
        }
    },
    
    showAlert(containerId, message, type = 'info') {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
        
        // Auto hide after 5 seconds
        setTimeout(() => {
            if (container.innerHTML.includes(message)) {
                container.innerHTML = '';
            }
        }, 5000);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // --- Navegación SPA (Sidebar y Cards del Home) ---
    const navItems = document.querySelectorAll('.nav-item[data-target], .module-card[data-target]');
    const sections = document.querySelectorAll('.section');
    
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetId = item.dataset.target;
            
            // Ocultar todas las secciones
            sections.forEach(sec => sec.classList.remove('active'));
            
            // Mostrar sección objetivo
            const targetSec = document.getElementById(targetId);
            if (targetSec) targetSec.classList.add('active');
            
            // Actualizar active state en sidebar
            document.querySelectorAll('.sidebar .nav-item').forEach(nav => {
                nav.classList.remove('active');
                if (nav.dataset.target === targetId) {
                    nav.classList.add('active');
                }
            });
            
            // Scroll to top
            window.scrollTo(0, 0);
        });
    });

    // --- Lógica de Tabs genérica ---
    document.querySelectorAll('.tabs').forEach(tabsContainer => {
        const btns = tabsContainer.querySelectorAll('.tab-btn');
        btns.forEach(btn => {
            btn.addEventListener('click', () => {
                // Desactivar todos los botones del grupo
                btns.forEach(b => b.classList.remove('active'));
                
                // Ocultar todos los paneles correspondientes a este grupo
                // (Asumimos que los paneles están al mismo nivel o dentro del mismo section)
                const section = btn.closest('.section');
                const panels = section.querySelectorAll('.tab-panel');
                panels.forEach(p => p.classList.remove('active'));
                
                // Activar seleccionado
                btn.classList.add('active');
                const targetPanel = document.getElementById(btn.dataset.tab);
                if (targetPanel) targetPanel.classList.add('active');
            });
        });
    });
});

// Exportar globales para los módulos
window.api = api;
window.ui = ui;
