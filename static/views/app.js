/**
 * IPsec VPN Module - Main Application
 * 
 * Handles tunnel listing, creation, and management.
 * FortiGate-style interface with Phase 1/Phase 2 hierarchy.
 */

const IPsecApp = {
    API_BASE: '/api/modules/strongswan',
    currentTunnel: null,
    cryptoOptions: null,

    // Initialize and render the app
    render: async function (container) {
        this.container = container;

        // Load crypto options
        await this.loadCryptoOptions();

        // Render main layout
        this.container.innerHTML = this.getMainTemplate();

        // Bind events
        this.bindEvents();

        // Load tunnels
        await this.loadTunnels();
    },

    // Fetch crypto algorithm options
    loadCryptoOptions: async function () {
        try {
            const resp = await fetch(`${this.API_BASE}/crypto-options`);
            if (resp.ok) {
                this.cryptoOptions = await resp.json();
            }
        } catch (e) {
            console.error('[IPsec] Failed to load crypto options:', e);
        }
    },

    // Main layout template
    getMainTemplate: function () {
        return `
            <div class="container-xl">
                <div class="page-header d-print-none mb-4">
                    <div class="row align-items-center">
                        <div class="col-auto">
                            <h2 class="page-title">
                                <svg class="icon icon-lg me-2" style="width:24px;height:24px" viewBox="0 0 24 24">
                                    <path fill="currentColor" d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M17.13,17C15.92,18.85 14.11,20.24 12,20.92C9.89,20.24 8.08,18.85 6.87,17C6.53,16.5 6.24,16 6,15.47C6,13.82 8.71,12.47 12,12.47C15.29,12.47 18,13.79 18,15.47C17.76,16 17.47,16.5 17.13,17Z"/>
                                </svg>
                                IPsec VPN Tunnels
                            </h2>
                        </div>
                        <div class="col-auto ms-auto">
                            <button type="button" class="btn btn-primary" id="btn-new-tunnel">
                                <svg class="icon icon-tabler icon-tabler-plus me-1" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                    <path d="M12 5v14M5 12h14"/>
                                </svg>
                                Nuovo Tunnel
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-body p-0">
                        <div id="tunnels-list" class="list-group list-group-flush">
                            <div class="text-center py-4">
                                <div class="spinner-border text-primary" role="status"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Tunnel Modal -->
            <div class="modal modal-blur fade" id="tunnel-modal" tabindex="-1">
                <div class="modal-dialog modal-lg modal-dialog-centered">
                    <div class="modal-content" id="tunnel-modal-content"></div>
                </div>
            </div>
        `;
    },

    // Bind event handlers
    bindEvents: function () {
        // New tunnel button
        document.getElementById('btn-new-tunnel')?.addEventListener('click', () => {
            this.showTunnelForm();
        });

        // Delegate clicks on tunnel list
        document.getElementById('tunnels-list')?.addEventListener('click', (e) => {
            const tunnelItem = e.target.closest('[data-tunnel-id]');
            if (tunnelItem) {
                const action = e.target.closest('[data-action]')?.dataset.action;
                const tunnelId = tunnelItem.dataset.tunnelId;

                if (action === 'start') {
                    this.startTunnel(tunnelId);
                } else if (action === 'stop') {
                    this.stopTunnel(tunnelId);
                } else if (action === 'delete') {
                    this.deleteTunnel(tunnelId);
                } else if (action === 'edit') {
                    this.editTunnel(tunnelId);
                } else if (!action) {
                    this.showTunnelDetails(tunnelId);
                }
            }

            // Toggle child SAs
            const toggle = e.target.closest('[data-toggle-children]');
            if (toggle) {
                const tunnelId = toggle.dataset.toggleChildren;
                const childrenEl = document.getElementById(`children-${tunnelId}`);
                if (childrenEl) {
                    childrenEl.classList.toggle('d-none');
                    toggle.querySelector('.icon-chevron')?.classList.toggle('rotate-90');
                }
            }
        });
    },

    // Load and display tunnels
    loadTunnels: async function () {
        const listEl = document.getElementById('tunnels-list');

        try {
            const resp = await fetch(`${this.API_BASE}/tunnels`);
            if (!resp.ok) throw new Error('Failed to load tunnels');

            const tunnels = await resp.json();

            if (tunnels.length === 0) {
                listEl.innerHTML = `
                    <div class="text-center py-5 text-muted">
                        <svg class="icon icon-lg mb-2" style="width:48px;height:48px;opacity:0.5" viewBox="0 0 24 24">
                            <path fill="currentColor" d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1Z"/>
                        </svg>
                        <p>Nessun tunnel IPsec configurato</p>
                        <button class="btn btn-primary" id="btn-empty-new">Crea il primo tunnel</button>
                    </div>
                `;
                document.getElementById('btn-empty-new')?.addEventListener('click', () => this.showTunnelForm());
                return;
            }

            listEl.innerHTML = tunnels.map(t => this.getTunnelItemTemplate(t)).join('');

            // Load child SAs for each tunnel
            for (const tunnel of tunnels) {
                await this.loadChildSas(tunnel.id);
            }

        } catch (e) {
            console.error('[IPsec] Error loading tunnels:', e);
            listEl.innerHTML = `
                <div class="text-center py-4 text-danger">
                    <p>Errore nel caricamento dei tunnel</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="IPsecApp.loadTunnels()">Riprova</button>
                </div>
            `;
        }
    },

    // Tunnel item template
    getTunnelItemTemplate: function (tunnel) {
        const statusBadge = this.getStatusBadge(tunnel.status);
        const ikeVersion = tunnel.ike_version === '1' ? 'IKEv1' : 'IKEv2';

        return `
            <div class="list-group-item" data-tunnel-id="${tunnel.id}">
                <div class="row align-items-center">
                    <div class="col-auto">
                        <button class="btn btn-icon btn-ghost-secondary" data-toggle-children="${tunnel.id}">
                            <svg class="icon icon-chevron" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                <polyline points="9 18 15 12 9 6"></polyline>
                            </svg>
                        </button>
                    </div>
                    <div class="col-auto">
                        ${statusBadge}
                    </div>
                    <div class="col">
                        <div class="fw-bold">${this.escapeHtml(tunnel.name)}</div>
                        <div class="text-muted small">
                            ${ikeVersion} &middot; ${this.escapeHtml(tunnel.local_address)} ↔ ${this.escapeHtml(tunnel.remote_address)}
                        </div>
                    </div>
                    <div class="col-auto text-muted">
                        ${tunnel.child_sa_count} Phase 2
                    </div>
                    <div class="col-auto">
                        <div class="btn-group">
                            ${tunnel.status === 'established' ?
                `<button class="btn btn-sm btn-outline-warning" data-action="stop" title="Stop">
                                    <svg class="icon" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                        <rect x="6" y="6" width="12" height="12"/>
                                    </svg>
                                </button>` :
                `<button class="btn btn-sm btn-outline-success" data-action="start" title="Start">
                                    <svg class="icon" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                        <polygon points="5 3 19 12 5 21 5 3"/>
                                    </svg>
                                </button>`
            }
                            <button class="btn btn-sm btn-outline-primary" data-action="edit" title="Modifica">
                                <svg class="icon" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" data-action="delete" title="Elimina">
                                <svg class="icon" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>
                <div id="children-${tunnel.id}" class="ps-5 mt-2 d-none">
                    <div class="text-center py-2">
                        <div class="spinner-border spinner-border-sm text-muted"></div>
                    </div>
                </div>
            </div>
        `;
    },

    // Load Child SAs for a tunnel
    loadChildSas: async function (tunnelId) {
        const childrenEl = document.getElementById(`children-${tunnelId}`);
        if (!childrenEl) return;

        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}/children`);
            if (!resp.ok) return;

            const children = await resp.json();

            if (children.length === 0) {
                childrenEl.innerHTML = `
                    <div class="text-muted small py-2">
                        <em>Nessuna Phase 2 configurata</em>
                        <button class="btn btn-sm btn-link" onclick="IPsecApp.showChildSaForm('${tunnelId}')">
                            + Aggiungi Phase 2
                        </button>
                    </div>
                `;
                return;
            }

            childrenEl.innerHTML = `
                ${children.map(c => `
                    <div class="d-flex align-items-center py-1 border-start ps-3 mb-1">
                        <span class="badge ${c.enabled ? 'bg-blue-lt' : 'bg-secondary-lt'} me-2">P2</span>
                        <span class="fw-medium">${this.escapeHtml(c.name)}</span>
                        <span class="text-muted mx-2">
                            ${this.escapeHtml(c.local_ts)} ↔ ${this.escapeHtml(c.remote_ts)}
                        </span>
                        <div class="ms-auto">
                            <button class="btn btn-sm btn-ghost-danger" onclick="IPsecApp.deleteChildSa('${tunnelId}', '${c.id}')" title="Elimina">
                                <svg class="icon" width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                            </button>
                        </div>
                    </div>
                `).join('')}
                <button class="btn btn-sm btn-link" onclick="IPsecApp.showChildSaForm('${tunnelId}')">
                    + Aggiungi Phase 2
                </button>
            `;
        } catch (e) {
            console.error('[IPsec] Error loading child SAs:', e);
        }
    },

    // Status badge helper
    getStatusBadge: function (status) {
        const badges = {
            'established': '<span class="badge bg-success">UP</span>',
            'connecting': '<span class="badge bg-warning">CONNECTING</span>',
            'disconnected': '<span class="badge bg-secondary">DOWN</span>'
        };
        return badges[status] || badges['disconnected'];
    },

    // Show tunnel creation/edit form
    showTunnelForm: function (tunnel = null) {
        const isEdit = !!tunnel;
        const modal = document.getElementById('tunnel-modal');
        const content = document.getElementById('tunnel-modal-content');

        content.innerHTML = `
            <div class="modal-header">
                <h5 class="modal-title">${isEdit ? 'Modifica Tunnel' : 'Nuovo Tunnel IPsec'}</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="tunnel-form">
                <div class="modal-body">
                    <div class="row mb-3">
                        <div class="col-12">
                            <label class="form-label required">Nome Tunnel</label>
                            <input type="text" class="form-control" name="name" value="${tunnel?.name || ''}" required 
                                   pattern="[a-zA-Z0-9_-]+" title="Solo lettere, numeri, underscore e trattini">
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">IKE Version</label>
                            <div class="btn-group w-100" role="group">
                                <input type="radio" class="btn-check" name="ike_version" value="2" id="ike-v2" 
                                       ${(tunnel?.ike_version || '2') === '2' ? 'checked' : ''}>
                                <label class="btn btn-outline-primary" for="ike-v2">IKEv2</label>
                                <input type="radio" class="btn-check" name="ike_version" value="1" id="ike-v1"
                                       ${tunnel?.ike_version === '1' ? 'checked' : ''}>
                                <label class="btn btn-outline-primary" for="ike-v1">IKEv1</label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">NAT Traversal</label>
                            <div class="form-check form-switch mt-2">
                                <input class="form-check-input" type="checkbox" name="nat_traversal" id="nat-t"
                                       ${(tunnel?.nat_traversal !== false) ? 'checked' : ''}>
                                <label class="form-check-label" for="nat-t">Abilita NAT-T</label>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label required">Local Gateway (IP)</label>
                            <input type="text" class="form-control" name="local_address" 
                                   value="${tunnel?.local_address || ''}" required placeholder="es. 192.168.1.1">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label required">Remote Gateway (IP/FQDN)</label>
                            <input type="text" class="form-control" name="remote_address" 
                                   value="${tunnel?.remote_address || ''}" required placeholder="es. 10.20.30.1">
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Local ID (opzionale)</label>
                            <input type="text" class="form-control" name="local_id" 
                                   value="${tunnel?.local_id || ''}" placeholder="es. gateway-milano">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Remote ID (opzionale)</label>
                            <input type="text" class="form-control" name="remote_id" 
                                   value="${tunnel?.remote_id || ''}" placeholder="es. gateway-roma">
                        </div>
                    </div>
                    
                    <hr>
                    <h6>Autenticazione</h6>
                    
                    <div class="row mb-3">
                        <div class="col-12">
                            <label class="form-label required">Pre-Shared Key (PSK)</label>
                            <div class="input-group">
                                <input type="password" class="form-control" name="psk" id="psk-input"
                                       value="${tunnel?.psk || ''}" ${isEdit ? '' : 'required'} 
                                       placeholder="${isEdit ? '(lascia vuoto per mantenere)' : 'Inserisci PSK'}">
                                <button class="btn btn-outline-secondary" type="button" onclick="IPsecApp.togglePsk()">
                                    <svg class="icon" width="16" height="16" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" fill="none">
                                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                        <circle cx="12" cy="12" r="3"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <hr>
                    <h6>IKE Proposal</h6>
                    
                    <div class="row mb-3">
                        <div class="col-md-4">
                            <label class="form-label">Encryption</label>
                            <select class="form-select" name="encryption" id="sel-encryption">
                                ${(this.cryptoOptions?.encryption || []).map(o =>
            `<option value="${o.value}" ${tunnel?.ike_proposal?.includes(o.value) ? 'selected' : ''}>
                                        ${o.label}
                                    </option>`
        ).join('')}
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Integrity</label>
                            <select class="form-select" name="integrity" id="sel-integrity">
                                ${(this.cryptoOptions?.integrity || []).map(o =>
            `<option value="${o.value}" ${tunnel?.ike_proposal?.includes(o.value) ? 'selected' : ''}>
                                        ${o.label}
                                    </option>`
        ).join('')}
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">DH Group</label>
                            <select class="form-select" name="dh_group" id="sel-dh">
                                ${(this.cryptoOptions?.dh_groups || []).map(o =>
            `<option value="${o.value}" ${tunnel?.ike_proposal?.includes(o.value) ? 'selected' : ''}>
                                        ${o.label}
                                    </option>`
        ).join('')}
                            </select>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-4">
                            <label class="form-label">IKE Lifetime (secondi)</label>
                            <input type="number" class="form-control" name="ike_lifetime" 
                                   value="${tunnel?.ike_lifetime || 28800}" min="3600" max="86400">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">DPD Delay (secondi)</label>
                            <input type="number" class="form-control" name="dpd_delay" 
                                   value="${tunnel?.dpd_delay || 30}" min="10" max="300">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">DPD Action</label>
                            <select class="form-select" name="dpd_action">
                                <option value="restart" ${tunnel?.dpd_action === 'restart' ? 'selected' : ''}>Restart</option>
                                <option value="clear" ${tunnel?.dpd_action === 'clear' ? 'selected' : ''}>Clear</option>
                                <option value="none" ${tunnel?.dpd_action === 'none' ? 'selected' : ''}>None</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="submit" class="btn btn-primary">
                        ${isEdit ? 'Salva Modifiche' : 'Crea Tunnel'}
                    </button>
                </div>
            </form>
        `;

        // Show modal
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Handle form submit
        document.getElementById('tunnel-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.saveTunnel(e.target, tunnel?.id);
            bsModal.hide();
        });
    },

    // Toggle PSK visibility
    togglePsk: function () {
        const input = document.getElementById('psk-input');
        input.type = input.type === 'password' ? 'text' : 'password';
    },

    // Save tunnel (create or update)
    saveTunnel: async function (form, tunnelId = null) {
        const formData = new FormData(form);

        // Build IKE proposal string
        const encryption = formData.get('encryption') || 'aes256';
        const integrity = formData.get('integrity') || 'sha256';
        const dh = formData.get('dh_group') || 'modp2048';
        const ikeProposal = `${encryption}-${integrity}-${dh}`;

        const data = {
            name: formData.get('name'),
            ike_version: formData.get('ike_version') || '2',
            local_address: formData.get('local_address'),
            remote_address: formData.get('remote_address'),
            local_id: formData.get('local_id') || null,
            remote_id: formData.get('remote_id') || null,
            auth_method: 'psk',
            psk: formData.get('psk'),
            ike_proposal: ikeProposal,
            ike_lifetime: parseInt(formData.get('ike_lifetime')) || 28800,
            dpd_action: formData.get('dpd_action') || 'restart',
            dpd_delay: parseInt(formData.get('dpd_delay')) || 30,
            nat_traversal: formData.get('nat_traversal') === 'on'
        };

        // Remove empty PSK for updates
        if (tunnelId && !data.psk) {
            delete data.psk;
        }

        try {
            const method = tunnelId ? 'PUT' : 'POST';
            const url = tunnelId ? `${this.API_BASE}/tunnels/${tunnelId}` : `${this.API_BASE}/tunnels`;

            const resp = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.detail || 'Errore nel salvataggio');
            }

            await this.loadTunnels();

        } catch (e) {
            console.error('[IPsec] Save error:', e);
            alert('Errore: ' + e.message);
        }
    },

    // Edit tunnel
    editTunnel: async function (tunnelId) {
        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}`);
            if (!resp.ok) throw new Error('Tunnel not found');
            const tunnel = await resp.json();
            this.showTunnelForm(tunnel);
        } catch (e) {
            console.error('[IPsec] Edit error:', e);
            alert('Errore nel caricamento del tunnel');
        }
    },

    // Delete tunnel
    deleteTunnel: async function (tunnelId) {
        if (!confirm('Eliminare questo tunnel IPsec? Questa azione è irreversibile.')) {
            return;
        }

        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}`, {
                method: 'DELETE'
            });

            if (!resp.ok) {
                throw new Error('Errore nell\'eliminazione');
            }

            await this.loadTunnels();

        } catch (e) {
            console.error('[IPsec] Delete error:', e);
            alert('Errore: ' + e.message);
        }
    },

    // Start tunnel
    startTunnel: async function (tunnelId) {
        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}/start`, {
                method: 'POST'
            });

            if (!resp.ok) {
                throw new Error('Errore nell\'avvio del tunnel');
            }

            await this.loadTunnels();

        } catch (e) {
            console.error('[IPsec] Start error:', e);
            alert('Errore: ' + e.message);
        }
    },

    // Stop tunnel
    stopTunnel: async function (tunnelId) {
        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}/stop`, {
                method: 'POST'
            });

            if (!resp.ok) {
                throw new Error('Errore nell\'arresto del tunnel');
            }

            await this.loadTunnels();

        } catch (e) {
            console.error('[IPsec] Stop error:', e);
            alert('Errore: ' + e.message);
        }
    },

    // Show Child SA form
    showChildSaForm: function (tunnelId) {
        const modal = document.getElementById('tunnel-modal');
        const content = document.getElementById('tunnel-modal-content');

        content.innerHTML = `
            <div class="modal-header">
                <h5 class="modal-title">Aggiungi Phase 2 (Child SA)</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="child-sa-form">
                <div class="modal-body">
                    <div class="row mb-3">
                        <div class="col-12">
                            <label class="form-label required">Nome Phase 2</label>
                            <input type="text" class="form-control" name="name" required 
                                   pattern="[a-zA-Z0-9_-]+" placeholder="es. phase2-lan1">
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label required">Local Subnet (CIDR)</label>
                            <input type="text" class="form-control" name="local_ts" required 
                                   placeholder="es. 192.168.1.0/24">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label required">Remote Subnet (CIDR)</label>
                            <input type="text" class="form-control" name="remote_ts" required 
                                   placeholder="es. 10.0.0.0/24">
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-4">
                            <label class="form-label">Start Action</label>
                            <select class="form-select" name="start_action">
                                <option value="trap" selected>Trap (on traffic)</option>
                                <option value="start">Start (on boot)</option>
                                <option value="none">None</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Close Action</label>
                            <select class="form-select" name="close_action">
                                <option value="restart" selected>Restart</option>
                                <option value="clear">Clear</option>
                                <option value="none">None</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">ESP Lifetime (sec)</label>
                            <input type="number" class="form-control" name="esp_lifetime" value="3600" min="300" max="86400">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="submit" class="btn btn-primary">Aggiungi Phase 2</button>
                </div>
            </form>
        `;

        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        document.getElementById('child-sa-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.saveChildSa(tunnelId, e.target);
            bsModal.hide();
        });
    },

    // Save Child SA
    saveChildSa: async function (tunnelId, form) {
        const formData = new FormData(form);

        const data = {
            name: formData.get('name'),
            local_ts: formData.get('local_ts'),
            remote_ts: formData.get('remote_ts'),
            start_action: formData.get('start_action') || 'trap',
            close_action: formData.get('close_action') || 'restart',
            esp_lifetime: parseInt(formData.get('esp_lifetime')) || 3600
        };

        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}/children`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.detail || 'Errore nel salvataggio');
            }

            await this.loadTunnels();

        } catch (e) {
            console.error('[IPsec] Save Child SA error:', e);
            alert('Errore: ' + e.message);
        }
    },

    // Delete Child SA
    deleteChildSa: async function (tunnelId, childId) {
        if (!confirm('Eliminare questa Phase 2?')) {
            return;
        }

        try {
            const resp = await fetch(`${this.API_BASE}/tunnels/${tunnelId}/children/${childId}`, {
                method: 'DELETE'
            });

            if (!resp.ok) {
                throw new Error('Errore nell\'eliminazione');
            }

            await this.loadTunnels();

        } catch (e) {
            console.error('[IPsec] Delete Child SA error:', e);
            alert('Errore: ' + e.message);
        }
    },

    // Utility: escape HTML
    escapeHtml: function (str) {
        if (!str) return '';
        return str.toString()
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
};

// Make available globally
window.IPsecApp = IPsecApp;
