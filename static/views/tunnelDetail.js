/**
 * IPsec VPN Module - Tunnel Detail View
 * 
 * Shows tunnel details with Phase 2 selectors management.
 */

import {
    apiGet, apiPost, apiDelete,
    showToast, confirmDialog, escapeHtml,
    statusBadge, loadingSpinner, parseProposal
} from '/static/modules/strongswan/views/utils.js';
import { showTunnelForm } from '/static/modules/strongswan/views/tunnelForm.js';
import { renderChildSaForm, setupChildSaFormEvents } from '/static/modules/strongswan/views/childSaForm.js';

let tunnel = null;
let children = [];
let canManage = false;
let statusInterval = null;

export async function renderTunnelDetail(container, tunnelId, permissions) {
    // Clear previous interval if any
    if (statusInterval) clearInterval(statusInterval);

    canManage = permissions.manage;

    container.innerHTML = loadingSpinner();

    try {
        tunnel = await apiGet(`/modules/strongswan/tunnels/${tunnelId}`);
        children = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/children`);
        renderDetail(container, tunnelId);
        startStatusPolling(tunnelId);
    } catch (e) {
        container.innerHTML = `
            <div class="mb-3">
                <a href="#strongswan" class="text-muted">
                    <i class="ti ti-arrow-left me-1"></i>Torna ai Tunnels
                </a>
            </div>
            <div class="alert alert-danger">${escapeHtml(e.message)}</div>
        `;
    }
}

async function startStatusPolling(tunnelId) {
    // Immediate status fetch on load
    try {
        const status = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/status`);
        updateStatusUI(status);
    } catch (e) {
        console.error('Initial status fetch failed', e);
    }

    statusInterval = setInterval(async () => {
        // Stop polling if element removed from DOM
        if (!document.getElementById('btn-stop') && !document.getElementById('btn-start')) {
            clearInterval(statusInterval);
            return;
        }

        try {
            const status = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/status`);

            // Update tunnel status object
            const newState = status.ike_state === 'ESTABLISHED' ? 'established' :
                status.ike_state === 'CONNECTING' ? 'connecting' : 'disconnected';

            if (tunnel.status !== newState) {
                // If status changed, full reload to update buttons and badges correctly without complex DOM manipulation
                tunnel.status = newState;
                location.reload();
            }

            // Note: Optimally we would just update the DOM elements, but reloading is safer for consistency
            // especially with the Start/Stop buttons logic. 
            // However, full reload is annoying. Let's try to update DOM.

            updateStatusUI(status);

        } catch (e) {
            console.error('Polling failed', e);
        }
    }, 5000);
}

function updateStatusUI(status) {
    const newState = status.ike_state === 'ESTABLISHED' ? 'established' :
        status.ike_state === 'CONNECTING' ? 'connecting' : 'disconnected';

    tunnel.status = newState;

    // Update Status Dot and Badge
    const header = document.querySelector('.card-body .d-flex .d-flex');
    if (header) {
        const dot = header.querySelector('.status-dot');
        const badge = header.querySelector('.badge');

        if (dot) {
            dot.className = `status-dot ${newState === 'established' ? 'status-dot-animated bg-success' : newState === 'connecting' ? 'status-dot-animated bg-warning' : 'bg-secondary'}`;
        }
        if (badge) {
            badge.className = `badge fs-6 ${newState === 'established' ? 'bg-success-lt text-success' : newState === 'connecting' ? 'bg-warning-lt text-warning' : 'bg-secondary-lt text-secondary'}`;
            badge.innerText = newState === 'established' ? 'UP' : newState === 'connecting' ? 'CONNECTING' : 'DOWN';
        }
    }

    // Update Buttons
    const btnContainer = document.querySelector('.card-body .d-flex .btn-group');
    if (btnContainer && canManage) {
        // Re-render buttons based on new state
        // Check if we need to switch from Start to Stop or vice-versa
        const hasStop = btnContainer.querySelector('#btn-stop');
        const hasStart = btnContainer.querySelector('#btn-start');

        if ((newState === 'established' || newState === 'connecting') && hasStart) {
            // Replace Start with Stop
            hasStart.outerHTML = `<button class="btn btn-warning" id="btn-stop"><i class="ti ti-player-stop me-1"></i>Stop</button>`;
            location.reload();
            return;
        } else if (newState === 'disconnected' && hasStop) {
            // Replace Stop with Start
            location.reload();
            return;
        }
    }

    // Update Child SAs
    if (status.child_sas) {
        // Create set of active children names (those INSTALLED)
        // VICI might append suffixes, but service.py now normalizes names
        const activeChildren = new Set(status.child_sas.filter(c => c.state === 'INSTALLED').map(c => c.name));

        children.forEach(c => {
            const dot = document.getElementById(`status-dot-${c.name}`);
            if (dot) {
                if (newState !== 'established') {
                    // If IKE is down/connecting, children are effectively down
                    dot.className = c.enabled ? 'status-dot bg-secondary' : 'status-dot bg-danger';
                    dot.title = c.enabled ? 'Waiting for Tunnel' : 'Disabled';
                } else {
                    if (activeChildren.has(c.name)) {
                        dot.className = 'status-dot status-dot-animated bg-success';
                        dot.title = 'UP (Installed)';
                    } else if (c.enabled) {
                        // Enabled but not established -> Negotiating or Failed
                        dot.className = 'status-dot status-dot-animated bg-warning';
                        dot.title = 'Negotiating / Failed';
                    } else {
                        // Disabled
                        dot.className = 'status-dot bg-danger';
                        dot.title = 'Disabled';
                    }
                }
            }
        });
    }
}

function renderDetail(container, tunnelId) {
    const proposal = parseProposal(tunnel.ike_proposal);

    container.innerHTML = `
        <!-- Breadcrumb -->
        <div class="mb-3">
            <a href="#strongswan" class="text-muted">
                <i class="ti ti-arrow-left me-1"></i>Torna ai Tunnels
            </a>
        </div>
        
        <!-- Header Card -->
        <div class="card mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <span class="status-dot ${tunnel.status === 'established' ? 'status-dot-animated bg-success' : tunnel.status === 'connecting' ? 'status-dot-animated bg-warning' : 'bg-secondary'}"></span>
                            <h2 class="mb-0">${escapeHtml(tunnel.name)}</h2>
                            <span class="badge fs-6 ${tunnel.status === 'established' ? 'bg-success-lt text-success' : tunnel.status === 'connecting' ? 'bg-warning-lt text-warning' : 'bg-secondary-lt text-secondary'}">
                                ${tunnel.status === 'established' ? 'UP' : tunnel.status === 'connecting' ? 'CONNECTING' : 'DOWN'}
                            </span>
                        </div>
                        <div class="text-muted">
                            <code>${escapeHtml(tunnel.local_address || '%any')}</code>
                            <i class="ti ti-arrows-exchange mx-2"></i>
                            <code>${escapeHtml(tunnel.remote_address)}</code>
                        </div>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        ${canManage ? `
                        <div class="btn-group">
                            ${tunnel.status === 'established' || tunnel.status === 'connecting'
                ? `<button class="btn btn-warning" id="btn-stop">
                                    <i class="ti ti-player-stop me-1"></i>Stop
                                   </button>`
                : `<button class="btn btn-success" id="btn-start">
                                    <i class="ti ti-player-play me-1"></i>Start
                                   </button>`
            }
                            <button class="btn btn-outline-primary" id="btn-edit-tunnel">
                                <i class="ti ti-edit me-1"></i>Modifica
                            </button>
                            <button class="btn btn-outline-danger" id="btn-delete-tunnel">
                                <i class="ti ti-trash"></i>
                            </button>
                        </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Info Cards Row -->
        <div class="row g-3 mb-3">
            <!-- Network -->
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-header py-2">
                        <h6 class="card-title mb-0"><i class="ti ti-network me-1"></i>Network</h6>
                    </div>
                    <div class="card-body py-2">
                        <table class="table table-sm table-borderless mb-0">
                            <tr><td class="text-muted" width="40%">NAT-T</td>
                                <td>${tunnel.nat_traversal ? '<span class="badge bg-green-lt">Enabled</span>' : '<span class="badge bg-secondary-lt">Disabled</span>'}</td></tr>
                            <tr><td class="text-muted">DPD</td>
                                <td>${tunnel.dpd_action} (${tunnel.dpd_delay}s)</td></tr>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Authentication -->
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-header py-2">
                        <h6 class="card-title mb-0"><i class="ti ti-key me-1"></i>Authentication</h6>
                    </div>
                    <div class="card-body py-2">
                        <table class="table table-sm table-borderless mb-0">
                            <tr><td class="text-muted" width="40%">Metodo</td>
                                <td>${tunnel.auth_method === 'psk' ? 'Pre-Shared Key' : 'Certificate'}</td></tr>
                            <tr><td class="text-muted">IKE</td>
                                <td><span class="badge bg-azure-lt">Version ${tunnel.ike_version}</span></td></tr>
                            ${tunnel.local_id ? `<tr><td class="text-muted">Local ID</td><td><code>${escapeHtml(tunnel.local_id)}</code></td></tr>` : ''}
                            ${tunnel.remote_id ? `<tr><td class="text-muted">Remote ID</td><td><code>${escapeHtml(tunnel.remote_id)}</code></td></tr>` : ''}
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Phase 1 Proposal -->
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-header py-2">
                        <h6 class="card-title mb-0"><i class="ti ti-lock me-1"></i>Phase 1 Proposal</h6>
                    </div>
                    <div class="card-body py-2">
                        <table class="table table-sm table-borderless mb-0">
                            <tr><td class="text-muted" width="40%">Encryption</td>
                                <td><code>${proposal.enc}</code></td></tr>
                            ${proposal.integ ? `<tr><td class="text-muted">Integrity</td><td><code>${proposal.integ}</code></td></tr>` : ''}
                            <tr><td class="text-muted">DH Group</td>
                                <td><code>${proposal.dh}</code></td></tr>
                            <tr><td class="text-muted">Lifetime</td>
                                <td>${tunnel.ike_lifetime}s</td></tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Phase 2 Selectors -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">
                <i class="ti ti-route me-2"></i>Phase 2 Selectors
                </h5>
                ${canManage ? `
                <button class="btn btn-primary btn-sm" id="btn-add-phase2">
                    <i class="ti ti-plus me-1"></i>Add Phase 2
                </button>
                ` : ''}
            </div>
            <div class="card-body p-0" id="phase2-container">
                ${renderPhase2Table()}
            </div>
            <div id="phase2-form-container"></div>
        </div>
        
        <!-- Traffic Statistics & Logs Row -->
        <div class="row mt-3">
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">
                            <i class="ti ti-chart-area me-2"></i>Traffico
                        </h5>
                        <div class="d-flex align-items-center gap-2">
                            <select class="form-select form-select-sm" id="traffic-period" style="width: auto;">
                                <option value="1h">Ultima ora</option>
                                <option value="6h">Ultime 6 ore</option>
                                <option value="24h" selected>Ultime 24 ore</option>
                                <option value="7d">Ultimi 7 giorni</option>
                            </select>
                            <span class="text-muted small" id="traffic-stats-label">--</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="traffic-chart" style="height: 180px;"></div>
                        <div class="row mt-3 text-center">
                            <div class="col-6">
                                <div class="text-muted small">Download</div>
                                <div class="h4 mb-0" id="traffic-in">--</div>
                            </div>
                            <div class="col-6">
                                <div class="text-muted small">Upload</div>
                                <div class="h4 mb-0" id="traffic-out">--</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">
                            <i class="ti ti-file-text me-2"></i>Log e Diagnostica
                        </h5>
                        <button class="btn btn-sm btn-outline-secondary" id="btn-refresh-logs">
                            <i class="ti ti-refresh"></i>
                        </button>
                    </div>
                    <div class="card-body p-0">
                        <div id="log-errors"></div>
                        <div id="log-container" class="p-2" style="max-height: 250px; overflow-y: auto; font-family: monospace; font-size: 11px; background: #f8f9fa;">
                            <div class="text-muted text-center py-3">Caricamento log...</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    setupDetailEvents(tunnelId);
    loadTrafficStats(tunnelId);
    loadLogs(tunnelId);
}

function renderPhase2Table() {
    if (children.length === 0) {
        return `
            <div class="text-center py-4 text-muted">
                <i class="ti ti-route-off" style="font-size: 2rem;"></i>
                <p class="mt-2 mb-0">Nessuna Phase 2 configurata</p>
                <small>Aggiungi una Phase 2 per definire i traffic selectors</small>
            </div>
        `;
    }

    return `
        <div class="table-responsive">
            <table class="table table-vcenter card-table">
                <thead>
                    <tr>
                        <th style="width: 30px;"></th>
                        <th>Nome</th>
                        <th>Local Subnet</th>
                        <th>Remote Subnet</th>
                        <th>ESP Proposal</th>
                        <th>Start</th>
                        ${canManage ? '<th class="w-1">Azioni</th>' : ''}
                    </tr>
                </thead>
                <tbody>
                    ${children.map(c => `
                        <tr>
                            <td>
                                <span id="status-dot-${c.name}" class="status-dot ${c.enabled ? 'bg-secondary' : 'bg-danger'}" 
                                      title="${c.enabled ? 'Verifica in corso...' : 'Disabilitato'}"></span>
                            </td>
                            <td><strong>${escapeHtml(c.name)}</strong></td>
                            <td><code class="small">${escapeHtml(c.local_ts)}</code></td>
                            <td><code class="small">${escapeHtml(c.remote_ts)}</code></td>
                            <td><code class="small text-muted">${escapeHtml(c.esp_proposal || 'default')}</code></td>
                            <td><span class="badge bg-secondary-lt">${c.start_action}</span></td>
                            ${canManage ? `
                            <td>
                                <div class="btn-list flex-nowrap">
                                    <button class="btn btn-sm btn-ghost-success btn-start-child" 
                                            data-id="${c.id}" title="Avvia">
                                        <i class="ti ti-player-play"></i>
                                    </button>
                                    <button class="btn btn-sm btn-ghost-warning btn-stop-child" 
                                            data-id="${c.id}" title="Ferma">
                                        <i class="ti ti-player-stop"></i>
                                    </button>
                                    <button class="btn btn-sm btn-ghost-primary btn-edit-child" 
                                            data-id="${c.id}" title="Modifica">
                                        <i class="ti ti-edit"></i>
                                    </button>
                                    <button class="btn btn-sm btn-ghost-danger btn-delete-child" 
                                            data-id="${c.id}" data-name="${escapeHtml(c.name)}" title="Elimina">
                                        <i class="ti ti-trash"></i>
                                    </button>
                                </div>
                            </td>
                            ` : ''}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function setupDetailEvents(tunnelId) {
    // Start Child SA
    document.querySelectorAll('.btn-start-child').forEach(btn => {
        btn.addEventListener('click', async () => {
            const childId = btn.dataset.id;
            const icon = btn.querySelector('i');
            const originalClass = icon.className;

            btn.disabled = true;
            icon.className = 'spinner-border spinner-border-sm';

            try {
                await apiPost(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}/start`);
                showToast('Child SA avviata', 'success');
            } catch (e) {
                showToast(e.message, 'error');
            } finally {
                btn.disabled = false;
                icon.className = originalClass;
            }
        });
    });

    // Stop Child SA
    document.querySelectorAll('.btn-stop-child').forEach(btn => {
        btn.addEventListener('click', async () => {
            const childId = btn.dataset.id;
            const icon = btn.querySelector('i');
            const originalClass = icon.className;

            btn.disabled = true;
            icon.className = 'spinner-border spinner-border-sm';

            try {
                await apiPost(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}/stop`);
                showToast('Child SA fermata', 'success');
            } catch (e) {
                showToast(e.message, 'error');
            } finally {
                btn.disabled = false;
                icon.className = originalClass;
            }
        });
    });

    // Start tunnel
    document.getElementById('btn-start')?.addEventListener('click', async () => {
        const btn = document.getElementById('btn-start');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Starting...';
        try {
            await apiPost(`/modules/strongswan/tunnels/${tunnelId}/start`);
            showToast('Tunnel avviato', 'success');
            tunnel.status = 'connecting';
            location.reload();
        } catch (e) {
            showToast(e.message, 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-player-play me-1"></i>Start';
        }
    });

    // Stop tunnel
    document.getElementById('btn-stop')?.addEventListener('click', async () => {
        const btn = document.getElementById('btn-stop');
        btn.disabled = true;
        try {
            await apiPost(`/modules/strongswan/tunnels/${tunnelId}/stop`);
            showToast('Tunnel fermato', 'success');
            tunnel.status = 'disconnected';
            location.reload();
        } catch (e) {
            showToast(e.message, 'error');
            btn.disabled = false;
        }
    });

    // Edit tunnel
    document.getElementById('btn-edit-tunnel')?.addEventListener('click', () => {
        showTunnelForm(tunnel, () => {
            location.reload();
        });
    });

    // Delete tunnel
    document.getElementById('btn-delete-tunnel')?.addEventListener('click', async () => {
        const confirmed = await confirmDialog(
            'Elimina Tunnel',
            `<p>Eliminare <strong>${escapeHtml(tunnel.name)}</strong>?</p>
            <p class="text-muted small">Verranno eliminate anche tutte le Phase 2.</p>`,
            'Elimina',
            'btn-danger',
            true
        );
        if (confirmed) {
            try {
                await apiDelete(`/modules/strongswan/tunnels/${tunnelId}`);
                showToast('Tunnel eliminato', 'success');
                window.location.hash = '#strongswan';
            } catch (e) {
                showToast(e.message, 'error');
            }
        }
    });

    // Add Phase 2
    document.getElementById('btn-add-phase2')?.addEventListener('click', () => {
        const formContainer = document.getElementById('phase2-form-container');
        formContainer.innerHTML = renderChildSaForm(tunnelId);
        document.getElementById('btn-add-phase2').classList.add('d-none');
        setupChildSaFormEvents(tunnelId, () => location.reload());
    });

    // Delete Phase 2
    document.querySelectorAll('.btn-delete-child').forEach(btn => {
        btn.addEventListener('click', async () => {
            const childId = btn.dataset.id;
            const childName = btn.dataset.name;

            const confirmed = await confirmDialog(
                'Elimina Phase 2',
                `Eliminare <strong>${escapeHtml(childName)}</strong>?`,
                'Elimina',
                'btn-danger',
                true  // Enable HTML content
            );

            if (confirmed) {
                try {
                    await apiDelete(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}`);
                    showToast('Phase 2 eliminata', 'success');
                    location.reload();
                } catch (e) {
                    showToast(e.message, 'error');
                }
            }
        });
    });

    // Edit Phase 2
    document.querySelectorAll('.btn-edit-child').forEach(btn => {
        btn.addEventListener('click', () => {
            const childId = btn.dataset.id;
            const child = children.find(c => c.id === childId);

            if (child) {
                const formContainer = document.getElementById('phase2-form-container');
                // Pass child data for editing
                formContainer.innerHTML = renderChildSaForm(tunnelId, null, child);
                document.getElementById('btn-add-phase2')?.classList.add('d-none');
                setupChildSaFormEvents(tunnelId, () => location.reload());

                // Scroll to form
                formContainer.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // Refresh logs button
    document.getElementById('btn-refresh-logs')?.addEventListener('click', () => {
        loadLogs(tunnelId);
    });

    // Traffic period selector
    document.getElementById('traffic-period')?.addEventListener('change', () => {
        loadTrafficStats(tunnelId);
    });
}

// Traffic stats history for chart
let trafficHistory = { in: [], out: [], labels: [] };
let trafficChart = null;

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function loadTrafficStats(tunnelId, period = null) {
    try {
        // Use selected period or get from dropdown
        const selectedPeriod = period || document.getElementById('traffic-period')?.value || '24h';

        // Fetch historical data
        const response = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/traffic?period=${selectedPeriod}`);

        // Process data for chart
        trafficHistory.labels = [];
        trafficHistory.in = [];
        trafficHistory.out = [];
        let totalIn = 0;
        let totalOut = 0;

        if (response.data && response.data.length > 0) {
            response.data.forEach(point => {
                // Format timestamp based on period
                const date = new Date(point.timestamp);
                const hours = date.getHours().toString().padStart(2, '0');
                const minutes = date.getMinutes().toString().padStart(2, '0');
                let label;

                if (selectedPeriod === '7d' || selectedPeriod === '30d') {
                    const day = date.getDate().toString().padStart(2, '0');
                    const month = (date.getMonth() + 1).toString().padStart(2, '0');
                    label = `${day}/${month} ${hours}:${minutes}`;
                } else {
                    // 1h, 6h, 24h
                    label = `${hours}:${minutes}`;
                }

                trafficHistory.labels.push(label);
                trafficHistory.in.push(point.bytes_in || 0);
                trafficHistory.out.push(point.bytes_out || 0);
                totalIn += point.bytes_in || 0;
                totalOut += point.bytes_out || 0;
            });
        }

        // Update display with totals
        document.getElementById('traffic-in').textContent = formatBytes(totalIn);
        document.getElementById('traffic-out').textContent = formatBytes(totalOut);
        document.getElementById('traffic-stats-label').textContent =
            `${response.data_points || 0} punti`;

        // Render chart
        renderTrafficChart(selectedPeriod);

    } catch (e) {
        console.error('Failed to load traffic stats', e);
        document.getElementById('traffic-in').textContent = '--';
        document.getElementById('traffic-out').textContent = '--';
        document.getElementById('traffic-stats-label').textContent = 'Errore';
    }
}

function renderTrafficChart(period = '24h') {
    const chartEl = document.getElementById('traffic-chart');
    if (!chartEl) return;

    const options = {
        series: [{
            name: 'Download',
            data: trafficHistory.in,
            color: '#206bc4'
        }, {
            name: 'Upload',
            data: trafficHistory.out,
            color: '#2fb344'
        }],
        chart: {
            type: 'area',
            height: 180,
            fontFamily: 'inherit',
            sparkline: { enabled: false },
            toolbar: { show: false },
            animations: { enabled: true }
        },
        dataLabels: { enabled: false },
        stroke: { curve: 'smooth', width: 2 },
        fill: {
            type: 'gradient',
            gradient: { opacityFrom: 0.4, opacityTo: 0.1 }
        },
        xaxis: {
            categories: trafficHistory.labels,
            labels: {
                style: { fontSize: '10px' },
                formatter: function (val) {
                    if (!val) return '';
                    // val format: "HH:mm" or "DD/MM HH:mm"

                    if (period === '1h' || period === '6h' || period === '24h') {
                        // Show full hours and half-hours
                        if (val.endsWith(':00') || val.endsWith(':30')) return val;
                        return '';
                    }

                    const timePart = val.includes(' ') ? val.split(' ')[1] : val;
                    if (!timePart) return val;

                    if (period === '7d') {
                        // Every 6 hours (00:00, 06:00, 12:00, 18:00)
                        if (timePart.endsWith(':00')) {
                            const hour = parseInt(timePart.split(':')[0]);
                            if (hour % 6 === 0) return val;
                        }
                        return '';
                    }

                    if (period === '30d') {
                        // Daily at midnight
                        if (timePart === '00:00') return val;
                        return '';
                    }

                    return val;
                }
            },
            tooltip: {
                enabled: false
            }
        },
        yaxis: {
            labels: {
                formatter: (v) => formatBytes(v),
                style: { fontSize: '10px' }
            }
        },
        tooltip: {
            y: { formatter: (v) => formatBytes(v) }
        },
        legend: { show: false }
    };

    if (trafficChart) {
        trafficChart.updateOptions(options);
    } else if (typeof ApexCharts !== 'undefined') {
        trafficChart = new ApexCharts(chartEl, options);
        trafficChart.render();
    } else {
        // Fallback if ApexCharts not loaded
        chartEl.innerHTML = '<div class="text-center text-muted py-4"><i class="ti ti-chart-line" style="font-size: 2rem;"></i><br>Grafici non disponibili</div>';
    }
}

async function loadLogs(tunnelId) {
    const container = document.getElementById('log-container');
    const errorsContainer = document.getElementById('log-errors');

    try {
        container.innerHTML = '<div class="text-center py-3"><span class="spinner-border spinner-border-sm"></span></div>';

        const data = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/logs`);

        // Display errors as alerts
        if (data.errors && data.errors.length > 0) {
            errorsContainer.innerHTML = data.errors.map(err => `
                <div class="alert alert-danger alert-dismissible m-2 py-2 px-3" style="font-size: 12px;">
                    <i class="ti ti-alert-circle me-1"></i>
                    <strong>${escapeHtml(err.description)}</strong>
                    ${err.log_line ? `<div class="text-muted small mt-1" style="font-family: monospace;">${escapeHtml(err.log_line.substring(0, 100))}...</div>` : ''}
                </div>
            `).join('');
        } else {
            errorsContainer.innerHTML = '';
        }

        // Display logs
        if (data.logs && data.logs.length > 0) {
            container.innerHTML = data.logs.map(line => {
                // Highlight errors in red
                const isError = /error|failed|timeout|refused/i.test(line);
                return `<div class="${isError ? 'text-danger' : ''}" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(line)}</div>`;
            }).join('');

            // Scroll to bottom
            container.scrollTop = container.scrollHeight;
        } else {
            container.innerHTML = '<div class="text-center text-muted py-3">Nessun log recente per questo tunnel</div>';
        }

    } catch (e) {
        console.error('Failed to load logs', e);
        container.innerHTML = `<div class="text-danger text-center py-3">Errore: ${escapeHtml(e.message)}</div>`;
    }
}
