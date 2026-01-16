/**
 * IPsec VPN Module - Tunnel List View
 * 
 * Displays table of all IPsec tunnels with actions.
 */

import {
    apiGet, apiPost, apiDelete,
    showToast, confirmDialog, escapeHtml,
    statusBadge, loadingSpinner, emptyState
} from '/static/modules/strongswan/views/utils.js';
import { showTunnelForm } from '/static/modules/strongswan/views/tunnelForm.js';

let tunnels = [];
let canManage = false;

export async function renderTunnelList(container, permissions) {
    canManage = permissions.manage;

    container.innerHTML = `
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h3 class="card-title mb-0">
                    <i class="ti ti-shield-lock me-2"></i>IPsec Tunnels
                </h3>
                ${canManage ? `
                <button class="btn btn-primary" id="btn-new-tunnel">
                    <i class="ti ti-plus me-1"></i>Nuovo Tunnel
                </button>` : ''}
            </div>
            <div class="card-body p-0" id="tunnels-container">
                ${loadingSpinner()}
            </div>
        </div>
    `;

    // Event listeners
    document.getElementById('btn-new-tunnel')?.addEventListener('click', () => {
        showTunnelForm(null, async () => {
            await loadTunnels();
        });
    });

    await loadTunnels();
}

async function loadTunnels() {
    const container = document.getElementById('tunnels-container');

    try {
        tunnels = await apiGet('/modules/strongswan/tunnels');
        renderTable();
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger m-3">${escapeHtml(e.message)}</div>`;
    }
}

function renderTable() {
    const container = document.getElementById('tunnels-container');

    if (tunnels.length === 0) {
        container.innerHTML = emptyState(
            'shield-off',
            'Nessun tunnel IPsec configurato',
            canManage ? 'Clicca "Nuovo Tunnel" per crearne uno' : ''
        );
        return;
    }

    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-vcenter card-table table-hover">
                <thead>
                    <tr>
                        <th style="width: 30px;"></th>
                        <th>Nome</th>
                        <th>Remote Gateway</th>
                        <th>IKE</th>
                        <th>Phase 2</th>
                        <th class="w-1">Azioni</th>
                    </tr>
                </thead>
                <tbody>
                    ${tunnels.map(t => `
                        <tr class="tunnel-row" data-id="${t.id}" style="cursor: pointer;">
                            <td>
                                <span class="status-dot ${t.status === 'established' ? 'status-dot-animated bg-success' : t.status === 'connecting' ? 'status-dot-animated bg-warning' : 'bg-secondary'}" 
                                      title="${t.status === 'established' ? 'UP' : t.status === 'connecting' ? 'Connecting' : 'DOWN'}"></span>
                            </td>
                            <td>
                                <a href="#strongswan/${t.id}" class="text-reset">
                                    <strong>${escapeHtml(t.name)}</strong>
                                </a>
                                <div class="small text-muted">
                                    ${t.status === 'established'
            ? '<span class="text-success">UP</span>'
            : t.status === 'connecting'
                ? '<span class="text-warning">Connecting...</span>'
                : '<span class="text-secondary">Down</span>'}
                                </div>
                            </td>
                            <td><code>${escapeHtml(t.remote_address)}</code></td>
                            <td><span class="badge bg-azure-lt">v${t.ike_version}</span></td>
                            <td>
                                ${t.child_sa_count > 0
            ? `<span class="badge ${t.status === 'established' ? 'bg-success-lt text-success' : 'bg-secondary-lt'}">${t.child_sa_count} ${t.status === 'established' ? 'UP' : ''}</span>`
            : '<span class="text-muted">0</span>'}
                            </td>
                            <td>
                                <div class="btn-group btn-group-sm" onclick="event.stopPropagation();">
                                    ${canManage ? `
                                    ${t.status === 'established' || t.status === 'connecting'
                ? `<button class="btn btn-ghost-warning btn-stop" data-id="${t.id}" title="Stop">
                                            <i class="ti ti-player-stop"></i>
                                           </button>`
                : `<button class="btn btn-ghost-success btn-start" data-id="${t.id}" title="Start">
                                            <i class="ti ti-player-play"></i>
                                           </button>`
            }
                                    <button class="btn btn-ghost-primary btn-edit" data-id="${t.id}" title="Modifica">
                                        <i class="ti ti-edit"></i>
                                    </button>
                                    <button class="btn btn-ghost-danger btn-delete" data-id="${t.id}" title="Elimina">
                                        <i class="ti ti-trash"></i>
                                    </button>
                                    ` : ''}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    setupRowActions();
}

function setupRowActions() {
    // Row click navigates to detail
    document.querySelectorAll('.tunnel-row').forEach(row => {
        row.addEventListener('click', (e) => {
            if (e.target.closest('.btn-group')) return;
            window.location.hash = `#strongswan/${row.dataset.id}`;
        });
    });

    // Start tunnel
    document.querySelectorAll('.btn-start').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const id = btn.dataset.id;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
            try {
                await apiPost(`/modules/strongswan/tunnels/${id}/start`);
                showToast('Tunnel avviato', 'success');
                await loadTunnels();
            } catch (err) {
                showToast(err.message, 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-player-play"></i>';
            }
        });
    });

    // Stop tunnel
    document.querySelectorAll('.btn-stop').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const id = btn.dataset.id;
            btn.disabled = true;
            try {
                await apiPost(`/modules/strongswan/tunnels/${id}/stop`);
                showToast('Tunnel fermato', 'success');
                await loadTunnels();
            } catch (err) {
                showToast(err.message, 'error');
                btn.disabled = false;
            }
        });
    });

    // Edit tunnel
    document.querySelectorAll('.btn-edit').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const id = btn.dataset.id;
            try {
                const tunnel = await apiGet(`/modules/strongswan/tunnels/${id}`);
                showTunnelForm(tunnel, async () => {
                    await loadTunnels();
                });
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    });

    // Delete tunnel
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const id = btn.dataset.id;
            const tunnel = tunnels.find(t => t.id === id);

            const confirmed = await confirmDialog(
                'Elimina Tunnel',
                `<p>Eliminare il tunnel <strong>${escapeHtml(tunnel?.name || id)}</strong>?</p>
                <p class="text-muted small">Verranno eliminate anche tutte le Phase 2 associate.</p>`,
                'Elimina',
                'btn-danger',
                true
            );

            if (confirmed) {
                try {
                    await apiDelete(`/modules/strongswan/tunnels/${id}`);
                    showToast('Tunnel eliminato', 'success');
                    await loadTunnels();
                } catch (err) {
                    showToast(err.message, 'error');
                }
            }
        });
    });
}
