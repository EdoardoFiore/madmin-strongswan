/**
 * IPsec VPN Module - Firewall Management Component
 * 
 * Manages per-Child-SA firewall rules with drag-and-drop ordering.
 */

import {
    apiGet, apiPost, apiPatch, apiDelete, apiPut,
    showToast, confirmDialog, escapeHtml
} from '/static/modules/strongswan/views/utils.js';

let currentTunnel = null;
let currentChildren = [];

/**
 * Render firewall management UI for a tunnel
 */
export async function renderFirewallManagement(container, tunnelId) {
    currentTunnel = await apiGet(`/modules/strongswan/tunnels/${tunnelId}`);
    currentChildren = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/children`);

    if (currentChildren.length === 0) {
        container.innerHTML = `
            <div class="empty">
                <div class="empty-icon">
                    <i class="ti ti-shield-off" style="font-size: 3rem;"></i>
                </div>
                <p class="empty-title">Nessuna Phase 2 configurata</p>
                <p class="empty-subtitle text-muted">
                    Aggiungi una Phase 2 per abilitare le regole firewall
                </p>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <ul class="nav nav-tabs mb-3" id="firewall-tabs" role="tablist">
            ${currentChildren.map((child, idx) => `
                <li class="nav-item" role="presentation">
                    <button class="nav-link ${idx === 0 ? 'active' : ''}" 
                            id="tab-${child.id}" 
                            data-bs-toggle="tab" 
                            data-bs-target="#content-${child.id}" 
                            type="button" 
                            role="tab">
                        <i class="ti ti-network me-2"></i>
                        <span class="fw-bold">${escapeHtml(child.local_ts)}</span> <i class="ti ti-arrow-right mx-1" style="font-size: 0.8em;"></i> <span class="fw-bold">${escapeHtml(child.remote_ts)}</span>
                    </button>
                </li>
            `).join('')}
        </ul>
        
        <div class="tab-content" id="firewall-tab-content">
            ${currentChildren.map((child, idx) => `
                <div class="tab-pane fade ${idx === 0 ? 'show active' : ''}" 
                     id="content-${child.id}" 
                     role="tabpanel">
                    <div id="child-firewall-${child.id}">
                        <div class="text-center py-3">
                            <span class="spinner-border spinner-border-sm"></span> Caricamento...
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
        
        <!-- Rule Modal -->
        <div class="modal modal-blur fade" id="firewall-rule-modal" tabindex="-1">
            <div class="modal-dialog modal-lg modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="modal-title">Aggiungi Regola Firewall</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" id="rule-id">
                        <input type="hidden" id="rule-child-id">
                        
                        <div class="mb-3">
                            <label class="form-label required">Direzione</label>
                            <select class="form-select" id="rule-direction">
                                <option value="out">→ Outbound (locale → remoto)</option>
                                <option value="in">← Inbound (remoto → locale)</option>
                                <option value="both">↔ Both (entrambe)</option>
                            </select>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label required">Azione</label>
                                <select class="form-select" id="rule-action">
                                    <option value="ACCEPT">ACCEPT (Permetti)</option>
                                    <option value="DROP">DROP (Blocca)</option>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label required">Protocollo</label>
                                <select class="form-select" id="rule-protocol">
                                    <option value="all">Tutti</option>
                                    <option value="tcp">TCP</option>
                                    <option value="udp">UDP</option>
                                    <option value="icmp">ICMP</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="mb-3" id="port-field" style="display:none;">
                            <label class="form-label">Porta</label>
                            <input type="text" class="form-control" id="rule-port" 
                                   placeholder="es. 80 oppure 8000-8100">
                            <small class="form-hint">Singola porta o range (es. 8000-8100)</small>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Source (opzionale)</label>
                                <input type="text" class="form-control" id="rule-source"
                                       placeholder="es. 192.168.1.0/24">
                                <small class="form-hint">Lascia vuoto per usare il subnet del tunnel</small>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Destination (opzionale)</label>
                                <input type="text" class="form-control" id="rule-destination"
                                       placeholder="es. 10.0.0.0/24">
                                <small class="form-hint">Lascia vuoto per usare il subnet del tunnel</small>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Descrizione</label>
                            <input type="text" class="form-control" id="rule-description"
                                   placeholder="es. Permetti traffico HTTPS">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-link link-secondary" data-bs-dismiss="modal">
                            Annulla
                        </button>
                        <button type="button" class="btn btn-primary" id="btn-save-rule">
                            <i class="ti ti-check me-1"></i>Salva Regola
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Setup protocol change handler
    document.getElementById('rule-protocol').addEventListener('change', (e) => {
        const portField = document.getElementById('port-field');
        portField.style.display = ['tcp', 'udp'].includes(e.target.value) ? 'block' : 'none';
    });

    // Setup save button
    document.getElementById('btn-save-rule').addEventListener('click', saveRule);

    // Load firewall rules for each child SA
    for (const child of currentChildren) {
        loadChildFirewall(tunnelId, child);
    }
}

/**
 * Load firewall configuration for a single Child SA
 */
async function loadChildFirewall(tunnelId, child) {
    const container = document.getElementById(`child-firewall-${child.id}`);

    try {
        const rules = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/children/${child.id}/firewall/rules`);

        // Separate rules by direction
        const rulesOut = rules.filter(r => r.direction === 'out' || r.direction === 'both');
        const rulesIn = rules.filter(r => r.direction === 'in' || r.direction === 'both');

        container.innerHTML = `
            <!-- Default Policies -->
            <div class="card mb-3">
                <div class="card-body">
                    <div class="row">
                        <!-- Outbound Policy -->
                        <div class="col-md-6 border-end">
                            <div class="row align-items-center">
                                <div class="col">
                                    <h4 class="card-title mb-1">Default Outbound Policy</h4>
                                    <p class="text-muted mb-0">
                                        Per traffico locale → remoto non matchato
                                    </p>
                                </div>
                                <div class="col-auto">
                                    <div class="form-check form-switch form-check-lg">
                                        <input class="form-check-input" type="checkbox" 
                                               id="policy-out-${child.id}" 
                                               ${child.firewall_policy_out === 'ACCEPT' ? 'checked' : ''}
                                               onchange="togglePolicy('${tunnelId}', '${child.id}', this.checked, 'out')">
                                        <label class="form-check-label" for="policy-out-${child.id}">
                                            <strong id="policy-out-label-${child.id}" class="${child.firewall_policy_out === 'ACCEPT' ? 'text-success' : 'text-danger'}">
                                                ${child.firewall_policy_out}
                                            </strong>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Inbound Policy -->
                        <div class="col-md-6">
                            <div class="row align-items-center">
                                <div class="col">
                                    <h4 class="card-title mb-1">Default Inbound Policy</h4>
                                    <p class="text-muted mb-0">
                                        Per traffico remoto → locale non matchato
                                    </p>
                                </div>
                                <div class="col-auto">
                                    <div class="form-check form-switch form-check-lg">
                                        <input class="form-check-input" type="checkbox" 
                                               id="policy-in-${child.id}" 
                                               ${child.firewall_policy_in === 'ACCEPT' ? 'checked' : ''}
                                               onchange="togglePolicy('${tunnelId}', '${child.id}', this.checked, 'in')">
                                        <label class="form-check-label" for="policy-in-${child.id}">
                                            <strong id="policy-in-label-${child.id}" class="${child.firewall_policy_in === 'ACCEPT' ? 'text-success' : 'text-danger'}">
                                                ${child.firewall_policy_in}
                                            </strong>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Outbound Rules -->
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="ti ti-arrow-right me-1 text-blue"></i>
                        Regole Outbound (${escapeHtml(child.local_ts)} → ${escapeHtml(child.remote_ts)})
                    </h3>
                    <div class="card-actions">
                        <button class="btn btn-primary btn-sm" onclick="showRuleModal('${tunnelId}', '${child.id}', 'out')">
                            <i class="ti ti-plus me-1"></i>Aggiungi
                        </button>
                    </div>
                </div>
                <div class="table-responsive">
                    ${renderRulesTable(rulesOut, tunnelId, child.id, 'out')}
                </div>
            </div>
            
            <!-- Inbound Rules -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="ti ti-arrow-left me-1 text-green"></i>
                        Regole Inbound (${escapeHtml(child.remote_ts)} → ${escapeHtml(child.local_ts)})
                    </h3>
                    <div class="card-actions">
                        <button class="btn btn-primary btn-sm" onclick="showRuleModal('${tunnelId}', '${child.id}', 'in')">
                            <i class="ti ti-plus me-1"></i>Aggiungi
                        </button>
                    </div>
                </div>
                <div class="table-responsive">
                    ${renderRulesTable(rulesIn, tunnelId, child.id, 'in')}
                </div>
            </div>
        `;

        // Initialize Sortable.js for drag-and-drop (if available)
        if (typeof Sortable !== 'undefined') {
            const outTable = document.querySelector(`#rules-out-${child.id} tbody`);
            const inTable = document.querySelector(`#rules-in-${child.id} tbody`);

            if (outTable && rulesOut.length > 0) {
                new Sortable(outTable, {
                    animation: 150,
                    handle: '.drag-handle',
                    onEnd: () => reorderRules(tunnelId, child.id, 'out')
                });
            }

            if (inTable && rulesIn.length > 0) {
                new Sortable(inTable, {
                    animation: 150,
                    handle: '.drag-handle',
                    onEnd: () => reorderRules(tunnelId, child.id, 'in')
                });
            }
        }

    } catch (e) {
        container.innerHTML = `
            <div class="alert alert-danger">
                <i class="ti ti-alert-circle me-2"></i>
                Errore nel caricamento delle regole: ${escapeHtml(e.message)}
            </div>
        `;
    }
}

/**
 * Render rules table
 */
function renderRulesTable(rules, tunnelId, childId, direction) {
    if (rules.length === 0) {
        return `
            <div class="empty py-4">
                <p class="empty-title">Nessuna regola configurata</p>
                <p class="empty-subtitle text-muted">
                    Le regole permettono un controllo granulare del traffico
                </p>
            </div>
        `;
    }

    return `
        <table class="table table-vcenter card-table" id="rules-${direction}-${childId}">
            <thead>
                <tr>
                    <th width="40">#</th>
                    <th>Azione</th>
                    <th>Protocollo</th>
                    <th>Porta</th>
                    <th>Sorgente</th>
                    <th>Destinazione</th>
                    <th>Commento</th>
                    <th class="rule-actions"></th>
                </tr>
            </thead>
            <tbody>
                ${rules.map(rule => `
                    <tr data-rule-id="${rule.id}">
                        <td class="drag-handle" style="cursor: grab;">
                            <i class="ti ti-grip-vertical text-muted"></i>
                        </td>
                        <td>
                            <span class="badge ${rule.action === 'ACCEPT' ? 'bg-success-lt' : 'bg-danger-lt'}">
                                ${rule.action}
                            </span>
                        </td>
                        <td>${rule.protocol ? `<code>${escapeHtml(rule.protocol)}</code>` : '<span class="text-muted">tutti</span>'}</td>
                        <td>${rule.port ? `<code>${escapeHtml(rule.port)}</code>` : '-'}</td>
                        <td>${rule.source ? `<code>${escapeHtml(rule.source)}</code>` : '-'}</td>
                        <td>${rule.destination ? `<code>${escapeHtml(rule.destination)}</code>` : '-'}</td>
                        <td class="text-muted">${rule.description ? escapeHtml(rule.description) : '-'}</td>
                        <td class="rule-actions">
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-ghost-primary btn-edit" 
                                        onclick="editRule('${tunnelId}', '${childId}', '${rule.id}')" 
                                        title="Modifica">
                                    <i class="ti ti-edit"></i>
                                </button>
                                <button class="btn btn-ghost-danger btn-delete" 
                                        onclick="deleteRule('${tunnelId}', '${childId}', '${rule.id}')" 
                                        title="Elimina">
                                    <i class="ti ti-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

/**
 * Show rule modal for creating/editing
 */
window.showRuleModal = function (tunnelId, childId, direction = null, ruleId = null) {
    const modal = new bootstrap.Modal(document.getElementById('firewall-rule-modal'));
    const title = document.getElementById('modal-title');

    // Reset form
    document.getElementById('rule-id').value = ruleId || '';
    document.getElementById('rule-child-id').value = childId;
    document.getElementById('rule-direction').value = direction || 'out';
    document.getElementById('rule-action').value = 'ACCEPT';
    document.getElementById('rule-protocol').value = 'all';
    document.getElementById('rule-port').value = '';
    document.getElementById('rule-source').value = '';
    document.getElementById('rule-destination').value = '';
    document.getElementById('rule-description').value = '';
    document.getElementById('port-field').style.display = 'none';

    if (ruleId) {
        title.textContent = 'Modifica Regola Firewall';
        // Load rule data
        loadRuleData(tunnelId, childId, ruleId);
    } else {
        title.textContent = 'Aggiungi Regola Firewall';
    }

    modal.show();
};

/**
 * Load rule data for editing
 */
async function loadRuleData(tunnelId, childId, ruleId) {
    try {
        const rules = await apiGet(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}/firewall/rules`);
        const rule = rules.find(r => r.id === ruleId);

        if (rule) {
            document.getElementById('rule-direction').value = rule.direction;
            document.getElementById('rule-action').value = rule.action;
            document.getElementById('rule-protocol').value = rule.protocol;
            document.getElementById('rule-port').value = rule.port || '';
            document.getElementById('rule-source').value = rule.source || '';
            document.getElementById('rule-destination').value = rule.destination || '';
            document.getElementById('rule-description').value = rule.description;

            // Show port field if TCP/UDP
            if (['tcp', 'udp'].includes(rule.protocol)) {
                document.getElementById('port-field').style.display = 'block';
            }
        }
    } catch (e) {
        showToast('Errore nel caricamento della regola', 'error');
    }
}

/**
 * Save rule (create or update)
 */
async function saveRule() {
    const tunnelId = currentTunnel.id;
    const childId = document.getElementById('rule-child-id').value;
    const ruleId = document.getElementById('rule-id').value;

    const data = {
        child_sa_id: childId,
        direction: document.getElementById('rule-direction').value,
        action: document.getElementById('rule-action').value,
        protocol: document.getElementById('rule-protocol').value,
        port: document.getElementById('rule-port').value || null,
        source: document.getElementById('rule-source').value || null,
        destination: document.getElementById('rule-destination').value || null,
        description: document.getElementById('rule-description').value
    };

    try {
        if (ruleId) {
            // Update
            await apiPatch(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}/firewall/rules/${ruleId}`, data);
            showToast('Regola aggiornata', 'success');
        } else {
            // Create
            await apiPost(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}/firewall/rules`, data);
            showToast('Regola creata', 'success');
        }

        // Close modal and reload
        bootstrap.Modal.getInstance(document.getElementById('firewall-rule-modal')).hide();

        const child = currentChildren.find(c => c.id === childId);
        loadChildFirewall(tunnelId, child);

    } catch (e) {
        showToast(e.message, 'error');
    }
}

/**
 * Edit rule
 */
window.editRule = function (tunnelId, childId, ruleId) {
    showRuleModal(tunnelId, childId, null, ruleId);
};

/**
 * Delete rule
 */
window.deleteRule = async function (tunnelId, childId, ruleId) {
    const confirmed = await confirmDialog(
        'Elimina Regola',
        'Sei sicuro di voler eliminare questa regola firewall?',
        'Elimina',
        'btn-danger'
    );

    if (confirmed) {
        try {
            await apiDelete(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}/firewall/rules/${ruleId}`);
            showToast('Regola eliminata', 'success');

            const child = currentChildren.find(c => c.id === childId);
            loadChildFirewall(tunnelId, child);
        } catch (e) {
            showToast(e.message, 'error');
        }
    }
};

/**
 * Reorder rules after drag-and-drop
 */
async function reorderRules(tunnelId, childId, direction) {
    const table = document.querySelector(`#rules-${direction}-${childId} tbody`);
    const rows = Array.from(table.querySelectorAll('tr[data-rule-id]'));

    const rulesOrder = rows.map((row, index) => ({
        id: row.dataset.ruleId,
        order: index
    }));

    try {
        await apiPut(
            `/modules/strongswan/tunnels/${tunnelId}/children/${childId}/firewall/rules/order`,
            { rules: rulesOrder }
        );
        showToast('Ordine aggiornato', 'success');
    } catch (e) {
        showToast('Errore nell\'aggiornamento dell\'ordine', 'error');
        // Reload to restore correct order
        const child = currentChildren.find(c => c.id === childId);
        loadChildFirewall(tunnelId, child);
    }
}

/**
 * Toggle default policy
 */
window.togglePolicy = async function (tunnelId, childId, isAccept, type) {
    const policy = isAccept ? 'ACCEPT' : 'DROP';
    const payload = type === 'out' ? { policy_out: policy } : { policy_in: policy };

    try {
        await apiPatch(
            `/modules/strongswan/tunnels/${tunnelId}/children/${childId}/firewall/policy`,
            payload
        );

        const label = document.getElementById(`policy-${type}-label-${childId}`);
        label.textContent = policy;
        label.className = isAccept ? 'text-success' : 'text-danger';

        const typeLabel = type === 'out' ? 'Outbound' : 'Inbound';
        showToast(`Policy ${typeLabel} impostata su ${policy}`, 'success');
    } catch (e) {
        showToast(e.message, 'error');
        // Revert checkbox
        document.getElementById(`policy-${type}-${childId}`).checked = !isAccept;
    }
};
