/**
 * IPsec VPN Module - Tunnel Form (Phase 1)
 * 
 * FortiGate-style modal for creating/editing IPsec tunnels.
 * Sections: General, Network, Authentication, Phase 1 Proposal
 */

import {
    apiPost, apiPatch, showToast, escapeHtml,
    CRYPTO_OPTIONS, getEncryptionOptions, getDhGroups,
    buildProposal, parseProposal, selectOptions
} from '/static/modules/strongswan/views/utils.js';

let currentTunnel = null;
let onSaveCallback = null;
let modal = null;
let p1ProposalCounter = 0;

// Render DH group checkboxes
function renderDhCheckboxes(version, selectedGroups = []) {
    const groups = getDhGroups(version);
    return groups.map(g => `
        <div class="form-check form-check-inline">
            <input class="form-check-input dh-checkbox" type="checkbox" 
                   value="${g.value}" id="dh-${g.value}" 
                   ${selectedGroups.includes(g.value) ? 'checked' : ''}>
            <label class="form-check-label small" for="dh-${g.value}">${g.label}</label>
        </div>
    `).join('');
}

// Render a Phase 1 proposal pair row
function renderP1ProposalPair(idx, version, enc = 'aes256', integ = 'sha256') {
    const id = p1ProposalCounter++;
    return `
        <div class="row g-2 mb-2 p1-proposal-pair" data-pair-id="${id}">
            <div class="col-5">
                ${idx === 0 ? '<label class="form-label small">Encryption</label>' : ''}
                <select class="form-select form-select-sm p1-enc">
                    ${selectOptions(getEncryptionOptions(version), enc)}
                </select>
            </div>
            <div class="col-5">
                ${idx === 0 ? '<label class="form-label small">Authentication</label>' : ''}
                <select class="form-select form-select-sm p1-integ">
                    ${selectOptions(CRYPTO_OPTIONS.integrity.common, integ)}
                </select>
            </div>
            <div class="col-2 d-flex align-items-${idx === 0 ? 'end' : 'center'}">
                ${idx > 0 ? `
                    <button type="button" class="btn btn-sm btn-outline-danger btn-remove-p1-proposal" data-pair-id="${id}">
                        <i class="ti ti-trash"></i>
                    </button>
                ` : '<span class="text-muted small mb-2">Primario</span>'}
            </div>
        </div>
    `;
}

// Render all proposal pairs (for edit mode)
function renderAllP1Proposals(version, pairs) {
    if (!pairs || pairs.length === 0) {
        return renderP1ProposalPair(0, version, 'aes256', 'sha256');
    }
    return pairs.map((pair, idx) =>
        renderP1ProposalPair(idx, version, pair.enc || 'aes256', pair.integ || 'sha256')
    ).join('');
}

// Get selected DH groups from checkboxes
function getSelectedDhGroups() {
    const checkboxes = document.querySelectorAll('.dh-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

export function showTunnelForm(tunnel, onSave) {
    currentTunnel = tunnel;
    onSaveCallback = onSave;
    const isEdit = !!tunnel;
    const ikeVersion = tunnel?.ike_version || '2';
    const proposal = parseProposal(tunnel?.ike_proposal);

    // Create modal if not exists
    let modalEl = document.getElementById('modal-tunnel-form');
    if (!modalEl) {
        modalEl = document.createElement('div');
        modalEl.id = 'modal-tunnel-form';
        modalEl.className = 'modal fade';
        modalEl.tabIndex = -1;
        document.body.appendChild(modalEl);
    }

    modalEl.innerHTML = `
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="ti ti-shield-lock me-2"></i>
                        ${isEdit ? 'Modifica Tunnel' : 'Nuovo Tunnel IPsec'}
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="form-tunnel">
                        <!-- General Section -->
                        <div class="card mb-3">
                            <div class="card-header py-2">
                                <h6 class="card-title mb-0">Generale</h6>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Nome *</label>
                                        <input type="text" class="form-control" id="tunnel-name" 
                                               value="${escapeHtml(tunnel?.name || '')}" 
                                               placeholder="es. VPN-Site-A" required>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Descrizione</label>
                                        <input type="text" class="form-control" id="tunnel-description" 
                                               value="${escapeHtml(tunnel?.description || '')}" 
                                               placeholder="Tunnel verso sede remota">
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Network Section -->
                        <div class="card mb-3">
                            <div class="card-header py-2">
                                <h6 class="card-title mb-0">Rete</h6>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Remote Gateway *</label>
                                        <input type="text" class="form-control" id="tunnel-remote" 
                                               value="${escapeHtml(tunnel?.remote_address || '')}" 
                                               placeholder="IP o hostname" required>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Local Gateway</label>
                                        <div class="input-group">
                                            <span class="input-group-text">
                                                <input type="checkbox" class="form-check-input m-0" 
                                                       id="tunnel-local-auto" ${!tunnel?.local_address ? 'checked' : ''}>
                                            </span>
                                            <input type="text" class="form-control" id="tunnel-local" 
                                                   value="${escapeHtml(tunnel?.local_address || '')}" 
                                                   placeholder="Auto-detect" ${!tunnel?.local_address ? 'disabled' : ''}>
                                        </div>
                                        <small class="form-hint">Seleziona per auto-detect (%any)</small>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <label class="form-label">NAT Traversal</label>
                                        <div class="btn-group w-100" role="group">
                                            <input type="radio" class="btn-check" name="tunnel-nat" id="nat-yes" value="yes" 
                                                   ${(tunnel?.nat_traversal !== false) ? 'checked' : ''}>
                                            <label class="btn btn-outline-primary" for="nat-yes">Enable</label>
                                            <input type="radio" class="btn-check" name="tunnel-nat" id="nat-no" value="no"
                                                   ${tunnel?.nat_traversal === false ? 'checked' : ''}>
                                            <label class="btn btn-outline-primary" for="nat-no">Disable</label>
                                        </div>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <label class="form-label">Dead Peer Detection</label>
                                        <select class="form-select" id="tunnel-dpd-action">
                                            ${selectOptions(CRYPTO_OPTIONS.dpdAction, tunnel?.dpd_action || 'restart')}
                                        </select>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <label class="form-label">DPD Interval (sec)</label>
                                        <input type="number" class="form-control" id="tunnel-dpd-delay" 
                                               value="${tunnel?.dpd_delay || 30}" min="5" max="300">
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Authentication Section -->
                        <div class="card mb-3">
                            <div class="card-header py-2">
                                <h6 class="card-title mb-0">Autenticazione</h6>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Metodo</label>
                                        <select class="form-select" id="tunnel-auth-method">
                                            <option value="psk" ${(tunnel?.auth_method || 'psk') === 'psk' ? 'selected' : ''}>
                                                Pre-shared Key
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-6 mb-3" id="psk-container">
                                        <label class="form-label">Pre-shared Key ${isEdit ? '' : '*'}</label>
                                        <div class="input-group">
                                            <input type="password" class="form-control" id="tunnel-psk" 
                                                   placeholder="${isEdit ? 'Lascia vuoto per mantenere' : 'Chiave condivisa'}"
                                                   ${isEdit ? '' : 'required'}>
                                            <button type="button" class="btn btn-outline-secondary" id="btn-toggle-psk">
                                                <i class="ti ti-eye"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Versione IKE</label>
                                        <div class="btn-group w-100" role="group">
                                            <input type="radio" class="btn-check" name="tunnel-ike" id="ike-1" value="1" 
                                                   ${ikeVersion === '1' ? 'checked' : ''}>
                                            <label class="btn btn-outline-primary" for="ike-1">IKEv1</label>
                                            <input type="radio" class="btn-check" name="tunnel-ike" id="ike-2" value="2"
                                                   ${ikeVersion !== '1' ? 'checked' : ''}>
                                            <label class="btn btn-outline-primary" for="ike-2">IKEv2</label>
                                        </div>
                                    </div>
                                    <div class="col-md-6 mb-3" id="ikev1-mode-container" ${ikeVersion !== '1' ? 'style="display:none"' : ''}>
                                        <label class="form-label">Mode (IKEv1)</label>
                                        <select class="form-select" id="tunnel-mode">
                                            <option value="main" ${(tunnel?.mode || 'main') === 'main' ? 'selected' : ''}>Main</option>
                                            <option value="aggressive" ${tunnel?.mode === 'aggressive' ? 'selected' : ''}>Aggressive</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Local ID (opzionale)</label>
                                        <input type="text" class="form-control" id="tunnel-local-id" 
                                               value="${escapeHtml(tunnel?.local_id || '')}" 
                                               placeholder="es. @vpn.example.com">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Remote ID (opzionale)</label>
                                        <input type="text" class="form-control" id="tunnel-remote-id" 
                                               value="${escapeHtml(tunnel?.remote_id || '')}" 
                                               placeholder="es. @peer.example.com">
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Phase 1 Proposal Section -->
                        <div class="card mb-3">
                            <div class="card-header py-2 d-flex justify-content-between align-items-center">
                                <h6 class="card-title mb-0">Phase 1 Proposal</h6>
                                <button type="button" class="btn btn-sm btn-outline-primary" id="btn-add-p1-proposal">
                                    <i class="ti ti-plus"></i> Add
                                </button>
                            </div>
                            <div class="card-body">
                                <!-- Dynamic Proposal Pairs Container -->
                                <div id="p1-proposals-container">
                                    ${renderAllP1Proposals(ikeVersion, proposal.pairs)}
                                </div>
                                
                                <!-- Diffie-Hellman Groups (Checkboxes) -->
                                <div class="mb-3 mt-3">
                                    <label class="form-label">Diffie-Hellman Group</label>
                                    <div id="dh-groups-container" class="d-flex flex-wrap gap-2">
                                        ${renderDhCheckboxes(ikeVersion, proposal.dh || ['modp2048'])}
                                    </div>
                                </div>
                                
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Key Lifetime (secondi)</label>
                                        <input type="number" class="form-control" id="tunnel-lifetime" 
                                               value="${tunnel?.ike_lifetime || 86400}" min="300" max="172800">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" id="btn-save-tunnel">
                        <i class="ti ti-check me-1"></i>${isEdit ? 'Salva' : 'Crea Tunnel'}
                    </button>
                </div>
            </div>
        </div>
    `;

    setupFormEvents();

    modal = new bootstrap.Modal(modalEl);
    modal.show();
}

function setupFormEvents() {
    // Toggle PSK visibility
    document.getElementById('btn-toggle-psk')?.addEventListener('click', () => {
        const input = document.getElementById('tunnel-psk');
        const icon = document.querySelector('#btn-toggle-psk i');
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'ti ti-eye-off';
        } else {
            input.type = 'password';
            icon.className = 'ti ti-eye';
        }
    });

    // Local gateway auto toggle
    document.getElementById('tunnel-local-auto')?.addEventListener('change', (e) => {
        const input = document.getElementById('tunnel-local');
        input.disabled = e.target.checked;
        if (e.target.checked) input.value = '';
    });

    // IKE version change - update all proposal options
    document.querySelectorAll('input[name="tunnel-ike"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const version = e.target.value;
            updateIkeVersionOptions(version);
        });
    });

    // Add Phase 1 proposal pair
    document.getElementById('btn-add-p1-proposal')?.addEventListener('click', () => {
        const container = document.getElementById('p1-proposals-container');
        const version = document.querySelector('input[name="tunnel-ike"]:checked')?.value || '2';
        const pairCount = container.querySelectorAll('.p1-proposal-pair').length;
        container.insertAdjacentHTML('beforeend', renderP1ProposalPair(pairCount, version, 'aes128', 'sha256'));
    });

    // Remove Phase 1 proposal pair (event delegation)
    document.getElementById('p1-proposals-container')?.addEventListener('click', (e) => {
        const removeBtn = e.target.closest('.btn-remove-p1-proposal');
        if (removeBtn) {
            const pairId = removeBtn.dataset.pairId;
            const pair = document.querySelector(`.p1-proposal-pair[data-pair-id="${pairId}"]`);
            pair?.remove();
        }
    });

    // Save button
    document.getElementById('btn-save-tunnel')?.addEventListener('click', saveTunnel);
}

function updateIkeVersionOptions(version) {
    // Show/hide IKEv1 mode
    const modeContainer = document.getElementById('ikev1-mode-container');
    if (modeContainer) {
        modeContainer.style.display = version === '1' ? '' : 'none';
    }

    // Update all encryption dropdowns in proposal pairs
    document.querySelectorAll('.p1-enc').forEach(select => {
        const currentVal = select.value;
        select.innerHTML = selectOptions(getEncryptionOptions(version), currentVal || 'aes256');
    });

    // Update all integrity dropdowns in proposal pairs
    document.querySelectorAll('.p1-integ').forEach(select => {
        const currentVal = select.value;
        select.innerHTML = selectOptions(CRYPTO_OPTIONS.integrity.common, currentVal || 'sha256');
    });

    // Update DH checkboxes
    const dhContainer = document.getElementById('dh-groups-container');
    if (dhContainer) {
        const selectedDh = getSelectedDhGroups();
        dhContainer.innerHTML = renderDhCheckboxes(version, selectedDh.length > 0 ? selectedDh : ['modp2048']);
    }
}

function updateIntegrityVisibility(encValue) {
    const isAead = CRYPTO_OPTIONS.encryption.ikev2Only?.some(e => e.value === encValue && e.aead);
    const container = document.getElementById('integrity-container');
    if (container) {
        container.style.display = isAead ? 'none' : '';
    }
}

async function saveTunnel() {
    const btn = document.getElementById('btn-save-tunnel');
    const isEdit = !!currentTunnel;

    // Gather form data
    const name = document.getElementById('tunnel-name').value.trim();
    const remoteAddress = document.getElementById('tunnel-remote').value.trim();
    const localAuto = document.getElementById('tunnel-local-auto').checked;
    const localAddress = localAuto ? '' : document.getElementById('tunnel-local').value.trim();
    const psk = document.getElementById('tunnel-psk').value;
    const ikeVersion = document.querySelector('input[name="tunnel-ike"]:checked')?.value || '2';
    const mode = document.getElementById('tunnel-mode').value;
    const natTraversal = document.querySelector('input[name="tunnel-nat"]:checked')?.value === 'yes';
    const dpdAction = document.getElementById('tunnel-dpd-action').value;
    const dpdDelay = parseInt(document.getElementById('tunnel-dpd-delay').value) || 30;
    const localId = document.getElementById('tunnel-local-id').value.trim() || null;
    const remoteId = document.getElementById('tunnel-remote-id').value.trim() || null;
    const lifetime = parseInt(document.getElementById('tunnel-lifetime').value) || 86400;

    // Collect proposal pairs (encryption + integrity)
    const proposalPairs = [];
    document.querySelectorAll('.p1-proposal-pair').forEach(pair => {
        const enc = pair.querySelector('.p1-enc')?.value || 'aes256';
        const integ = pair.querySelector('.p1-integ')?.value || 'sha256';
        proposalPairs.push({ enc, integ });
    });

    // Collect DH groups from checkboxes
    const dhGroups = getSelectedDhGroups();
    if (dhGroups.length === 0) {
        dhGroups.push('modp2048'); // Default if none selected
    }

    // Validation
    if (!name) {
        showToast('Inserisci un nome per il tunnel', 'error');
        return;
    }
    if (!remoteAddress) {
        showToast('Inserisci l\'indirizzo del remote gateway', 'error');
        return;
    }
    if (!isEdit && !psk) {
        showToast('Inserisci la Pre-shared Key', 'error');
        return;
    }

    // Build proposal string: enc-integ-dh,enc-integ-dh,...
    // For multiple DH, append each DH to first proposal pair
    const proposals = [];
    proposalPairs.forEach((pair, idx) => {
        if (idx === 0) {
            // First pair gets all DH groups
            dhGroups.forEach(dh => {
                proposals.push(buildProposal(pair.enc, pair.integ, dh));
            });
        } else {
            // Other pairs use first DH group
            proposals.push(buildProposal(pair.enc, pair.integ, dhGroups[0]));
        }
    });
    const proposal = proposals.join(',');

    const data = {
        name,
        remote_address: remoteAddress,
        local_address: localAddress || null,
        ike_version: ikeVersion,
        mode: ikeVersion === '1' ? mode : 'main',
        auth_method: 'psk',
        nat_traversal: natTraversal,
        dpd_action: dpdAction,
        dpd_delay: dpdDelay,
        local_id: localId,
        remote_id: remoteId,
        ike_proposal: proposal,
        ike_lifetime: lifetime
    };

    // Only include PSK if provided
    if (psk) {
        data.psk = psk;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Salvataggio...';

    try {
        if (isEdit) {
            await apiPatch(`/modules/strongswan/tunnels/${currentTunnel.id}`, data);
            showToast('Tunnel aggiornato', 'success');
        } else {
            await apiPost('/modules/strongswan/tunnels', data);
            showToast('Tunnel creato', 'success');
        }

        modal?.hide();
        if (onSaveCallback) onSaveCallback();

    } catch (err) {
        showToast(err.message, 'error');
        btn.disabled = false;
        btn.innerHTML = `<i class="ti ti-check me-1"></i>${isEdit ? 'Salva' : 'Crea Tunnel'}`;
    }
}
