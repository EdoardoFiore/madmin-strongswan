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
                            <div class="card-header py-2">
                                <h6 class="card-title mb-0">Phase 1 Proposal</h6>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Encryption</label>
                                        <select class="form-select" id="tunnel-encryption">
                                            ${selectOptions(getEncryptionOptions(ikeVersion), proposal.enc)}
                                        </select>
                                    </div>
                                    <div class="col-md-6 mb-3" id="integrity-container">
                                        <label class="form-label">Authentication/Integrity</label>
                                        <select class="form-select" id="tunnel-integrity">
                                            ${selectOptions(CRYPTO_OPTIONS.integrity.common, proposal.integ || 'sha256')}
                                        </select>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Diffie-Hellman Group</label>
                                        <select class="form-select" id="tunnel-dh">
                                            ${selectOptions(getDhGroups(ikeVersion), proposal.dh || 'modp2048')}
                                        </select>
                                    </div>
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

    // IKE version change - update options
    document.querySelectorAll('input[name="tunnel-ike"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const version = e.target.value;
            updateIkeVersionOptions(version);
        });
    });

    // Encryption change - hide integrity for AEAD
    document.getElementById('tunnel-encryption')?.addEventListener('change', (e) => {
        updateIntegrityVisibility(e.target.value);
    });

    // Initial integrity visibility check
    updateIntegrityVisibility(document.getElementById('tunnel-encryption')?.value);

    // Save button
    document.getElementById('btn-save-tunnel')?.addEventListener('click', saveTunnel);
}

function updateIkeVersionOptions(version) {
    // Show/hide IKEv1 mode
    const modeContainer = document.getElementById('ikev1-mode-container');
    if (modeContainer) {
        modeContainer.style.display = version === '1' ? '' : 'none';
    }

    // Update encryption options (default: aes256)
    const encSelect = document.getElementById('tunnel-encryption');
    if (encSelect) {
        const currentEnc = encSelect.value;
        encSelect.innerHTML = selectOptions(getEncryptionOptions(version), currentEnc || 'aes256');
    }

    // Update integrity/authentication options (default: sha256)
    const integSelect = document.getElementById('tunnel-integrity');
    if (integSelect) {
        const currentInteg = integSelect.value;
        integSelect.innerHTML = selectOptions(CRYPTO_OPTIONS.integrity.common, currentInteg || 'sha256');
    }

    // Update DH dropdown options (default: modp2048)
    const dhSelect = document.getElementById('tunnel-dh');
    if (dhSelect) {
        const currentDh = dhSelect.value;
        dhSelect.innerHTML = selectOptions(getDhGroups(version), currentDh || 'modp2048');
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
    const encryption = document.getElementById('tunnel-encryption').value;
    const integrity = document.getElementById('tunnel-integrity').value;
    const dhGroup = document.getElementById('tunnel-dh').value;
    const lifetime = parseInt(document.getElementById('tunnel-lifetime').value) || 86400;

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

    // Build proposal string
    const proposal = buildProposal(encryption, integrity, dhGroup);

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
