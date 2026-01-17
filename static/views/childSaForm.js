/**
 * IPsec VPN Module - Child SA Form (Phase 2)
 * 
 * Inline form for creating Phase 2 selectors with advanced options.
 */

import {
    apiPost, apiPut, showToast, escapeHtml,
    CRYPTO_OPTIONS, selectOptions, parseProposal
} from '/static/modules/strongswan/views/utils.js';

// Custom CSS for rounded inputs
const formStyles = `
<style>
.phase2-form .form-control,
.phase2-form .form-select {
    border-radius: 6px;
}
.phase2-form .form-control-sm,
.phase2-form .form-select-sm {
    border-radius: 5px;
}
.crypto-group {
    max-height: 150px;
    overflow-y: auto;
    border: 1px solid #e2e8f0;
    padding: 8px;
    border-radius: 4px;
    background: #fff;
}
</style>
`;

// CIDR notation validator
function isValidCidr(value) {
    if (!value) return false;

    // Match IPv4 CIDR: x.x.x.x/y
    const cidrRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
    const match = value.match(cidrRegex);

    if (!match) {
        // Also allow single IP (will be treated as /32)
        const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const ipMatch = value.match(ipRegex);
        if (ipMatch) {
            // Check octets
            for (let i = 1; i <= 4; i++) {
                const octet = parseInt(ipMatch[i], 10);
                if (octet < 0 || octet > 255) return false;
            }
            return true;
        }
        return false;
    }

    // Check octets (0-255)
    for (let i = 1; i <= 4; i++) {
        const octet = parseInt(match[i], 10);
        if (octet < 0 || octet > 255) return false;
    }

    // Check prefix (0-32)
    const prefix = parseInt(match[5], 10);
    if (prefix < 0 || prefix > 32) return false;

    return true;
}

// Counter for unique proposal pair IDs
let proposalPairCounter = 0;

// Render a single proposal pair row
function renderProposalPair(index, enc = 'aes256', integ = 'sha256') {
    const id = proposalPairCounter++;
    return `
        <div class="row g-2 mb-2 proposal-pair" data-pair-id="${id}">
            <div class="col-5">
                <select class="form-select form-select-sm proposal-enc">
                    ${selectOptions(CRYPTO_OPTIONS.encryption.common, enc)}
                </select>
            </div>
            <div class="col-5">
                <select class="form-select form-select-sm proposal-integ">
                    ${selectOptions(CRYPTO_OPTIONS.integrity.common, integ)}
                </select>
            </div>
            <div class="col-2 d-flex align-items-center">
                ${index > 0 ? `
                    <button type="button" class="btn btn-sm btn-outline-danger btn-remove-proposal" data-pair-id="${id}">
                        <i class="ti ti-trash"></i>
                    </button>
                ` : '<span class="text-muted small">Primario</span>'}
            </div>
        </div>
    `;
}

export function renderChildSaForm(tunnelId, onSave, initialData = null) {
    const isEdit = !!initialData;
    const data = initialData || {};

    // Parse existing proposal or default
    const proposal = parseProposal(data.esp_proposal);
    // proposal returns { enc: [], integ: [], dh: [] }

    // Ensure arrays
    const selEnc = Array.isArray(proposal.enc) ? proposal.enc : [proposal.enc];
    const selInteg = Array.isArray(proposal.integ) ? proposal.integ : [proposal.integ];
    const selDh = Array.isArray(proposal.dh) ? proposal.dh : [proposal.dh];

    return `
        ${formStyles}
        <div class="card bg-light phase2-form" id="new-phase2-form">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
                <h6 class="card-title mb-0">
                    <i class="ti ti-${isEdit ? 'edit' : 'plus'} me-1"></i>${isEdit ? 'Modifica' : 'Nuova'} Phase 2
                </h6>
                <div class="btn-group btn-group-sm">
                    <button type="button" class="btn btn-success btn-save-phase2" 
                            data-tunnel="${tunnelId}" data-id="${data.id || ''}">
                        <i class="ti ti-check"></i>
                    </button>
                    <button type="button" class="btn btn-secondary btn-cancel-phase2">
                        <i class="ti ti-x"></i>
                    </button>
                </div>
            </div>
            <div class="card-body py-3">
                <!-- Basic Options -->
                <div class="row g-2 mb-3">
                    <div class="col-md-4">
                        <label class="form-label small mb-1">Nome *</label>
                        <input type="text" class="form-control form-control-sm" id="phase2-name" 
                               value="${escapeHtml(data.name || '')}" placeholder="es. LAN-to-LAN" required>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small mb-1">Local Subnet *</label>
                        <input type="text" class="form-control form-control-sm" id="phase2-local" 
                               value="${escapeHtml(data.local_ts || '')}" placeholder="192.168.1.0/24" required>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small mb-1">Remote Subnet *</label>
                        <input type="text" class="form-control form-control-sm" id="phase2-remote" 
                               value="${escapeHtml(data.remote_ts || '')}" placeholder="10.0.0.0/24" required>
                    </div>
                </div>
                
                <!-- Advanced Toggle -->
                <div class="mb-2">
                    <a class="text-muted small" data-bs-toggle="collapse" href="#phase2-advanced" role="button" aria-expanded="true">
                        <i class="ti ti-settings me-1"></i>Opzioni Avanzate (Crittografia Multipla)
                    </a>
                </div>
                
                <!-- Advanced Options -->
                <div class="collapse show" id="phase2-advanced">
                    <div class="card card-body bg-white py-3">
                        <!-- ESP Proposal Pairs -->
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="small text-muted mb-0">Phase 2 Proposal (ESP)</h6>
                            <button type="button" class="btn btn-sm btn-outline-primary" id="btn-add-proposal">
                                <i class="ti ti-plus"></i> Aggiungi Proposal
                            </button>
                        </div>
                        
                        <div id="proposal-pairs-container">
                            ${renderProposalPair(0, selEnc[0] || 'aes256', selInteg[0] || 'sha256')}
                        </div>
                        
                        <div class="row g-2 mb-3 mt-2">
                            <div class="col-md-6">
                                <label class="form-label small mb-1">PFS Group</label>
                                <select class="form-select form-select-sm" id="phase2-pfs">
                                    <option value="">Nessuno (No PFS)</option>
                                    ${selectOptions(CRYPTO_OPTIONS.pfsGroups, selDh[0] || 'modp2048')}
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label small mb-1">Key Lifetime (sec)</label>
                                <input type="number" class="form-control form-control-sm" id="phase2-lifetime" 
                                       value="${data.esp_lifetime || 43200}" min="300" max="172800">
                            </div>
                        </div>

                        <!-- Actions -->
                        <h6 class="small text-muted mb-2">Connection Actions</h6>
                        <div class="row g-2">
                            <div class="col-md-6">
                                <label class="form-label small mb-1">Start Action</label>
                                <select class="form-select form-select-sm" id="phase2-start">
                                    ${selectOptions(CRYPTO_OPTIONS.startAction, data.start_action || 'trap')}
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label small mb-1">Close Action</label>
                                <select class="form-select form-select-sm" id="phase2-close">
                                    ${selectOptions(CRYPTO_OPTIONS.closeAction, data.close_action || 'restart')}
                                </select>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

export function setupChildSaFormEvents(tunnelId, onSave) {
    // Save Phase 2
    document.querySelector('.btn-save-phase2')?.addEventListener('click', async (e) => {
        const btn = e.target.closest('.btn-save-phase2');
        const childId = btn.dataset.id; // Empty if new

        const name = document.getElementById('phase2-name').value.trim();
        const localTs = document.getElementById('phase2-local').value.trim();
        const remoteTs = document.getElementById('phase2-remote').value.trim();

        // Reset validation state
        document.getElementById('phase2-local').classList.remove('is-invalid');
        document.getElementById('phase2-remote').classList.remove('is-invalid');

        if (!name || !localTs || !remoteTs) {
            showToast('Compila tutti i campi obbligatori', 'error');
            return;
        }

        // CIDR validation
        if (!isValidCidr(localTs)) {
            document.getElementById('phase2-local').classList.add('is-invalid');
            showToast('Local Subnet non è un CIDR valido (es. 192.168.1.0/24)', 'error');
            return;
        }

        if (!isValidCidr(remoteTs)) {
            document.getElementById('phase2-remote').classList.add('is-invalid');
            showToast('Remote Subnet non è un CIDR valido (es. 10.0.0.0/24)', 'error');
            return;
        }

        // Build ESP proposal from all pairs
        const pairs = document.querySelectorAll('.proposal-pair');
        const pfsGroup = document.getElementById('phase2-pfs').value;
        const proposals = [];

        pairs.forEach(pair => {
            const enc = pair.querySelector('.proposal-enc').value;
            const integ = pair.querySelector('.proposal-integ').value;
            let proposal = `${enc}-${integ}`;
            if (pfsGroup) {
                proposal += `-${pfsGroup}`;
            }
            proposals.push(proposal);
        });

        // Join proposals with comma for strongswan format
        const espProposal = proposals.join(',');

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

        const payload = {
            name,
            local_ts: localTs,
            remote_ts: remoteTs,
            esp_proposal: espProposal,
            esp_lifetime: parseInt(document.getElementById('phase2-lifetime')?.value) || 43200,
            pfs_group: pfsGroup || null,
            start_action: document.getElementById('phase2-start')?.value || 'trap',
            close_action: document.getElementById('phase2-close')?.value || 'restart'
        };

        try {
            if (childId) {
                // UPDATE
                // Note: using PUT as per router definition
                await apiPut(`/modules/strongswan/tunnels/${tunnelId}/children/${childId}`, payload);
                showToast('Phase 2 aggiornata', 'success');
            } else {
                // CREATE
                await apiPost(`/modules/strongswan/tunnels/${tunnelId}/children`, payload);
                showToast('Phase 2 creata', 'success');
            }
            if (onSave) onSave();
        } catch (err) {
            showToast(err.message, 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-check"></i>';
        }
    });

    // Cancel
    document.querySelector('.btn-cancel-phase2')?.addEventListener('click', () => {
        document.getElementById('new-phase2-form')?.remove();
        document.getElementById('btn-add-phase2')?.classList.remove('d-none');
        // If editing row-inline, we might need logic to unhide row? 
        // For now form is separate block.
    });

    // Add new proposal pair
    document.getElementById('btn-add-proposal')?.addEventListener('click', () => {
        const container = document.getElementById('proposal-pairs-container');
        if (container) {
            const pairCount = container.querySelectorAll('.proposal-pair').length;
            container.insertAdjacentHTML('beforeend', renderProposalPair(pairCount, 'aes128', 'sha256'));
        }
    });

    // Remove proposal pair (event delegation)
    document.getElementById('proposal-pairs-container')?.addEventListener('click', (e) => {
        const removeBtn = e.target.closest('.btn-remove-proposal');
        if (removeBtn) {
            const pairId = removeBtn.dataset.pairId;
            const pair = document.querySelector(`.proposal-pair[data-pair-id="${pairId}"]`);
            pair?.remove();
        }
    });
}
