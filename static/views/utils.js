/**
 * IPsec VPN Module - Shared Utilities
 * 
 * Crypto options, API helpers, and shared functions.
 */

import { apiGet, apiPost, apiDelete, apiPatch, apiPut } from '/static/js/api.js';
import { showToast, confirmDialog, escapeHtml } from '/static/js/utils.js';

// Re-export for convenience
export { apiGet, apiPost, apiDelete, apiPatch, apiPut, showToast, confirmDialog, escapeHtml };

// Status badge helper
export function statusBadge(status) {
    const classes = {
        'established': 'bg-success',
        'connecting': 'bg-warning',
        'disconnected': 'bg-secondary'
    };
    const labels = {
        'established': 'Connesso',
        'connecting': 'Connessione...',
        'disconnected': 'Disconnesso'
    };
    return `<span class="badge ${classes[status] || 'bg-secondary'}">${labels[status] || status}</span>`;
}

// Crypto options organized by IKE version
export const CRYPTO_OPTIONS = {
    encryption: {
        common: [
            { value: 'aes256', label: 'AES-256', security: 5 },
            { value: 'aes128', label: 'AES-128', security: 4 },
            { value: '3des', label: '3DES (Legacy)', security: 2, legacy: true }
        ],
        ikev2Only: [
            { value: 'aes256gcm16', label: 'AES-256-GCM', security: 5, aead: true },
            { value: 'aes128gcm16', label: 'AES-128-GCM', security: 5, aead: true },
            { value: 'chacha20poly1305', label: 'ChaCha20-Poly1305', security: 5, aead: true }
        ]
    },
    integrity: {
        common: [
            { value: 'sha256', label: 'SHA-256', security: 5 },
            { value: 'sha384', label: 'SHA-384', security: 5 },
            { value: 'sha512', label: 'SHA-512', security: 5 },
            { value: 'sha1', label: 'SHA-1 (Legacy)', security: 3, legacy: true }
        ]
    },
    dhGroups: {
        ikev1: [
            { value: 'modp768', label: 'Group 1 (768-bit)', number: 1, security: 1, legacy: true },
            { value: 'modp1024', label: 'Group 2 (1024-bit)', number: 2, security: 2, legacy: true },
            { value: 'modp1536', label: 'Group 5 (1536-bit)', number: 5, security: 3 },
            { value: 'modp2048', label: 'Group 14 (2048-bit)', number: 14, security: 4 },
            { value: 'modp3072', label: 'Group 15 (3072-bit)', number: 15, security: 5 },
            { value: 'modp4096', label: 'Group 16 (4096-bit)', number: 16, security: 5 },
            { value: 'modp6144', label: 'Group 17 (6144-bit)', number: 17, security: 5 },
            { value: 'modp8192', label: 'Group 18 (8192-bit)', number: 18, security: 5 }
        ],
        ikev2: [
            { value: 'modp2048', label: 'Group 14 (2048-bit)', number: 14, security: 4 },
            { value: 'modp3072', label: 'Group 15 (3072-bit)', number: 15, security: 5 },
            { value: 'modp4096', label: 'Group 16 (4096-bit)', number: 16, security: 5 },
            { value: 'modp6144', label: 'Group 17 (6144-bit)', number: 17, security: 5 },
            { value: 'modp8192', label: 'Group 18 (8192-bit)', number: 18, security: 5 },
            { value: 'ecp256', label: 'ECP-256 (Group 19)', number: 19, security: 5 },
            { value: 'ecp384', label: 'ECP-384 (Group 20)', number: 20, security: 5 },
            { value: 'ecp521', label: 'ECP-521 (Group 21)', number: 21, security: 5 },
            { value: 'curve25519', label: 'Curve25519 (Group 31)', number: 31, security: 5 }
        ]
    },
    dpdAction: [
        { value: 'restart', label: 'Restart' },
        { value: 'clear', label: 'Clear' },
        { value: 'none', label: 'Disabilita' }
    ],
    natTraversal: [
        { value: 'yes', label: 'Enable' },
        { value: 'no', label: 'Disable' },
        { value: 'force', label: 'Force' }
    ],
    startAction: [
        { value: 'start', label: 'Start (inizia subito)' },
        { value: 'trap', label: 'On Demand (trap)' },
        { value: 'none', label: 'Manual (none)' }
    ],
    closeAction: [
        { value: 'restart', label: 'Restart' },
        { value: 'trap', label: 'Hold (trap)' },
        { value: 'none', label: 'None' }
    ],
    // DH groups for PFS (Phase 2) - more standard/common groups
    pfsGroups: [
        { value: 'modp1024', label: 'Group 2 (1024-bit)', number: 2, security: 2, legacy: true },
        { value: 'modp1536', label: 'Group 5 (1536-bit)', number: 5, security: 3 },
        { value: 'modp2048', label: 'Group 14 (2048-bit)', number: 14, security: 4 },
        { value: 'modp3072', label: 'Group 15 (3072-bit)', number: 15, security: 5 },
        { value: 'modp4096', label: 'Group 16 (4096-bit)', number: 16, security: 5 },
        { value: 'ecp256', label: 'Group 19 (ECP-256)', number: 19, security: 5 },
        { value: 'ecp384', label: 'Group 20 (ECP-384)', number: 20, security: 5 }
    ]
};

// Get encryption options for IKE version
export function getEncryptionOptions(ikeVersion) {
    const options = [...CRYPTO_OPTIONS.encryption.common];
    if (ikeVersion === '2' || ikeVersion === 2) {
        options.unshift(...CRYPTO_OPTIONS.encryption.ikev2Only);
    }
    return options;
}

// Get DH groups for IKE version
export function getDhGroups(ikeVersion) {
    return ikeVersion === '1' || ikeVersion === 1
        ? CRYPTO_OPTIONS.dhGroups.ikev1
        : CRYPTO_OPTIONS.dhGroups.ikev2;
}

// Build proposal string from selections
export function buildProposal(enc, integ, dhGroup) {
    // AEAD ciphers don't need integrity
    const isAead = CRYPTO_OPTIONS.encryption.ikev2Only.some(e => e.value === enc && e.aead);
    return isAead ? `${enc}-${dhGroup}` : `${enc}-${integ}-${dhGroup}`;
}

// Parse proposal string to components (handling multiple proposals separated by comma)
export function parseProposal(proposal) {
    const result = {
        enc: ['aes256'],
        integ: ['sha256'],
        dh: ['modp2048'],
        pairs: [{ enc: 'aes256', integ: 'sha256' }]  // Array of enc+integ pairs
    };

    if (!proposal) return result;

    const allEnc = [
        ...CRYPTO_OPTIONS.encryption.common,
        ...CRYPTO_OPTIONS.encryption.ikev2Only
    ].map(o => o.value);

    const allInteg = CRYPTO_OPTIONS.integrity.common.map(o => o.value);

    const allDh = [
        ...CRYPTO_OPTIONS.dhGroups.ikev1,
        ...CRYPTO_OPTIONS.dhGroups.ikev2
    ].map(o => o.value);

    const encSet = new Set();
    const integSet = new Set();
    const dhSet = new Set();
    const pairs = [];

    // Split by comma for multiple proposals
    const proposals = proposal.split(',').map(p => p.trim()).filter(p => p);

    proposals.forEach(singleProposal => {
        const parts = singleProposal.split('-').filter(p => p);

        let pairEnc = null;
        let pairInteg = null;

        parts.forEach(p => {
            if (allEnc.includes(p)) {
                encSet.add(p);
                if (!pairEnc) pairEnc = p;
            } else if (allInteg.includes(p)) {
                integSet.add(p);
                if (!pairInteg) pairInteg = p;
            } else if (allDh.includes(p)) {
                dhSet.add(p);
            } else if (p === 'aes256' || p === 'aes128' || p === '3des') {
                encSet.add(p);
                if (!pairEnc) pairEnc = p;
            } else if (p === 'sha256' || p === 'sha1' || p === 'md5') {
                integSet.add(p);
                if (!pairInteg) pairInteg = p;
            }
        });

        // Add pair if we found enc/integ
        if (pairEnc || pairInteg) {
            pairs.push({
                enc: pairEnc || 'aes256',
                integ: pairInteg || 'sha256'
            });
        }
    });

    // Convert sets to arrays
    result.enc = encSet.size > 0 ? Array.from(encSet) : ['aes256'];
    result.integ = integSet.size > 0 ? Array.from(integSet) : ['sha256'];
    result.dh = dhSet.size > 0 ? Array.from(dhSet) : ['modp2048'];
    result.pairs = pairs.length > 0 ? pairs : [{ enc: 'aes256', integ: 'sha256' }];

    return result;
}

// Create select options HTML
export function selectOptions(options, selectedValue) {
    return options.map(o =>
        `<option value="${o.value}" ${o.value === selectedValue ? 'selected' : ''}>${o.label}</option>`
    ).join('');
}

// Generic Checkbox Group
export function renderCheckboxGroup(cls, options, selectedValues = [], inline = false) {
    return options.map(o => `
        <div class="form-check ${inline ? 'form-check-inline' : 'mb-1'}">
            <input class="form-check-input ${cls}" type="checkbox" 
                   id="${cls}-${o.value}" value="${o.value}"
                   ${selectedValues.includes(o.value) ? 'checked' : ''}>
            <label class="form-check-label small" for="${cls}-${o.value}">${o.label}</label>
        </div>
    `).join('');
}

// Get selected values from checkboxes
export function getSelectedValues(cls) {
    const checked = document.querySelectorAll(`.${cls}:checked`);
    return Array.from(checked).map(cb => cb.value);
}

// Legacy wrappers for compatibility (if needed) or direct replacement
export function pfsCheckboxes(selectedValues = ['modp2048']) {
    return renderCheckboxGroup('pfs-checkbox', CRYPTO_OPTIONS.pfsGroups, selectedValues, true);
}

export function getSelectedPfsGroups() {
    return getSelectedValues('pfs-checkbox');
}

// DH checkboxes for Phase 1 (version-specific)
export function dhCheckboxes(version, selectedValues = ['modp2048']) {
    const groups = getDhGroups(version);
    return groups.map(g => `
        <div class="form-check form-check-inline">
            <input class="form-check-input dh-checkbox" type="checkbox" 
                   id="dh-${g.value}" value="${g.value}"
                   ${selectedValues.includes(g.value) ? 'checked' : ''}>
            <label class="form-check-label small" for="dh-${g.value}">${g.label}</label>
        </div>
    `).join('');
}

export function getSelectedDhGroups() {
    return getSelectedValues('dh-checkbox');
}

// Loading spinner
export function loadingSpinner() {
    return `<div class="text-center py-4">
        <div class="spinner-border spinner-border-sm text-primary"></div>
        <p class="text-muted small mt-2">Caricamento...</p>
    </div>`;
}

// Empty state
export function emptyState(icon, title, description = '') {
    return `<div class="text-center py-5 text-muted">
        <i class="ti ti-${icon}" style="font-size: 3rem;"></i>
        <p class="mt-2 mb-0">${title}</p>
        ${description ? `<small>${description}</small>` : ''}
    </div>`;
}
