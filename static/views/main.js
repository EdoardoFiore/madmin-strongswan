/**
 * IPsec VPN Module - Main Entry Point
 * 
 * Routes between list and detail views based on URL hash.
 */

import { checkPermission } from '/static/js/app.js';
import { renderTunnelList } from '/static/modules/strongswan/views/tunnelList.js';
import { renderTunnelDetail } from '/static/modules/strongswan/views/tunnelDetail.js';

// Cache permissions
let permissions = {
    view: false,
    manage: false
};

export async function render(container, params) {
    // Check permissions
    permissions = {
        view: checkPermission('ipsec.view'),
        manage: checkPermission('ipsec.manage')
    };

    // Route based on params
    if (params && params.length > 0) {
        // Detail view: #strongswan/{tunnelId}
        const tunnelId = params[0];
        await renderTunnelDetail(container, tunnelId, permissions);
    } else {
        // List view: #strongswan
        await renderTunnelList(container, permissions);
    }
}
