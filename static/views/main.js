/**
 * IPsec VPN Module - Frontend Entry Point
 * 
 * Registers and initializes the IPsec VPN module with MADMIN.
 */

// Module definition for MADMIN dynamic loading
window.MADMIN_MODULE = {
    id: 'strongswan',
    name: 'IPsec VPN',
    version: '0.1.0',

    // Initialize module
    init: function () {
        console.log('[IPsec] Module initialized');
    },

    // Render module content
    render: function (container) {
        // Load the main app
        if (typeof IPsecApp !== 'undefined') {
            IPsecApp.render(container);
        } else {
            // Load app.js dynamically
            const script = document.createElement('script');
            script.src = '/static/modules/strongswan/views/app.js';
            script.onload = function () {
                if (typeof IPsecApp !== 'undefined') {
                    IPsecApp.render(container);
                }
            };
            document.head.appendChild(script);
        }
    },

    // Cleanup on module unload
    destroy: function () {
        console.log('[IPsec] Module destroyed');
    }
};
