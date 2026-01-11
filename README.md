# IPsec VPN Manager Module

Site-to-Site IPsec VPN management with strongSwan, IKEv1/IKEv2 support, and FortiGate-style configuration.

## Features

- **Multiple Tunnels**: Create and manage multiple IPsec tunnels simultaneously
- **Multiple Phase 2 (Child SA)**: Each tunnel can have multiple Child SAs for different traffic selectors
- **IKEv1/IKEv2 Support**: Full support for both IKE versions
- **VICI API Integration**: Real-time tunnel status via strongSwan's VICI protocol
- **Automatic Firewall Rules**: IPsec traffic rules (UDP 500, 4500, ESP) and FORWARD rules for traffic selectors
- **FortiGate-style UI**: Intuitive interface with hierarchical tunnel/Phase 2 display

## Requirements

- Debian/Ubuntu Linux server
- strongSwan with swanctl (modern configuration)
- MADMIN core

## Installation

Install via the MADMIN Module Store:

1. Navigate to **Store** > **IPsec VPN Manager**
2. Click **Install**
3. The module will automatically:
   - Install strongswan packages (`strongswan`, `strongswan-swanctl`, `strongswan-pki`)
   - Install Python VICI library
   - Create database tables
   - Configure system (IP forwarding, swanctl directories)

## Usage

### Creating a Tunnel

1. Go to **IPsec VPN** in the sidebar
2. Click **+ Nuovo Tunnel**
3. Configure Phase 1 (IKE SA):
   - Name: Unique tunnel identifier
   - IKE Version: IKEv1 or IKEv2
   - Local/Remote Gateway: IP addresses
   - PSK: Pre-Shared Key
   - IKE Proposal: Encryption + Integrity + DH Group
4. Click **Crea Tunnel**

### Adding Phase 2 (Child SA)

1. Expand the tunnel by clicking the chevron
2. Click **+ Aggiungi Phase 2**
3. Configure:
   - Name: Phase 2 identifier
   - Local/Remote Subnet: CIDR notation (e.g., `192.168.1.0/24`)
   - Start Action: How the tunnel initiates
   - Close Action: What to do when the tunnel closes

### Managing Tunnels

- **Start**: Click the play button to initiate the tunnel
- **Stop**: Click the stop button to terminate the tunnel
- **Edit**: Click the edit button to modify settings
- **Delete**: Click the trash button to remove the tunnel

## Configuration Files

The module generates configuration files in `/etc/swanctl/conf.d/`:

- `madmin_{tunnel_name}.conf` - Tunnel configuration
- `madmin_secrets.conf` - PSK secrets (mode 600)

## Firewall Integration

The module creates firewall chains:

- `MOD_IPSEC_INPUT`: Allows IKE (UDP 500), NAT-T (UDP 4500), and ESP
- `MOD_IPSEC_FORWARD`: Allows traffic between local and remote subnets
- `MOD_IPSEC_NAT`: NAT rules if needed

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/modules/strongswan/tunnels` | GET | List all tunnels |
| `/api/modules/strongswan/tunnels` | POST | Create tunnel |
| `/api/modules/strongswan/tunnels/{id}` | GET | Get tunnel details |
| `/api/modules/strongswan/tunnels/{id}` | PUT | Update tunnel |
| `/api/modules/strongswan/tunnels/{id}` | DELETE | Delete tunnel |
| `/api/modules/strongswan/tunnels/{id}/start` | POST | Start tunnel |
| `/api/modules/strongswan/tunnels/{id}/stop` | POST | Stop tunnel |
| `/api/modules/strongswan/tunnels/{id}/status` | GET | Get real-time status |
| `/api/modules/strongswan/tunnels/{id}/children` | GET | List Child SAs |
| `/api/modules/strongswan/tunnels/{id}/children` | POST | Add Child SA |
| `/api/modules/strongswan/tunnels/{id}/children/{cid}` | PUT | Update Child SA |
| `/api/modules/strongswan/tunnels/{id}/children/{cid}` | DELETE | Delete Child SA |

## License

MIT License - MADMIN Team
