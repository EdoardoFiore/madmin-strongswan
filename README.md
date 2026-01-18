# IPsec VPN Manager Module

Site-to-Site IPsec VPN management with strongSwan, IKEv1/IKEv2 support, per-Child-SA firewall, and FortiGate-style configuration.

## Features

- **Multiple Tunnels**: Create and manage multiple IPsec tunnels simultaneously
- **Multiple Phase 2 (Child SA)**: Each tunnel can have multiple Child SAs for different traffic selectors
- **IKEv1/IKEv2 Support**: Full support for both IKE versions
- **VICI API Integration**: Real-time tunnel status via strongSwan's VICI protocol
- **Per-Child-SA Firewall**: Granular firewall rules for each Phase 2 with separate IN/OUT policies
- **Traffic Statistics**: Real-time and historical traffic monitoring with charts
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

### Managing Firewall Rules

Each Child SA has its own firewall with separate Inbound and Outbound policies:

1. Click on a tunnel to expand it
2. Go to the **Firewall** tab
3. Select a Child SA from the tabs
4. For each direction (Outbound/Inbound):
   - Set **Default Policy**: ACCEPT (green) or DROP (red)
   - Add specific rules with protocol, source, destination, port
   - Drag rules to reorder priority
5. Rules are applied immediately to iptables

**Chain Structure:**
- `IPSEC_{TunnelName}_{N}_OUT` - Outbound rules (local → remote)
- `IPSEC_{TunnelName}_{N}_IN` - Inbound rules (remote → local)

### Managing Tunnels

- **Start**: Click the play button to initiate the tunnel
- **Stop**: Click the stop button to terminate the tunnel
- **Edit**: Click the edit button to modify settings
- **Delete**: Click the trash button to remove the tunnel

### Traffic Statistics

1. Click on a tunnel to view its details
2. Go to the **Statistiche** tab
3. View real-time traffic graphs with period selection (1h, 6h, 24h, 7d)

## Configuration Files

The module generates configuration files in `/etc/swanctl/conf.d/`:

- `madmin_{tunnel_name}.conf` - Tunnel configuration
- `madmin_secrets.conf` - PSK secrets (mode 600)

## Firewall Integration

The module creates firewall chains:

- `MOD_IPSEC_INPUT`: Allows IKE (UDP 500), NAT-T (UDP 4500), and ESP
- `MOD_IPSEC_FORWARD`: Jump rules to per-Child-SA chains
- `IPSEC_{Tunnel}_{N}_IN/OUT`: Per-Child-SA firewall chains with custom rules

**Firewall Features:**
- Separate default policies for IN and OUT traffic per Child SA
- Rule ordering by drag-and-drop
- Protocol filtering (TCP, UDP, ICMP, All)
- Port and destination filtering
- Enable/disable individual rules

## API Endpoints

### Tunnel Management

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

### Child SA Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/modules/strongswan/tunnels/{id}/children` | GET | List Child SAs |
| `/api/modules/strongswan/tunnels/{id}/children` | POST | Add Child SA |
| `/api/modules/strongswan/tunnels/{id}/children/{cid}` | PUT | Update Child SA |
| `/api/modules/strongswan/tunnels/{id}/children/{cid}` | DELETE | Delete Child SA |

### Firewall Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/modules/strongswan/tunnels/{tid}/children/{cid}/firewall/rules` | GET | List firewall rules |
| `/api/modules/strongswan/tunnels/{tid}/children/{cid}/firewall/rules` | POST | Create firewall rule |
| `/api/modules/strongswan/tunnels/{tid}/children/{cid}/firewall/rules/{rid}` | PATCH | Update firewall rule |
| `/api/modules/strongswan/tunnels/{tid}/children/{cid}/firewall/rules/{rid}` | DELETE | Delete firewall rule |
| `/api/modules/strongswan/tunnels/{tid}/children/{cid}/firewall/rules/order` | PUT | Reorder rules |
| `/api/modules/strongswan/tunnels/{tid}/children/{cid}/firewall/policy` | PATCH | Update default policy (IN/OUT) |

### Traffic Statistics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/modules/strongswan/tunnels/{id}/traffic` | GET | Get traffic history |

## License

MIT License - MADMIN Team
