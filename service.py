"""
IPsec VPN Module - Service Layer

Business logic for IPsec operations: VICI API communication,
config file generation, tunnel management, and firewall rules.
"""
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

SWANCTL_CONF_DIR = Path("/etc/swanctl/conf.d")
VICI_SOCKET = "/var/run/charon.vici"


class StrongSwanService:
    """
    Service class for strongSwan IPsec operations.
    
    Handles:
    - VICI API connection for tunnel control
    - Configuration file generation
    - Firewall rule management
    """
    
    # Firewall chain names (must match manifest.json)
    IPSEC_INPUT_CHAIN = "MOD_IPSEC_INPUT"
    IPSEC_FORWARD_CHAIN = "MOD_IPSEC_FORWARD"
    IPSEC_NAT_CHAIN = "MOD_IPSEC_NAT"
    
    def _get_vici_session(self):
        """
        Get a VICI session connected to charon daemon.
        
        Returns:
            vici.Session or None if connection fails
        """
        try:
            import vici
            return vici.Session()
        except ImportError:
            logger.error("vici module not installed")
            return None
        except Exception as e:
            logger.error(f"Failed to connect to VICI: {e}")
            return None
    
    def _run_swanctl(self, args: List[str], check: bool = False) -> subprocess.CompletedProcess:
        """Execute a swanctl command."""
        try:
            result = subprocess.run(
                ['swanctl'] + args,
                capture_output=True,
                text=True
            )
            if check and result.returncode != 0:
                logger.warning(f"swanctl {args} failed: {result.stderr}")
            return result
        except FileNotFoundError:
            logger.error("swanctl not found")
            raise
    
    def _run_iptables(self, table: str, args: List[str], suppress_errors: bool = False) -> bool:
        """Execute an iptables command."""
        cmd = ['iptables', '-t', table] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0 and not suppress_errors:
                logger.warning(f"iptables command failed: {' '.join(cmd)}: {result.stderr}")
                return False
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("iptables not found")
            return False
    
    # --- Config File Generation ---
    
    def generate_tunnel_config(
        self,
        tunnel_id: uuid.UUID,
        name: str,
        ike_version: str,
        local_address: str,
        remote_address: str,
        local_id: Optional[str],
        remote_id: Optional[str],
        auth_method: str,
        ike_proposal: str,
        ike_lifetime: int,
        dpd_action: str,
        dpd_delay: int,
        nat_traversal: bool,
        child_sas: List[Dict]
    ) -> str:
        """
        Generate swanctl.conf content for a tunnel.
        
        Args:
            All tunnel parameters
            child_sas: List of Child SA configurations
        
        Returns:
            swanctl.conf file content
        """
        # Connection name (filesystem safe)
        conn_name = f"madmin_{name}"
        
        # Build children section
        children_conf = ""
        for child in child_sas:
            child_name = child.get("name", "child1")
            children_conf += f"""
            {child_name} {{
                local_ts = {child.get("local_ts", "0.0.0.0/0")}
                remote_ts = {child.get("remote_ts", "0.0.0.0/0")}
                esp_proposals = {child.get("esp_proposal", "aes256-sha256-modp2048")}
                life_time = {child.get("esp_lifetime", 3600)}s
                start_action = {child.get("start_action", "trap")}
                close_action = {child.get("close_action", "restart")}
                dpd_action = {dpd_action}
            }}"""
        
        # Build local/remote auth sections
        local_auth = f"""
        local {{
            auth = {auth_method}"""
        if local_id:
            local_auth += f"""
            id = {local_id}"""
        local_auth += """
        }"""
        
        remote_auth = f"""
        remote {{
            auth = {auth_method}"""
        if remote_id:
            remote_auth += f"""
            id = {remote_id}"""
        remote_auth += """
        }"""
        
        # Build main connection config
        config = f"""# MADMIN IPsec VPN - {name}
# Tunnel ID: {tunnel_id}
# Generated: {datetime.utcnow().isoformat()}

connections {{
    {conn_name} {{
        version = {ike_version}
        local_addrs = {local_address if local_address else '%any'}
        remote_addrs = {remote_address}
        proposals = {ike_proposal}
        rekey_time = {ike_lifetime}s
        dpd_delay = {dpd_delay}s
        encap = {"yes" if nat_traversal else "no"}
        
{local_auth}
{remote_auth}
        
        children {{{children_conf}
        }}
    }}
}}
"""
        return config
    
    def generate_secrets_entry(
        self,
        name: str,
        local_id: Optional[str],
        remote_id: Optional[str],
        psk: str
    ) -> str:
        """
        Generate secrets entry for PSK authentication.
        
        Returns:
            Secret configuration snippet
        """
        secret_name = f"madmin-{name}"
        
        # Build ID list for the secret
        ids = []
        if local_id:
            ids.append(local_id)
        if remote_id:
            ids.append(remote_id)
        
        id_list = " ".join(ids) if ids else ""
        
        return f"""
    ike-{secret_name} {{
        id = {id_list}
        secret = "{psk}"
    }}
"""
    
    def save_tunnel_config(self, name: str, config: str) -> bool:
        """Save tunnel configuration to file."""
        config_file = SWANCTL_CONF_DIR / f"madmin_{name}.conf"
        try:
            SWANCTL_CONF_DIR.mkdir(parents=True, exist_ok=True)
            config_file.write_text(config)
            logger.info(f"Saved tunnel config: {config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save tunnel config: {e}")
            return False
    
    def update_secrets_file(self, secrets_entries: List[str]) -> bool:
        """
        Update the MADMIN secrets file with all PSK entries.
        
        Args:
            secrets_entries: List of secret configuration snippets
        """
        secrets_file = SWANCTL_CONF_DIR / "madmin_secrets.conf"
        try:
            content = "# MADMIN IPsec VPN secrets - managed by MADMIN\nsecrets {"
            for entry in secrets_entries:
                content += entry
            content += "\n}\n"
            
            secrets_file.write_text(content)
            import os
            os.chmod(secrets_file, 0o600)
            logger.info("Updated secrets file")
            return True
        except Exception as e:
            logger.error(f"Failed to update secrets file: {e}")
            return False
    
    def delete_tunnel_config(self, name: str) -> bool:
        """Delete tunnel configuration file."""
        config_file = SWANCTL_CONF_DIR / f"madmin_{name}.conf"
        try:
            if config_file.exists():
                config_file.unlink()
                logger.info(f"Deleted tunnel config: {config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete tunnel config: {e}")
            return False
    
    # --- Tunnel Control via VICI ---
    
    def load_all_connections(self) -> bool:
        """Reload all swanctl connections."""
        result = self._run_swanctl(['--load-all'])
        return result.returncode == 0
    
    def initiate_tunnel(self, name: str, child_name: Optional[str] = None) -> bool:
        """
        Initiate an IPsec tunnel.
        
        Args:
            name: Tunnel name (without madmin_ prefix)
            child_name: Optional specific Child SA to initiate
        """
        conn_name = f"madmin_{name}"
        args = ['--initiate', '--ike', conn_name, '--timeout', '5']
        if child_name:
            args.extend(['--child', child_name])
        
        # We don't check return code strictly because timeout (which is expected if peer is down) causes non-zero exit
        # Yet the initiation has started in background.
        result = self._run_swanctl(args)
        if result.returncode == 0:
            logger.info(f"Initiated tunnel {name}")
            return True
        elif any(x in (result.stderr + result.stdout).lower() for x in ["timeout", "not established after"]):
            logger.warning(f"Initiate tunnel {name} timed out waiting for connection (background retry active)")
            return True
        else:
            logger.error(f"Failed to initiate tunnel {name}: {result.stderr}")
            return False
    
    def terminate_tunnel(self, name: str) -> bool:
        """Terminate an IPsec tunnel."""
        conn_name = f"madmin_{name}"
        result = self._run_swanctl(['--terminate', '--ike', conn_name])
        if result.returncode == 0:
            logger.info(f"Terminated tunnel {name}")
            return True
        else:
            # Tunnel may not be active, which is fine
            logger.info(f"Tunnel {name} termination result: {result.stderr.strip()}")
            return True
    
    def unload_connection(self, name: str) -> bool:
        """Unload connection from StrongSwan runtime."""
        session = self._get_vici_session()
        if not session:
            return False
            
        conn_name = f"madmin_{name}"
        try:
            # unload_conn expects request dict with connection name
            session.unload_conn({"name": conn_name})
            logger.info(f"Unloaded connection {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to unload connection {name}: {e}")
            return False

    def get_tunnel_status(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get real-time status of a tunnel via VICI.
        
        Returns:
            Status dict or None if tunnel not found
        """
        session = self._get_vici_session()
        if not session:
            return None
        
        conn_name = f"madmin_{name}"
        
        try:
            # List Security Associations
            sas = list(session.list_sas())
            
            # Find all matching SAs
            matches = []
            
            for sa in sas:
                for ike_name, ike_data in sa.items():
                    name_str = ike_name.decode('utf-8', errors='ignore') if isinstance(ike_name, bytes) else ike_name
                    
                    if name_str == conn_name:
                        matches.append(ike_data)
            
            if not matches:
                # No SA found
                return None
                
            # Pick the best match (ESTABLISHED preferred, then CONNECTING)
            # Also prefer the one with children if states are equal
            best_sa = None
            
            # established value is "seconds since established" (duration). We want SMALLEST duration (newest).
            # To sort Descending, we negate the time.
            def sa_score(sa_data):
                state = sa_data.get('state', b'').decode('utf-8', errors='ignore')
                est_time = int(sa_data.get('established', 0))
                child_count = len(sa_data.get('child-sas', {}))
                
                # Established = 2, Connecting = 1, Other = 0
                state_score = 2 if state == 'ESTABLISHED' else (1 if state == 'CONNECTING' else 0)
                
                # Prioritize: 1. State, 2. Has Children, 3. Newest
                has_children = 1 if child_count > 0 else 0
                
                return (state_score, has_children, -est_time)

            matches.sort(key=sa_score, reverse=True)
            best_sa = matches[0]
            ike_data = best_sa
            
            # Now parse the best match
            state = ike_data.get('state', b'').decode('utf-8', errors='ignore')
            local_host = ike_data.get('local-host', b'').decode('utf-8', errors='ignore')
            remote_host = ike_data.get('remote-host', b'').decode('utf-8', errors='ignore')
            initiator = ike_data.get('initiator', b'no') == b'yes'
            established = int(ike_data.get('established', 0))
            rekey_time = int(ike_data.get('rekey-time', 0))
            
            # Get Child SAs
            child_sas = []
            children_sas = ike_data.get('child-sas', {})
            for sa_key, child_data in children_sas.items():
                # The key might have a suffix (e.g., -1, -2). The real config name is in 'name'.
                # If 'name' is missing, fallback to key.
                c_name_val = child_data.get('name', sa_key)
                child_name_str = c_name_val.decode('utf-8', errors='ignore') if isinstance(c_name_val, bytes) else c_name_val
                
                child_sas.append({
                    "name": child_name_str,
                    "state": child_data.get('state', b'').decode('utf-8', errors='ignore'),
                    "bytes_in": int(child_data.get('bytes-in', 0)),
                    "bytes_out": int(child_data.get('bytes-out', 0)),
                    "packets_in": int(child_data.get('packets-in', 0)),
                    "packets_out": int(child_data.get('packets-out', 0)),
                })
            
            return {
                "ike_state": state,
                "local_host": local_host,
                "remote_host": remote_host,
                "initiator": initiator,
                "established_time": established,
                "rekey_time": rekey_time,
                "child_sas": child_sas
            }
            
            # Tunnel not found in active SAs
            return {
                "ike_state": "DISCONNECTED",
                "local_host": None,
                "remote_host": None,
                "initiator": False,
                "established_time": None,
                "rekey_time": None,
                "child_sas": []
            }
            
        except Exception as e:
            logger.error(f"Failed to get tunnel status via VICI: {e}")
            return None
    
    def list_all_sas(self) -> List[Dict]:
        """List all active Security Associations."""
        session = self._get_vici_session()
        if not session:
            return []
        
        try:
            sas = list(session.list_sas())
            result = []
            
            for sa in sas:
                for ike_name, ike_data in sa.items():
                    name_str = ike_name.decode('utf-8', errors='ignore') if isinstance(ike_name, bytes) else ike_name
                    state = ike_data.get('state', b'').decode('utf-8', errors='ignore')
                    
                    result.append({
                        "name": name_str,
                        "state": state
                    })
            
            return result
        except Exception as e:
            logger.error(f"Failed to list SAs: {e}")
            return []
    
    def get_tunnel_logs(self, name: str, lines: int = 100) -> Dict:
        """
        Get StrongSwan logs filtered by tunnel name with error detection.
        
        Args:
            name: Tunnel name (without madmin_ prefix)
            lines: Number of log lines to fetch
            
        Returns:
            Dict with logs list and detected errors
        """
        conn_name = f"madmin_{name}"
        
        # Known error patterns and their user-friendly descriptions
        error_patterns = [
            ("received AUTH_FAILED", "Autenticazione fallita - PSK errata o mismatch"),
            ("no matching peer config found", "Configurazione peer non trovata - Controlla ID locale/remoto"),
            ("received NO_PROPOSAL_CHOSEN", "Nessuna proposal accettata - Algoritmi non compatibili"),
            ("establishing IKE_SA.*failed", "Connessione IKE fallita - Endpoint non raggiungibile"),
            ("unable to resolve", "Impossibile risolvere hostname - Problema DNS"),
            ("peer didn't accept", "Peer ha rifiutato - Verifica configurazione remota"),
            ("connection timeout", "Timeout connessione - Endpoint non risponde"),
            ("AUTHENTICATION_FAILED", "Autenticazione rifiutata dal peer"),
            ("INVALID_KE_PAYLOAD", "Payload DH non valido - Gruppo DH non supportato"),
            ("INVALID_SYNTAX", "Errore di sintassi nel messaggio IKE"),
            ("TS_UNACCEPTABLE", "Traffic Selector rifiutato - Subnet non corrispondenti"),
        ]
        
        logs = []
        errors = []
        
        try:
            # Fetch logs from journalctl for charon/strongswan
            result = subprocess.run(
                ['journalctl', '-u', 'strongswan', '-n', str(lines), '--no-pager', '-o', 'short-iso'],
                capture_output=True,
                text=True
            )
            
            all_lines = result.stdout.strip().split('\n') if result.stdout else []
            
            # Filter lines containing our connection name or general charon messages
            import re
            for line in all_lines:
                # Include lines mentioning our connection or general IKE messages
                if conn_name in line or name in line:
                    logs.append(line)
                    
                    # Check for error patterns
                    for pattern, description in error_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            error_entry = {
                                "pattern": pattern,
                                "description": description,
                                "log_line": line[:200]  # Truncate long lines
                            }
                            # Avoid duplicates
                            if error_entry not in errors:
                                errors.append(error_entry)
            
            # If no filtered logs, include last N general charon lines
            if not logs and all_lines:
                for line in all_lines[-20:]:
                    if 'charon' in line.lower() or 'ike' in line.lower():
                        logs.append(line)
            
            return {
                "logs": logs[-50:],  # Return last 50 relevant lines
                "errors": errors,
                "total_lines": len(logs)
            }
            
        except FileNotFoundError:
            logger.warning("journalctl not found")
            return {"logs": [], "errors": [], "total_lines": 0}
        except Exception as e:
            logger.error(f"Failed to get tunnel logs: {e}")
            return {"logs": [], "errors": [{"description": str(e)}], "total_lines": 0}
    
    # --- Firewall Rules ---
    
    def setup_ipsec_input_rules(self) -> bool:
        """
        Setup INPUT rules for IPsec traffic.
        
        Allows:
        - UDP 500 (IKE)
        - UDP 4500 (NAT-T)
        - ESP protocol (50)
        """
        success = True
        
        # Allow IKE (UDP 500)
        if not self._run_iptables('filter', [
            '-C', self.IPSEC_INPUT_CHAIN, '-p', 'udp', '--dport', '500', '-j', 'ACCEPT'
        ], suppress_errors=True):
            success &= self._run_iptables('filter', [
                '-A', self.IPSEC_INPUT_CHAIN, '-p', 'udp', '--dport', '500', '-j', 'ACCEPT'
            ])
        
        # Allow NAT-T (UDP 4500)
        if not self._run_iptables('filter', [
            '-C', self.IPSEC_INPUT_CHAIN, '-p', 'udp', '--dport', '4500', '-j', 'ACCEPT'
        ], suppress_errors=True):
            success &= self._run_iptables('filter', [
                '-A', self.IPSEC_INPUT_CHAIN, '-p', 'udp', '--dport', '4500', '-j', 'ACCEPT'
            ])
        
        # Allow ESP
        if not self._run_iptables('filter', [
            '-C', self.IPSEC_INPUT_CHAIN, '-p', 'esp', '-j', 'ACCEPT'
        ], suppress_errors=True):
            success &= self._run_iptables('filter', [
                '-A', self.IPSEC_INPUT_CHAIN, '-p', 'esp', '-j', 'ACCEPT'
            ])
        
        if success:
            logger.info("IPsec INPUT rules configured")
        return success
    
    def setup_forward_rules(self, local_ts: str, remote_ts: str, tunnel_name: str) -> bool:
        """
        Setup FORWARD rules for a Child SA traffic selector.
        
        Allows traffic between local and remote subnets.
        """
        comment = f"IPSEC_{tunnel_name}"
        success = True
        
        # Forward: local -> remote
        if not self._run_iptables('filter', [
            '-C', self.IPSEC_FORWARD_CHAIN, '-s', local_ts, '-d', remote_ts, '-j', 'ACCEPT'
        ], suppress_errors=True):
            success &= self._run_iptables('filter', [
                '-A', self.IPSEC_FORWARD_CHAIN, '-s', local_ts, '-d', remote_ts,
                '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'
            ])
        
        # Forward: remote -> local
        if not self._run_iptables('filter', [
            '-C', self.IPSEC_FORWARD_CHAIN, '-s', remote_ts, '-d', local_ts, '-j', 'ACCEPT'
        ], suppress_errors=True):
            success &= self._run_iptables('filter', [
                '-A', self.IPSEC_FORWARD_CHAIN, '-s', remote_ts, '-d', local_ts,
                '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'
            ])
        
        if success:
            logger.info(f"FORWARD rules for {local_ts} <-> {remote_ts} configured")
        return success
    
    def remove_forward_rules(self, local_ts: str, remote_ts: str) -> bool:
        """Remove FORWARD rules for a traffic selector pair."""
        success = True
        
        # Try to delete both directions (ignore errors if rules don't exist)
        self._run_iptables('filter', [
            '-D', self.IPSEC_FORWARD_CHAIN, '-s', local_ts, '-d', remote_ts, '-j', 'ACCEPT'
        ], suppress_errors=True)
        
        self._run_iptables('filter', [
            '-D', self.IPSEC_FORWARD_CHAIN, '-s', remote_ts, '-d', local_ts, '-j', 'ACCEPT'
        ], suppress_errors=True)
        
        return success
    
    def flush_tunnel_forward_rules(self, tunnel_name: str) -> bool:
        """Remove all FORWARD rules for a specific tunnel."""
        comment = f"IPSEC_{tunnel_name}"
        
        # Get current rules and remove those with matching comment
        # This is a simplified approach - iptables-save/restore would be more robust
        try:
            result = subprocess.run(
                ['iptables', '-t', 'filter', '-L', self.IPSEC_FORWARD_CHAIN, '-n', '--line-numbers'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return False
            
            # Parse and collect rule numbers to delete (in reverse order)
            lines = result.stdout.strip().split('\n')[2:]  # Skip headers
            rules_to_delete = []
            
            for line in lines:
                if comment in line:
                    rule_num = line.split()[0]
                    rules_to_delete.append(int(rule_num))
            
            # Delete in reverse order to maintain correct indices
            for rule_num in sorted(rules_to_delete, reverse=True):
                self._run_iptables('filter', [
                    '-D', self.IPSEC_FORWARD_CHAIN, str(rule_num)
                ])
            
            logger.info(f"Removed {len(rules_to_delete)} FORWARD rules for tunnel {tunnel_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to flush tunnel forward rules: {e}")
            return False
    
    # --- Traffic Statistics Collection ---
    
    async def collect_traffic_stats(self, db) -> int:
        """
        Collect current traffic stats from all active tunnels.
        Called periodically by background task.
        
        Returns:
            Number of stats records collected
        """
        from sqlalchemy import select
        from modules.strongswan.models import IpsecTunnel, IpsecTrafficStats
        
        collected = 0
        
        try:
            # Get all enabled tunnels
            result = await db.execute(
                select(IpsecTunnel).where(IpsecTunnel.enabled == True)
            )
            tunnels = result.scalars().all()
            
            for tunnel in tunnels:
                # Get current traffic from VICI
                status = self.get_tunnel_status(tunnel.name)
                if not status:
                    continue
                
                # Aggregate traffic from all child SAs
                total_bytes_in = 0
                total_bytes_out = 0
                total_packets_in = 0
                total_packets_out = 0
                
                for child_name, child_data in status.get("child_sas", {}).items():
                    total_bytes_in += child_data.get("bytes_in", 0)
                    total_bytes_out += child_data.get("bytes_out", 0)
                    total_packets_in += child_data.get("packets_in", 0)
                    total_packets_out += child_data.get("packets_out", 0)
                
                # Get previous stats for delta calculation
                prev_result = await db.execute(
                    select(IpsecTrafficStats)
                    .where(IpsecTrafficStats.tunnel_id == tunnel.id)
                    .order_by(IpsecTrafficStats.timestamp.desc())
                    .limit(1)
                )
                prev_stats = prev_result.scalar_one_or_none()
                
                # Calculate deltas (handle counter resets)
                if prev_stats:
                    bytes_in_delta = max(0, total_bytes_in - prev_stats.bytes_in)
                    bytes_out_delta = max(0, total_bytes_out - prev_stats.bytes_out)
                    # If tunnel reconnected, counters reset - use current value
                    if bytes_in_delta > total_bytes_in:
                        bytes_in_delta = total_bytes_in
                    if bytes_out_delta > total_bytes_out:
                        bytes_out_delta = total_bytes_out
                else:
                    bytes_in_delta = 0
                    bytes_out_delta = 0
                
                # Create new stats record
                stats = IpsecTrafficStats(
                    tunnel_id=tunnel.id,
                    bytes_in=total_bytes_in,
                    bytes_out=total_bytes_out,
                    packets_in=total_packets_in,
                    packets_out=total_packets_out,
                    bytes_in_delta=bytes_in_delta,
                    bytes_out_delta=bytes_out_delta,
                    timestamp=datetime.utcnow()
                )
                db.add(stats)
                collected += 1
            
            if collected > 0:
                await db.commit()
                logger.debug(f"Collected traffic stats for {collected} tunnels")
                
        except Exception as e:
            logger.error(f"Traffic stats collection failed: {e}")
            await db.rollback()
        
        return collected
    
    async def get_traffic_history(
        self, 
        tunnel_id: uuid.UUID, 
        period: str,
        db
    ) -> List[Dict]:
        """
        Get historical traffic data for charting.
        
        Args:
            tunnel_id: UUID of the tunnel
            period: Time period - "1h", "6h", "24h", "7d"
            db: Database session
            
        Returns:
            List of {timestamp, bytes_in_delta, bytes_out_delta} points
        """
        from sqlalchemy import select
        from modules.strongswan.models import IpsecTrafficStats
        from datetime import timedelta
        
        # Calculate time range
        period_map = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7)
        }
        
        delta = period_map.get(period, timedelta(hours=24))
        since = datetime.utcnow() - delta
        
        try:
            result = await db.execute(
                select(IpsecTrafficStats)
                .where(IpsecTrafficStats.tunnel_id == tunnel_id)
                .where(IpsecTrafficStats.timestamp >= since)
                .order_by(IpsecTrafficStats.timestamp.asc())
            )
            stats = result.scalars().all()
            
            return [
                {
                    "timestamp": s.timestamp.isoformat(),
                    "bytes_in": s.bytes_in_delta,
                    "bytes_out": s.bytes_out_delta,
                    "total_in": s.bytes_in,
                    "total_out": s.bytes_out
                }
                for s in stats
            ]
            
        except Exception as e:
            logger.error(f"Failed to get traffic history: {e}")
            return []
    
    async def cleanup_old_stats(self, db, days: int = 30) -> int:
        """
        Remove traffic stats older than X days.
        
        Returns:
            Number of records deleted
        """
        from sqlalchemy import delete
        from modules.strongswan.models import IpsecTrafficStats
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        try:
            result = await db.execute(
                delete(IpsecTrafficStats)
                .where(IpsecTrafficStats.timestamp < cutoff)
            )
            await db.commit()
            deleted = result.rowcount
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old traffic stats records")
            return deleted
            
        except Exception as e:
            logger.error(f"Failed to cleanup old stats: {e}")
            await db.rollback()
            return 0


# Singleton instance
strongswan_service = StrongSwanService()
