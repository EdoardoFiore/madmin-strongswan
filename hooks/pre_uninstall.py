"""
IPsec VPN Module - Pre-uninstall Hook

Executes before module uninstallation to clean up:
1. Terminate all active IPsec tunnels
2. Remove all firewall chains and rules
3. Remove MADMIN-managed configuration files
4. Clean up secrets file
"""
import subprocess
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


async def run():
    """
    Pre-uninstallation cleanup for strongSwan.
    
    This hook is executed before:
    - Database tables are dropped
    - Module files are removed
    """
    logger.info("Running strongSwan pre-uninstall hook...")
    errors = []
    
    # 1. Terminate all active tunnels via swanctl
    logger.info("Terminating all IPsec tunnels...")
    try:
        result = subprocess.run(
            ['swanctl', '--terminate', '--ike', '*'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("All tunnels terminated")
        else:
            # This might fail if no tunnels are active, which is OK
            logger.info(f"Tunnel termination result: {result.stderr.strip()}")
    except FileNotFoundError:
        logger.warning("swanctl not found, skipping tunnel termination")
    except Exception as e:
        errors.append(f"Failed to terminate tunnels: {e}")
    
    # 2. Remove per-tunnel FORWARD rules (any comments with madmin_)
    logger.info("Removing IPsec FORWARD rules...")
    try:
        # List all filter rules
        result = subprocess.run(
            ['iptables', '-t', 'filter', '-S', 'MOD_IPSEC_FORWARD'],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if line.startswith('-A ') and 'madmin_' in line:
                # Build delete command
                parts = line.split()
                delete_cmd = ['iptables', '-t', 'filter'] + ['-D' if p == '-A' else p for p in parts]
                subprocess.run(delete_cmd, capture_output=True)
                logger.debug(f"Removed FORWARD rule: {line[:50]}...")
    except Exception as e:
        logger.warning(f"Error removing FORWARD rules: {e}")
    
    # 3. Flush and remove module firewall chains
    logger.info("Removing IPsec firewall chains...")
    module_chains = [
        ("filter", "MOD_IPSEC_INPUT"),
        ("filter", "MOD_IPSEC_FORWARD"),
        ("nat", "MOD_IPSEC_NAT"),
    ]
    
    for table, chain in module_chains:
        # First remove any jump rules from MADMIN chains
        for parent_chain in ['MADMIN_INPUT', 'MADMIN_FORWARD', 'MADMIN_POSTROUTING', 'INPUT', 'FORWARD', 'POSTROUTING']:
            subprocess.run(
                ['iptables', '-t', table, '-D', parent_chain, '-j', chain],
                capture_output=True
            )
        
        # Flush chain
        subprocess.run(['iptables', '-t', table, '-F', chain], capture_output=True)
        # Delete chain
        result = subprocess.run(['iptables', '-t', table, '-X', chain], capture_output=True)
        if result.returncode == 0:
            logger.info(f"Removed chain: {chain}")
        else:
            logger.debug(f"Chain {chain} may not exist or has references")
    
    # 4. Remove MADMIN-managed configuration files
    logger.info("Removing MADMIN configuration files...")
    conf_dir = Path("/etc/swanctl/conf.d")
    
    if conf_dir.exists():
        # Remove all madmin_* config files
        for conf_file in conf_dir.glob("madmin_*.conf"):
            try:
                conf_file.unlink()
                logger.info(f"Removed {conf_file}")
            except Exception as e:
                errors.append(f"Failed to remove {conf_file}: {e}")
    
    # 5. Remove MADMIN secrets file
    logger.info("Removing MADMIN secrets file...")
    secrets_file = Path("/etc/swanctl/conf.d/madmin_secrets.conf")
    if secrets_file.exists():
        try:
            secrets_file.unlink()
            logger.info(f"Removed {secrets_file}")
        except Exception as e:
            errors.append(f"Failed to remove {secrets_file}: {e}")
    
    # 6. Reload swanctl to clear configurations
    logger.info("Reloading swanctl...")
    try:
        subprocess.run(
            ['swanctl', '--load-all'],
            capture_output=True,
            text=True
        )
        logger.info("swanctl configuration reloaded")
    except FileNotFoundError:
        logger.warning("swanctl not found, skipping reload")
    except Exception as e:
        errors.append(f"Failed to reload swanctl: {e}")
    
    # 7. Remove strongSwan packages
    logger.info("Removing strongSwan packages...")
    packages_to_remove = [
        'strongswan',
        'strongswan-swanctl',
        'strongswan-charon',
        'libcharon-extra-plugins',
        'strongswan-pki',
        'charon-systemd'
    ]
    
    try:
        # Use apt-get remove with auto-remove to clean dependencies
        result = subprocess.run(
            ['apt-get', 'remove', '-y', '--purge'] + packages_to_remove,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("strongSwan packages removed")
        else:
            logger.warning(f"Package removal result: {result.stderr.strip()}")
        
        # Auto-remove orphaned dependencies
        subprocess.run(
            ['apt-get', 'autoremove', '-y'],
            capture_output=True,
            text=True
        )
        logger.info("Orphaned dependencies cleaned up")
    except Exception as e:
        errors.append(f"Failed to remove packages: {e}")
    
    # 8. Remove /etc/swanctl directory entirely
    logger.info("Removing swanctl configuration directory...")
    swanctl_dir = Path("/etc/swanctl")
    if swanctl_dir.exists():
        try:
            shutil.rmtree(swanctl_dir)
            logger.info(f"Removed {swanctl_dir}")
        except Exception as e:
            errors.append(f"Failed to remove {swanctl_dir}: {e}")
    
    # Report results
    if errors:
        for err in errors:
            logger.error(f"Pre-uninstall error: {err}")
        logger.warning("strongSwan pre-uninstall completed with warnings")
    else:
        logger.info("strongSwan pre-uninstall completed successfully")
    
    return True
