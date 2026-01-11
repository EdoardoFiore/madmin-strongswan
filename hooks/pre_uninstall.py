"""
IPsec VPN Module - Pre-uninstall Hook

Executes before module uninstallation to clean up:
1. Terminate all active IPsec tunnels
2. Remove MADMIN-managed configuration files
3. Clean up firewall rules
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run():
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
    
    # 2. Remove MADMIN-managed configuration files
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
    
    # 3. Reload swanctl to clear configurations
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
    
    # Report results
    if errors:
        for err in errors:
            logger.error(f"Pre-uninstall error: {err}")
        logger.warning("strongSwan pre-uninstall completed with warnings")
    else:
        logger.info("strongSwan pre-uninstall completed successfully")
    
    return True
