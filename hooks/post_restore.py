"""
IPsec VPN Module - Post-restore Hook

Executes after backup restoration to reload configurations.
"""
import subprocess
import logging

logger = logging.getLogger(__name__)


def run():
    """
    Post-restore configuration reload for strongSwan.
    
    After restoring backup files, we need to:
    1. Reload all swanctl configurations
    2. Re-establish tunnels if they were active
    """
    logger.info("Running strongSwan post-restore hook...")
    
    # Reload all swanctl configurations from restored files
    try:
        result = subprocess.run(
            ['swanctl', '--load-all'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("swanctl configurations reloaded from backup")
        else:
            logger.warning(f"swanctl reload warning: {result.stderr.strip()}")
    except FileNotFoundError:
        logger.warning("swanctl not found, skipping reload")
    except Exception as e:
        logger.error(f"Failed to reload swanctl: {e}")
    
    logger.info("strongSwan post-restore completed")
    return True
