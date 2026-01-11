"""
IPsec VPN Module - Post-update Hook

Executes after module update to ensure configurations are reloaded.
"""
import subprocess
import logging

logger = logging.getLogger(__name__)


def run():
    """
    Post-update configuration reload for strongSwan.
    """
    logger.info("Running strongSwan post-update hook...")
    
    # Reload all swanctl configurations
    try:
        result = subprocess.run(
            ['swanctl', '--load-all'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("swanctl configurations reloaded")
        else:
            logger.warning(f"swanctl reload warning: {result.stderr.strip()}")
    except FileNotFoundError:
        logger.warning("swanctl not found, skipping reload")
    except Exception as e:
        logger.error(f"Failed to reload swanctl: {e}")
    
    logger.info("strongSwan post-update completed")
    return True
