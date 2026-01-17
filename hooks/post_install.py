"""
IPsec VPN Module - Post-install Hook

Executes after module installation to configure system for strongSwan:
1. Enable and start strongswan-swanctl service
2. Create /etc/swanctl/conf.d directory with correct permissions
3. Create empty secrets file with secure permissions
4. Enable IP forwarding persistently
"""
import subprocess
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def run():
    """
    Post-installation system configuration for strongSwan.
    
    This hook is executed after:
    - apt packages are installed (strongswan, strongswan-swanctl, etc.)
    - Database migrations are complete
    """
    logger.info("Running strongSwan post-install hook...")
    errors = []
    
    # 1. Ensure swanctl directories exist
    logger.info("Creating swanctl configuration directories...")
    swanctl_dirs = [
        Path("/etc/swanctl/conf.d"),
        Path("/etc/swanctl/x509"),
        Path("/etc/swanctl/x509ca"),
        Path("/etc/swanctl/private"),
    ]
    
    for dir_path in swanctl_dirs:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {dir_path}")
        except PermissionError:
            errors.append(f"Permission denied creating {dir_path}")
        except Exception as e:
            errors.append(f"Failed to create {dir_path}: {e}")
    
    # 2. Create empty secrets file with secure permissions
    logger.info("Creating secrets configuration file...")
    secrets_file = Path("/etc/swanctl/conf.d/madmin_secrets.conf")
    try:
        if not secrets_file.exists():
            secrets_file.write_text("# MADMIN IPsec VPN secrets - managed by MADMIN\nsecrets {\n}\n")
            os.chmod(secrets_file, 0o600)
            logger.info(f"Created {secrets_file} with mode 600")
        else:
            logger.info(f"{secrets_file} already exists")
    except PermissionError:
        errors.append(f"Permission denied creating {secrets_file}")
    except Exception as e:
        errors.append(f"Failed to create {secrets_file}: {e}")
    
    # 3. Enable IP forwarding (required for IPsec routing)
    logger.info("Enabling IP forwarding...")
    sysctl_conf = Path("/etc/sysctl.d/99-strongswan.conf")
    try:
        # Write persistent configuration
        sysctl_content = "# IPsec VPN IP forwarding\nnet.ipv4.ip_forward=1\n"
        sysctl_conf.write_text(sysctl_content)
        logger.info(f"Created {sysctl_conf}")
        
        # Apply immediately
        result = subprocess.run(
            ['sysctl', '-p', str(sysctl_conf)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("IP forwarding enabled")
        else:
            logger.warning(f"sysctl apply warning: {result.stderr.strip()}")
            
    except PermissionError:
        errors.append("Permission denied enabling IP forwarding")
    except FileNotFoundError:
        # Fallback: try direct sysctl
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            logger.info("IP forwarding enabled (direct sysctl)")
        except Exception as e:
            errors.append(f"Failed to enable IP forwarding: {e}")
    except Exception as e:
        errors.append(f"IP forwarding configuration failed: {e}")
    
    # 4. Configure and start strongswan service
    # charon-systemd provides 'strongswan' service with VICI support
    # strongswan-starter is legacy and doesn't work well with swanctl
    logger.info("Configuring strongswan service...")
    try:
        # First, stop and disable the legacy starter if running
        subprocess.run(
            ['systemctl', 'stop', 'strongswan-starter'],
            capture_output=True
        )
        subprocess.run(
            ['systemctl', 'disable', 'strongswan-starter'],
            capture_output=True
        )
        logger.info("Disabled legacy strongswan-starter")
        
        # Enable and start the charon-systemd based service
        result = subprocess.run(
            ['systemctl', 'enable', 'strongswan'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("strongswan service enabled")
        else:
            logger.warning(f"Failed to enable strongswan: {result.stderr.strip()}")
        
        # Start service
        result = subprocess.run(
            ['systemctl', 'start', 'strongswan'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("strongswan service started")
        else:
            logger.warning(f"Failed to start strongswan: {result.stderr.strip()}")
            
    except FileNotFoundError:
        errors.append("systemctl not found")
    except Exception as e:
        errors.append(f"Service management failed: {e}")
    
    # Report results
    if errors:
        for err in errors:
            logger.error(f"Post-install error: {err}")
        logger.warning("strongSwan post-install completed with warnings")
    else:
        logger.info("strongSwan post-install completed successfully")
    
    # Don't fail the installation for non-critical errors
    return True
