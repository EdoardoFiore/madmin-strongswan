"""
IPsec VPN Module - API Router

FastAPI endpoints for IPsec tunnel management.
"""
import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from core.database import get_session
from core.auth.dependencies import require_permission
from core.auth.models import User

from .models import (
    IpsecTunnel, IpsecChildSa,
    IpsecTunnelCreate, IpsecTunnelUpdate, IpsecTunnelRead,
    IpsecChildSaCreate, IpsecChildSaUpdate, IpsecChildSaRead,
    IpsecTunnelStatus,
    IKE_ENCRYPTION_OPTIONS, IKE_INTEGRITY_OPTIONS, DH_GROUP_OPTIONS
)
from .service import strongswan_service
from . import tasks

logger = logging.getLogger(__name__)
router = APIRouter()

# Start traffic collector background task
try:
    tasks.start_collector()
except Exception as e:
    logger.warning(f"Could not start traffic collector: {e}")


# --- CRYPTO OPTIONS ---

@router.get("/crypto-options")
async def get_crypto_options(
    _user: User = Depends(require_permission("ipsec.view"))
):
    """Get available cryptographic algorithm options for UI."""
    return {
        "encryption": IKE_ENCRYPTION_OPTIONS,
        "integrity": IKE_INTEGRITY_OPTIONS,
        "dh_groups": DH_GROUP_OPTIONS
    }


# --- TUNNELS ---

@router.get("/tunnels", response_model=List[IpsecTunnelRead])
async def list_tunnels(
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.view"))
):
    """List all IPsec tunnels."""
    result = await db.execute(
        select(IpsecTunnel)
        .options(selectinload(IpsecTunnel.child_sas))
        .order_by(IpsecTunnel.name)
    )
    tunnels = result.scalars().all()
    
    return [
        IpsecTunnelRead(
            **tunnel.model_dump(exclude={"child_sas", "psk"}),
            child_sa_count=len(tunnel.child_sas)
        )
        for tunnel in tunnels
    ]


@router.post("/tunnels", response_model=IpsecTunnelRead)
async def create_tunnel(
    data: IpsecTunnelCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Create a new IPsec tunnel (Phase 1 - IKE SA)."""
    # Check if name already exists
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.name == data.name)
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Tunnel name already exists")
    
    # Create tunnel
    tunnel = IpsecTunnel(**data.model_dump())
    db.add(tunnel)
    await db.flush()
    await db.refresh(tunnel)
    
    # Generate and save configuration
    config = strongswan_service.generate_tunnel_config(
        tunnel_id=tunnel.id,
        name=tunnel.name,
        ike_version=tunnel.ike_version,
        local_address=tunnel.local_address,
        remote_address=tunnel.remote_address,
        local_id=tunnel.local_id,
        remote_id=tunnel.remote_id,
        auth_method=tunnel.auth_method,
        ike_proposal=tunnel.ike_proposal,
        ike_lifetime=tunnel.ike_lifetime,
        dpd_action=tunnel.dpd_action,
        dpd_delay=tunnel.dpd_delay,
        nat_traversal=tunnel.nat_traversal,
        child_sas=[]  # No Child SAs yet
    )
    await run_in_threadpool(strongswan_service.save_tunnel_config, tunnel.name, config)
    
    # Update secrets if PSK
    if tunnel.auth_method == "psk" and tunnel.psk:
        await _update_all_secrets(db)
    
    # Setup base INPUT rules for IPsec traffic
    await run_in_threadpool(strongswan_service.setup_ipsec_input_rules)
    
    # Reload swanctl
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    await db.commit()
    
    logger.info(f"Created IPsec tunnel: {tunnel.name}")
    
    return IpsecTunnelRead(
        **tunnel.model_dump(exclude={"child_sas", "psk"}),
        child_sa_count=0
    )


@router.get("/tunnels/{tunnel_id}", response_model=IpsecTunnelRead)
async def get_tunnel(
    tunnel_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.view"))
):
    """Get a single IPsec tunnel by ID."""
    result = await db.execute(
        select(IpsecTunnel)
        .options(selectinload(IpsecTunnel.child_sas))
        .where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    return IpsecTunnelRead(
        **tunnel.model_dump(exclude={"child_sas", "psk"}),
        child_sa_count=len(tunnel.child_sas)
    )


@router.patch("/tunnels/{tunnel_id}", response_model=IpsecTunnelRead)
async def patch_tunnel(
    tunnel_id: str,
    data: IpsecTunnelUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Partially update an IPsec tunnel."""
    return await update_tunnel(tunnel_id, data, db, _user)


@router.put("/tunnels/{tunnel_id}", response_model=IpsecTunnelRead)
async def update_tunnel(
    tunnel_id: str,
    data: IpsecTunnelUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Update an IPsec tunnel."""
    result = await db.execute(
        select(IpsecTunnel)
        .options(selectinload(IpsecTunnel.child_sas))
        .where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    old_name = tunnel.name
    
    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        # Convert None to empty string for local_address (DB doesn't allow NULL)
        if key == 'local_address' and value is None:
            value = ''
        setattr(tunnel, key, value)
    
    tunnel.updated_at = datetime.utcnow()
    
    # If name changed, delete old config file
    if data.name and data.name != old_name:
        await run_in_threadpool(strongswan_service.delete_tunnel_config, old_name)
        await run_in_threadpool(strongswan_service.flush_tunnel_forward_rules, old_name)
    
    # Regenerate configuration
    child_sas_data = [
        {
            "name": c.name,
            "local_ts": c.local_ts,
            "remote_ts": c.remote_ts,
            "esp_proposal": c.esp_proposal,
            "esp_lifetime": c.esp_lifetime,
            "start_action": c.start_action,
            "close_action": c.close_action,
        }
        for c in tunnel.child_sas if c.enabled
    ]
    
    config = strongswan_service.generate_tunnel_config(
        tunnel_id=tunnel.id,
        name=tunnel.name,
        ike_version=tunnel.ike_version,
        local_address=tunnel.local_address,
        remote_address=tunnel.remote_address,
        local_id=tunnel.local_id,
        remote_id=tunnel.remote_id,
        auth_method=tunnel.auth_method,
        ike_proposal=tunnel.ike_proposal,
        ike_lifetime=tunnel.ike_lifetime,
        dpd_action=tunnel.dpd_action,
        dpd_delay=tunnel.dpd_delay,
        nat_traversal=tunnel.nat_traversal,
        child_sas=child_sas_data
    )
    await run_in_threadpool(strongswan_service.save_tunnel_config, tunnel.name, config)
    
    # Update secrets
    if tunnel.auth_method == "psk":
        await _update_all_secrets(db)
    
    # Reload
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    await db.commit()
    await db.refresh(tunnel)
    
    logger.info(f"Updated IPsec tunnel: {tunnel.name}")
    
    return IpsecTunnelRead(
        **tunnel.model_dump(exclude={"child_sas", "psk"}),
        child_sa_count=len(tunnel.child_sas)
    )


@router.delete("/tunnels/{tunnel_id}")
async def delete_tunnel(
    tunnel_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Delete an IPsec tunnel and all its Child SAs."""
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    # Terminate if active
    await run_in_threadpool(strongswan_service.terminate_tunnel, tunnel.name)
    
    # Remove config file
    await run_in_threadpool(strongswan_service.delete_tunnel_config, tunnel.name)
    
    # Remove firewall rules
    await run_in_threadpool(strongswan_service.flush_tunnel_forward_rules, tunnel.name)
    
    # Delete from DB (cascades to child_sas)
    await db.delete(tunnel)
    await db.commit()
    
    # Update secrets
    await _update_all_secrets(db)
    
    # Reload
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    logger.info(f"Deleted IPsec tunnel: {tunnel.name}")
    
    return {"status": "deleted", "name": tunnel.name}


# --- TUNNEL CONTROL ---

@router.post("/tunnels/{tunnel_id}/start")
async def start_tunnel(
    tunnel_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Start (initiate) an IPsec tunnel."""
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    # Enable tunnel
    tunnel.enabled = True
    await db.commit()
    
    # 1. Fetch children for config generation
    result_children = await db.execute(select(IpsecChildSa).where(IpsecChildSa.tunnel_id == tunnel.id))
    children = result_children.scalars().all()
    
    child_sas_data = [
        {
            "name": c.name,
            "local_ts": c.local_ts,
            "remote_ts": c.remote_ts,
            "esp_proposal": c.esp_proposal,
            "esp_lifetime": c.esp_lifetime,
            "pfs_group": c.pfs_group,
            "start_action": c.start_action,
            "close_action": c.close_action
        }
        for c in children if c.enabled
    ]
    
    # 2. Generate and Save Config
    config = strongswan_service.generate_tunnel_config(
        tunnel_id=tunnel.id,
        name=tunnel.name,
        ike_version=tunnel.ike_version,
        local_address=tunnel.local_address,
        remote_address=tunnel.remote_address,
        local_id=tunnel.local_id,
        remote_id=tunnel.remote_id,
        auth_method=tunnel.auth_method,
        ike_proposal=tunnel.ike_proposal,
        ike_lifetime=tunnel.ike_lifetime,
        dpd_action=tunnel.dpd_action,
        dpd_delay=tunnel.dpd_delay,
        nat_traversal=tunnel.nat_traversal,
        child_sas=child_sas_data
    )
    
    await run_in_threadpool(strongswan_service.save_tunnel_config, tunnel.name, config)

    # 3. Reload configs
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    # 4. Initiate tunnel
    # We use a timeout in initiate_tunnel, so if it returns True, it has started.
    # It might already be up if it was fast.
    success = await run_in_threadpool(strongswan_service.initiate_tunnel, tunnel.name)
    
    if success:
        # Check immediate status
        real_status = await run_in_threadpool(strongswan_service.get_tunnel_status, tunnel.name)
        if real_status and real_status["ike_state"] == "ESTABLISHED":
            tunnel.status = "established"
            status_response = "established"
        else:
            tunnel.status = "connecting"
            status_response = "initiated"
            
        await db.commit()
        return {"status": status_response, "name": tunnel.name}
    else:
        raise HTTPException(status_code=500, detail="Failed to initiate tunnel")


@router.post("/tunnels/{tunnel_id}/stop")
async def stop_tunnel(
    tunnel_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Stop (terminate) an IPsec tunnel."""
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    # 1. Terminate active SA
    await run_in_threadpool(strongswan_service.terminate_tunnel, tunnel.name)
    
    # 2. Unload connection from runtime (prevents auto-response)
    await run_in_threadpool(strongswan_service.unload_connection, tunnel.name)
    
    # 3. Delete config file (prevents loading on restart)
    await run_in_threadpool(strongswan_service.delete_tunnel_config, tunnel.name)
    
    # 4. Update DB
    tunnel.enabled = False
    tunnel.status = "disconnected"
    await db.commit()
    
    return {"status": "terminated", "name": tunnel.name}


@router.get("/tunnels/{tunnel_id}/status", response_model=IpsecTunnelStatus)
async def get_tunnel_status(
    tunnel_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.view"))
):
    """Get real-time status of a tunnel via VICI."""
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    status = await run_in_threadpool(strongswan_service.get_tunnel_status, tunnel.name)
    
    if status is None:
        raise HTTPException(status_code=500, detail="Failed to get tunnel status")
    
    # Update DB status based on VICI state
    if status["ike_state"] == "ESTABLISHED":
        tunnel.status = "established"
    elif status["ike_state"] == "CONNECTING":
        tunnel.status = "connecting"
    else:
        tunnel.status = "disconnected"
    await db.commit()
    
    return IpsecTunnelStatus(
        tunnel_id=tunnel.id,
        **status
    )


@router.get("/tunnels/{tunnel_id}/logs")
async def get_tunnel_logs(
    tunnel_id: str,
    lines: int = 100,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.view"))
):
    """Get StrongSwan logs filtered by tunnel with error detection."""
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    logs_data = await run_in_threadpool(strongswan_service.get_tunnel_logs, tunnel.name, lines)
    
    return {
        "tunnel_id": tunnel.id,
        "tunnel_name": tunnel.name,
        **logs_data
    }


@router.get("/tunnels/{tunnel_id}/traffic")
async def get_tunnel_traffic(
    tunnel_id: str,
    period: str = "24h",
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.view"))
):
    """
    Get historical traffic statistics for a tunnel.
    
    Args:
        tunnel_id: UUID of the tunnel
        period: Time period - "1h", "6h", "24h", "7d"
    """
    # Validate period
    if period not in ["1h", "6h", "24h", "7d"]:
        raise HTTPException(status_code=400, detail="Invalid period. Use: 1h, 6h, 24h, 7d")
    
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    data = await strongswan_service.get_traffic_history(tunnel.id, period, db)
    
    return {
        "tunnel_id": str(tunnel.id),
        "tunnel_name": tunnel.name,
        "period": period,
        "data_points": len(data),
        "data": data
    }


# --- CHILD SAs (Phase 2) ---

@router.get("/tunnels/{tunnel_id}/children", response_model=List[IpsecChildSaRead])
async def list_child_sas(
    tunnel_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.view"))
):
    """List all Child SAs for a tunnel."""
    result = await db.execute(
        select(IpsecChildSa)
        .where(IpsecChildSa.tunnel_id == tunnel_id)
        .order_by(IpsecChildSa.name)
    )
    children = result.scalars().all()
    return children


@router.post("/tunnels/{tunnel_id}/children", response_model=IpsecChildSaRead)
async def create_child_sa(
    tunnel_id: str,
    data: IpsecChildSaCreate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Create a new Child SA (Phase 2) for a tunnel."""
    # Get tunnel
    result = await db.execute(
        select(IpsecTunnel)
        .options(selectinload(IpsecTunnel.child_sas))
        .where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    # Create Child SA
    child = IpsecChildSa(tunnel_id=tunnel.id, **data.model_dump())
    db.add(child)
    await db.flush()
    await db.refresh(child)
    
    # Regenerate tunnel config with new child
    all_children = tunnel.child_sas + [child]
    child_sas_data = [
        {
            "name": c.name,
            "local_ts": c.local_ts,
            "remote_ts": c.remote_ts,
            "esp_proposal": c.esp_proposal,
            "esp_lifetime": c.esp_lifetime,
            "start_action": c.start_action,
            "close_action": c.close_action,
        }
        for c in all_children if c.enabled
    ]
    
    config = strongswan_service.generate_tunnel_config(
        tunnel_id=tunnel.id,
        name=tunnel.name,
        ike_version=tunnel.ike_version,
        local_address=tunnel.local_address,
        remote_address=tunnel.remote_address,
        local_id=tunnel.local_id,
        remote_id=tunnel.remote_id,
        auth_method=tunnel.auth_method,
        ike_proposal=tunnel.ike_proposal,
        ike_lifetime=tunnel.ike_lifetime,
        dpd_action=tunnel.dpd_action,
        dpd_delay=tunnel.dpd_delay,
        nat_traversal=tunnel.nat_traversal,
        child_sas=child_sas_data
    )
    await run_in_threadpool(strongswan_service.save_tunnel_config, tunnel.name, config)
    
    # Setup FORWARD rules
    await run_in_threadpool(strongswan_service.setup_forward_rules, child.local_ts, child.remote_ts, tunnel.name)
    
    # Reload
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    await db.commit()
    
    logger.info(f"Created Child SA {child.name} for tunnel {tunnel.name}")
    
    return child


@router.put("/tunnels/{tunnel_id}/children/{child_id}", response_model=IpsecChildSaRead)
async def update_child_sa(
    tunnel_id: str,
    child_id: str,
    data: IpsecChildSaUpdate,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Update a Child SA."""
    result = await db.execute(
        select(IpsecChildSa)
        .where(IpsecChildSa.id == child_id)
        .where(IpsecChildSa.tunnel_id == tunnel_id)
    )
    child = result.scalar_one_or_none()
    
    if not child:
        raise HTTPException(status_code=404, detail="Child SA not found")
    
    old_local_ts = child.local_ts
    old_remote_ts = child.remote_ts
    
    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(child, key, value)
    
    # Get tunnel for regeneration
    result = await db.execute(
        select(IpsecTunnel)
        .options(selectinload(IpsecTunnel.child_sas))
        .where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    # Remove old FORWARD rules if TS changed
    if data.local_ts or data.remote_ts:
        await run_in_threadpool(strongswan_service.remove_forward_rules, old_local_ts, old_remote_ts)
        await run_in_threadpool(strongswan_service.setup_forward_rules, child.local_ts, child.remote_ts, tunnel.name)
    
    # Regenerate config
    child_sas_data = [
        {
            "name": c.name,
            "local_ts": c.local_ts,
            "remote_ts": c.remote_ts,
            "esp_proposal": c.esp_proposal,
            "esp_lifetime": c.esp_lifetime,
            "start_action": c.start_action,
            "close_action": c.close_action,
        }
        for c in tunnel.child_sas if c.enabled
    ]
    
    config = strongswan_service.generate_tunnel_config(
        tunnel_id=tunnel.id,
        name=tunnel.name,
        ike_version=tunnel.ike_version,
        local_address=tunnel.local_address,
        remote_address=tunnel.remote_address,
        local_id=tunnel.local_id,
        remote_id=tunnel.remote_id,
        auth_method=tunnel.auth_method,
        ike_proposal=tunnel.ike_proposal,
        ike_lifetime=tunnel.ike_lifetime,
        dpd_action=tunnel.dpd_action,
        dpd_delay=tunnel.dpd_delay,
        nat_traversal=tunnel.nat_traversal,
        child_sas=child_sas_data
    )
    await run_in_threadpool(strongswan_service.save_tunnel_config, tunnel.name, config)
    
    # Reload
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    await db.commit()
    await db.refresh(child)
    
    logger.info(f"Updated Child SA {child.name}")
    
    return child


@router.delete("/tunnels/{tunnel_id}/children/{child_id}")
async def delete_child_sa(
    tunnel_id: str,
    child_id: str,
    db: AsyncSession = Depends(get_session),
    _user: User = Depends(require_permission("ipsec.manage"))
):
    """Delete a Child SA."""
    result = await db.execute(
        select(IpsecChildSa)
        .where(IpsecChildSa.id == child_id)
        .where(IpsecChildSa.tunnel_id == tunnel_id)
    )
    child = result.scalar_one_or_none()
    
    if not child:
        raise HTTPException(status_code=404, detail="Child SA not found")
    
    # Remove FORWARD rules
    await run_in_threadpool(strongswan_service.remove_forward_rules, child.local_ts, child.remote_ts)
    
    # Get tunnel
    result = await db.execute(
        select(IpsecTunnel)
        .options(selectinload(IpsecTunnel.child_sas))
        .where(IpsecTunnel.id == tunnel_id)
    )
    tunnel = result.scalar_one_or_none()
    
    # Delete child
    await db.delete(child)
    await db.flush()
    
    # Regenerate config without deleted child
    remaining_children = [c for c in tunnel.child_sas if c.id != child.id]
    child_sas_data = [
        {
            "name": c.name,
            "local_ts": c.local_ts,
            "remote_ts": c.remote_ts,
            "esp_proposal": c.esp_proposal,
            "esp_lifetime": c.esp_lifetime,
            "start_action": c.start_action,
            "close_action": c.close_action,
        }
        for c in remaining_children if c.enabled
    ]
    
    config = strongswan_service.generate_tunnel_config(
        tunnel_id=tunnel.id,
        name=tunnel.name,
        ike_version=tunnel.ike_version,
        local_address=tunnel.local_address,
        remote_address=tunnel.remote_address,
        local_id=tunnel.local_id,
        remote_id=tunnel.remote_id,
        auth_method=tunnel.auth_method,
        ike_proposal=tunnel.ike_proposal,
        ike_lifetime=tunnel.ike_lifetime,
        dpd_action=tunnel.dpd_action,
        dpd_delay=tunnel.dpd_delay,
        nat_traversal=tunnel.nat_traversal,
        child_sas=child_sas_data
    )
    await run_in_threadpool(strongswan_service.save_tunnel_config, tunnel.name, config)
    
    # Reload
    await run_in_threadpool(strongswan_service.load_all_connections)
    
    await db.commit()
    
    logger.info(f"Deleted Child SA {child.name}")
    
    return {"status": "deleted", "name": child.name}


# --- HELPER FUNCTIONS ---

async def _update_all_secrets(db: AsyncSession):
    """Regenerate secrets file with all tunnels' PSKs."""
    result = await db.execute(
        select(IpsecTunnel).where(IpsecTunnel.auth_method == "psk")
    )
    tunnels = result.scalars().all()
    
    secrets_entries = []
    for tunnel in tunnels:
        if tunnel.psk:
            entry = strongswan_service.generate_secrets_entry(
                name=tunnel.name,
                local_id=tunnel.local_id,
                remote_id=tunnel.remote_id,
                psk=tunnel.psk
            )
            secrets_entries.append(entry)
    
    await run_in_threadpool(strongswan_service.update_secrets_file, secrets_entries)
