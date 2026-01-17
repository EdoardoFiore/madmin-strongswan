"""
IPsec VPN Module - Initial Database Migration

Creates IPsec tables using direct engine access.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel


async def upgrade(session: AsyncSession) -> None:
    """Create IPsec module tables."""
    # Import models to register them in SQLModel metadata
    from modules.strongswan.models import (
        IpsecTunnel, IpsecChildSa, IpsecTrafficStats
    )
    
    # Import the engine directly from database module
    from core.database import engine
    
    # Use the engine directly for DDL operations
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    print("IPsec VPN module tables created")


async def downgrade(session: AsyncSession) -> None:
    """Drop IPsec module tables."""
    from core.database import engine
    from sqlalchemy import text
    
    tables = ["ipsec_child_sa", "ipsec_tunnel"]
    
    async with engine.begin() as conn:
        for table in tables:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
