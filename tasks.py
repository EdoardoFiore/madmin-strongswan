"""
IPsec VPN Module - Background Tasks

Periodic tasks for traffic statistics collection and maintenance.
"""
import asyncio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Task control
_collector_task = None
_stop_event = asyncio.Event()

COLLECTION_INTERVAL = 60  # seconds
CLEANUP_INTERVAL = 3600  # 1 hour


async def traffic_collector_loop():
    """
    Background task to collect traffic stats every 60 seconds.
    
    Runs continuously until stop_collector() is called.
    """
    from core.database import async_session_maker
    from modules.strongswan.service import strongswan_service
    
    logger.info("Traffic collector started")
    
    cleanup_counter = 0
    
    while not _stop_event.is_set():
        try:
            async with async_session_maker() as db:
                # Collect traffic stats
                collected = await strongswan_service.collect_traffic_stats(db)
                
                # Run cleanup periodically (every hour)
                cleanup_counter += COLLECTION_INTERVAL
                if cleanup_counter >= CLEANUP_INTERVAL:
                    await strongswan_service.cleanup_old_stats(db, days=30)
                    cleanup_counter = 0
                    
        except Exception as e:
            logger.error(f"Traffic collector error: {e}")
        
        # Wait for next collection interval (or stop signal)
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=COLLECTION_INTERVAL)
            break  # Stop event was set
        except asyncio.TimeoutError:
            pass  # Continue collecting
    
    logger.info("Traffic collector stopped")


def start_collector():
    """Start the traffic collector background task."""
    global _collector_task
    
    if _collector_task is not None and not _collector_task.done():
        logger.warning("Traffic collector already running")
        return
    
    _stop_event.clear()
    _collector_task = asyncio.create_task(traffic_collector_loop())
    logger.info("Traffic collector task created")


def stop_collector():
    """Stop the traffic collector background task."""
    global _collector_task
    
    _stop_event.set()
    
    if _collector_task is not None:
        _collector_task.cancel()
        _collector_task = None
        logger.info("Traffic collector task stopped")
