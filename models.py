"""
IPsec VPN Module - Database Models

SQLModel tables for IPsec tunnels (IKE SA) and Child SAs (Phase 2).
Supports multiple tunnels and multiple Child SAs per tunnel.
"""
from typing import Optional, List
from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship
import uuid


class IpsecTunnel(SQLModel, table=True):
    """
    IPsec tunnel (Phase 1 - IKE SA).
    
    Represents a site-to-site IPsec connection with IKE negotiation parameters.
    A tunnel can have multiple Child SAs (Phase 2) for different traffic selectors.
    """
    __tablename__ = "ipsec_tunnel"
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, max_length=64, index=True)
    enabled: bool = Field(default=True)
    
    # IKE Version and Mode
    ike_version: str = Field(default="2")  # "1" or "2"
    mode: str = Field(default="main")  # "main" or "aggressive" (IKEv1 only)
    
    # Addresses
    local_address: str = Field(max_length=255)  # Local gateway IP
    remote_address: str = Field(max_length=255)  # Remote peer IP or FQDN
    
    # Identity (optional)
    local_id: Optional[str] = Field(default=None, max_length=255)
    remote_id: Optional[str] = Field(default=None, max_length=255)
    
    # Authentication
    auth_method: str = Field(default="psk")  # "psk" or "pubkey"
    psk: str = Field(default="")  # Pre-Shared Key (stored in secrets)
    
    # IKE Proposal (encryption-integrity-dhgroup)
    ike_proposal: str = Field(default="aes256-sha256-modp2048")
    ike_lifetime: int = Field(default=28800)  # Seconds
    
    # Dead Peer Detection
    dpd_action: str = Field(default="restart")  # "restart", "clear", "none"
    dpd_delay: int = Field(default=30)  # Seconds
    
    # NAT Traversal
    nat_traversal: bool = Field(default=True)
    
    # Status
    status: str = Field(default="disconnected")  # disconnected, connecting, established
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    child_sas: List["IpsecChildSa"] = Relationship(
        back_populates="tunnel",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class IpsecChildSa(SQLModel, table=True):
    """
    IPsec Child SA (Phase 2).
    
    Defines traffic selectors and ESP parameters for encrypted traffic.
    Multiple Child SAs can exist per tunnel for different subnets.
    """
    __tablename__ = "ipsec_child_sa"
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    tunnel_id: uuid.UUID = Field(foreign_key="ipsec_tunnel.id", index=True)
    name: str = Field(max_length=64)
    
    # Traffic Selectors (CIDR notation)
    local_ts: str = Field(max_length=100)  # e.g., "192.168.1.0/24"
    remote_ts: str = Field(max_length=100)  # e.g., "10.0.0.0/24"
    
    # ESP Proposal
    esp_proposal: str = Field(default="aes256-sha256-modp2048")
    esp_lifetime: int = Field(default=3600)  # Seconds
    
    # Perfect Forward Secrecy
    pfs_group: Optional[str] = Field(default="modp2048")  # DH group or None
    
    # Actions
    start_action: str = Field(default="trap")  # "none", "start", "trap"
    close_action: str = Field(default="restart")  # "none", "restart", "clear"
    
    enabled: bool = Field(default=True)
    
    # Relationship
    tunnel: "IpsecTunnel" = Relationship(back_populates="child_sas")


# --- Pydantic Schemas for API ---

class IpsecTunnelCreate(SQLModel):
    """Schema for creating a new tunnel."""
    name: str
    ike_version: str = "2"
    mode: str = "main"
    local_address: str
    remote_address: str
    local_id: Optional[str] = None
    remote_id: Optional[str] = None
    auth_method: str = "psk"
    psk: str = ""
    ike_proposal: str = "aes256-sha256-modp2048"
    ike_lifetime: int = 28800
    dpd_action: str = "restart"
    dpd_delay: int = 30
    nat_traversal: bool = True


class IpsecTunnelUpdate(SQLModel):
    """Schema for updating a tunnel."""
    name: Optional[str] = None
    enabled: Optional[bool] = None
    ike_version: Optional[str] = None
    mode: Optional[str] = None
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    local_id: Optional[str] = None
    remote_id: Optional[str] = None
    auth_method: Optional[str] = None
    psk: Optional[str] = None
    ike_proposal: Optional[str] = None
    ike_lifetime: Optional[int] = None
    dpd_action: Optional[str] = None
    dpd_delay: Optional[int] = None
    nat_traversal: Optional[bool] = None


class IpsecTunnelRead(SQLModel):
    """Schema for reading a tunnel."""
    id: uuid.UUID
    name: str
    enabled: bool
    ike_version: str
    mode: str
    local_address: str
    remote_address: str
    local_id: Optional[str]
    remote_id: Optional[str]
    auth_method: str
    ike_proposal: str
    ike_lifetime: int
    dpd_action: str
    dpd_delay: int
    nat_traversal: bool
    status: str
    created_at: datetime
    updated_at: datetime
    child_sa_count: int = 0


class IpsecChildSaCreate(SQLModel):
    """Schema for creating a Child SA."""
    name: str
    local_ts: str
    remote_ts: str
    esp_proposal: str = "aes256-sha256-modp2048"
    esp_lifetime: int = 3600
    pfs_group: Optional[str] = "modp2048"
    start_action: str = "trap"
    close_action: str = "restart"


class IpsecChildSaUpdate(SQLModel):
    """Schema for updating a Child SA."""
    name: Optional[str] = None
    local_ts: Optional[str] = None
    remote_ts: Optional[str] = None
    esp_proposal: Optional[str] = None
    esp_lifetime: Optional[int] = None
    pfs_group: Optional[str] = None
    start_action: Optional[str] = None
    close_action: Optional[str] = None
    enabled: Optional[bool] = None


class IpsecChildSaRead(SQLModel):
    """Schema for reading a Child SA."""
    id: uuid.UUID
    tunnel_id: uuid.UUID
    name: str
    local_ts: str
    remote_ts: str
    esp_proposal: str
    esp_lifetime: int
    pfs_group: Optional[str]
    start_action: str
    close_action: str
    enabled: bool


class IpsecTunnelStatus(SQLModel):
    """Schema for tunnel status from VICI."""
    tunnel_id: uuid.UUID
    ike_state: str  # ESTABLISHED, CONNECTING, DISCONNECTED
    local_host: Optional[str] = None
    remote_host: Optional[str] = None
    initiator: bool = False
    established_time: Optional[int] = None  # Seconds
    rekey_time: Optional[int] = None  # Seconds until rekey
    child_sas: List[dict] = []  # Child SA status


# --- Algorithm Options for UI ---

IKE_ENCRYPTION_OPTIONS = [
    {"value": "aes256", "label": "AES-256", "security": 5},
    {"value": "aes128", "label": "AES-128", "security": 4},
    {"value": "aes256gcm16", "label": "AES-256-GCM (IKEv2)", "security": 5},
    {"value": "chacha20poly1305", "label": "ChaCha20-Poly1305 (IKEv2)", "security": 5},
    {"value": "3des", "label": "3DES (Legacy)", "security": 2},
]

IKE_INTEGRITY_OPTIONS = [
    {"value": "sha256", "label": "SHA-256", "security": 5},
    {"value": "sha384", "label": "SHA-384", "security": 5},
    {"value": "sha512", "label": "SHA-512", "security": 5},
    {"value": "sha1", "label": "SHA-1 (Legacy)", "security": 3},
]

DH_GROUP_OPTIONS = [
    {"value": "modp2048", "label": "MODP 2048-bit", "security": 4},
    {"value": "modp3072", "label": "MODP 3072-bit", "security": 5},
    {"value": "modp4096", "label": "MODP 4096-bit", "security": 5},
    {"value": "ecp256", "label": "ECP 256-bit", "security": 5},
    {"value": "ecp384", "label": "ECP 384-bit", "security": 5},
    {"value": "curve25519", "label": "Curve25519", "security": 5},
]
