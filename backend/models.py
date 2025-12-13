"""
Data Models và Storage cho API
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class KeyEntry(BaseModel):
    """Public key entry trong directory"""
    id: str
    name: str
    department: str
    public_key: str
    created_at: str


class VerifyResponse(BaseModel):
    """Response model cho signature verification"""
    valid: bool
    message: str
    signer: Optional[str] = None


class DirectoryResponse(BaseModel):
    """Response model cho directory listing"""
    entries: list[KeyEntry]


# In-memory storage cho public keys
# Trong production, nên dùng database
key_directory: dict[str, KeyEntry] = {}
