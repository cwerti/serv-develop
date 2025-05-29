from pydantic import Field, ConfigDict
from typing import Optional, List

from schemas.core import Model


class PermissionBase(Model):
    name: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    code: str = Field(..., max_length=100)

    model_config = ConfigDict(from_attributes=True)


class PermissionCreateRequest(PermissionBase):
    pass


class PermissionUpdateRequest(Model):
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    code: Optional[str] = Field(None, max_length=100)

    model_config = ConfigDict(from_attributes=True)


class PermissionDTO(PermissionBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


class PermissionCollectionDTO(Model):
    permissions: List[PermissionDTO]
    model_config = ConfigDict(from_attributes=True)
