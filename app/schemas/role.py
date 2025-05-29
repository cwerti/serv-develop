from pydantic import BaseModel, Field, validator, ConfigDict
from typing import Optional, List

from schemas.core import Model


class RoleBase(Model):
    name: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    code: str = Field(..., max_length=100)

    model_config = ConfigDict(from_attributes=True)


class RoleCreateRequest(RoleBase):
    pass


class RoleUpdateRequest(Model):
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    code: Optional[str] = Field(None, max_length=100)

    model_config = ConfigDict(from_attributes=True)


class RoleDTO(RoleBase):
    id: int
    permissions: List[str] = []
    model_config = ConfigDict(from_attributes=True)

    @validator('permissions', pre=True)
    def extract_permission_codes(cls, v):
        if isinstance(v, list):
            return [p.code if hasattr(p, 'code') else p for p in v]
        return v


class RoleCollectionDTO(Model):
    roles: List[RoleDTO]

    model_config = ConfigDict(from_attributes=True)
