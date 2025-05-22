import re
from datetime import date
from typing import Annotated

from pydantic import field_validator, Field, EmailStr

from schemas.core import Model


class LoginRequest(Model):
    username: Annotated[
        str,
        Field(..., description="Имя пользователя", min_length=7)
    ]
    password: Annotated[
        str,
        Field(..., description="Пароль пользователя", min_length=8)
    ]

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not v[0].isupper():
            raise ValueError('Username must start with an uppercase letter')
        if not re.fullmatch(r'^[A-Za-z]+$', v):
            raise ValueError('Username can only contain Latin letters')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least 1 digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least 1 uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least 1 lowercase letter')
        if not any(not char.isalnum() for char in v):
            raise ValueError('Password must contain at least 1 special character')
        return v


class RegisterRequest(Model):
    username: Annotated[
        str,
        Field(..., description="Имя пользователя", min_length=7)
    ]
    email: Annotated[
        EmailStr,
        Field(..., description="Email пользователя")
    ]
    password: Annotated[
        str,
        Field(..., description="Пароль пользователя", min_length=8)
    ]
    confirm_password: Annotated[
        str,
        Field(..., alias="_password", description="Подтверждение пароля")
    ]
    birthday: Annotated[
        date,
        Field(..., description="Дата рождения в формате YYYY-MM-DD")
    ]

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not v[0].isupper():
            raise ValueError('Username must start with an uppercase letter')
        if not re.fullmatch(r'^[A-Za-z]+$', v):
            raise ValueError('Username can only contain Latin letters')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least 1 digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least 1 uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least 1 lowercase letter')
        if not any(not char.isalnum() for char in v):
            raise ValueError('Password must contain at least 1 special character')
        return v

    @field_validator('confirm_password')
    @classmethod
    def validate_confirm_password(cls, v: str, values) -> str:
        if 'password' in values.data and v != values.data['password']:
            raise ValueError('Passwords do not match')
        return v

    @field_validator('birthday')
    @classmethod
    def validate_birthday(cls, v: date) -> date:
        today = date.today()
        age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
        if age < 14:
            raise ValueError('User must be at least 14 years old')
        return v

    class Config:
        populate_by_name = True
