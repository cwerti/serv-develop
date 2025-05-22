from typing import Any
import os
import imghdr

from sqlalchemy import (
    Column, DateTime, Integer, String, Boolean, Text, ForeignKey,
    Index, CheckConstraint, Numeric, Enum, Table
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func
from enum import IntEnum

from models.core import Base, TimestampMixin, fresh_timestamp


def attachment_is_image_default(context: Any) -> bool:
    return is_image(context.get_current_parameters()["path"])


def is_image(path: os.PathLike) -> bool:
    return imghdr.what(path) is not None


# user_role_association = Table(
#     'user_roles',
#     Base.metadata,
#     Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
#     Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
# )


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email ~* '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$'",
                        name="valid_email"),
    )

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(220), nullable=False)
    password = Column(String(256), nullable=False)
    birthday = Column(DateTime, nullable=False)


# class Role(TimestampMixin, Base):
#     __tablename__ = "roles"
#
#     id = Column(Integer, primary_key=True)
#     name = Column(Text, nullable=False, unique=True)
#     description = Column(Text)
#     is_core = Column(Boolean, server_default="false")
#
#     users = relationship("User", back_populates="role")
