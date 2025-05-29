from typing import Any, List
import os
import imghdr

from sqlalchemy import (
    Column, DateTime, Integer, String, Boolean, Text, ForeignKey,
    Index, CheckConstraint, Numeric, Enum, Table, UniqueConstraint
)
from sqlalchemy.ext.hybrid import hybrid_property
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

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    birthday = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    user_roles = relationship('Role',
                              secondary='users_and_roles',
                              primaryjoin='and_(User.id == UsersAndRoles.user_id, UsersAndRoles.is_deleted == False)',
                              secondaryjoin='Role.id == UsersAndRoles.role_id',
                              back_populates='users')


class Role(TimestampMixin, Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    code = Column(String(100), unique=True, nullable=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    users = relationship('User',
                         secondary='users_and_roles',
                         primaryjoin='and_(Role.id == UsersAndRoles.role_id, UsersAndRoles.is_deleted == False)',
                         secondaryjoin='User.id == UsersAndRoles.user_id',
                         back_populates='user_roles')
    role_permissions = relationship('Permission', secondary='roles_and_permissions', back_populates='permission_roles')


class Permission(TimestampMixin, Base):
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    code = Column(String(100), unique=True, nullable=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    permission_roles = relationship('Role', secondary='roles_and_permissions', back_populates='role_permissions')


class UsersAndRoles(TimestampMixin, Base):
    __tablename__ = 'users_and_roles'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)
    is_deleted = Column(Boolean, default=False)
    deleted_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    __table_args__ = (UniqueConstraint('user_id', 'role_id', name='_user_role_uc'),)

    # Определяем отношения для аудита
    deleter = relationship('User', foreign_keys=[deleted_by], overlaps="user_roles,users")
    creator = relationship('User', foreign_keys=[created_by], overlaps="user_roles,users")
    # Основное отношение для связи пользователь-роль
    user = relationship('User', foreign_keys=[user_id], overlaps="user_roles,users")
    role = relationship('Role', foreign_keys=[role_id], overlaps="user_roles,users")


class RolesAndPermissions(TimestampMixin, Base):
    __tablename__ = 'roles_and_permissions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=False)
    __table_args__ = (UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),)
