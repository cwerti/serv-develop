from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from typing import List

from models import User, UsersAndRoles, RolesAndPermissions
from utils.database_connection import db_async_session
from utils.permission import require_permission

ref = APIRouter()


@ref.get("/", dependencies=[Depends(require_permission("get-list_user"))])
async def get_users(session: AsyncSession = Depends(db_async_session)):
    """Получение списка пользователей"""
    result = await session.execute(
        select(User).where(User.is_active == True)
    )
    users = result.scalars().all()
    return users


@ref.get("/{id}/role", response_model=List[str], dependencies=[Depends(require_permission("get_roles_user"))])
async def get_user_roles(id: int, session: AsyncSession = Depends(db_async_session)):
    """Получение ролей пользователя"""
    result = await session.execute(
        select(User).where(
            User.id == id,
            User.is_active == True
        )
    )
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return [role.code for role in user.roles]


@ref.post("/{id}/role", dependencies=[Depends(require_permission("assign_role_user"))])
async def assign_role(id: int, role_id: int, session: AsyncSession = Depends(db_async_session)):
    """Присвоение роли пользователю"""
    # Проверяем существование пользователя
    user_result = await session.execute(
        select(User).where(
            User.id == id,
            User.is_active == True
        )
    )
    user = user_result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверяем, не назначена ли уже роль
    existing_result = await session.execute(
        select(UsersAndRoles).where(
            UsersAndRoles.user_id == id,
            UsersAndRoles.role_id == role_id
        )
    )
    if existing_result.scalars().first():
        raise HTTPException(status_code=400, detail="Роль уже присвоена пользователю")

    # Создаем связь
    user_role = UsersAndRoles(user_id=id, role_id=role_id)
    session.add(user_role)
    await session.commit()
    return {"status": "success"}


@ref.delete("/{id}/role/{role_id}", dependencies=[Depends(require_permission("hard_delete_role_user"))])
async def delete_role(id: int, role_id: int, session: AsyncSession = Depends(db_async_session)):
    """Жесткое удаление роли у пользователя"""
    result = await session.execute(
        select(UsersAndRoles).where(
            UsersAndRoles.user_id == id,
            UsersAndRoles.role_id == role_id
        )
    )
    user_role = result.scalars().first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Связь пользователь-роль не найдена")

    await session.delete(user_role)
    await session.commit()
    return {"status": "success"}


@ref.delete("/{id}/role/{role_id}/soft", dependencies=[Depends(require_permission("soft_delete_role_user"))])
async def soft_delete_role(id: int, role_id: int, session: AsyncSession = Depends(db_async_session)):
    """Мягкое удаление роли у пользователя"""
    result = await session.execute(
        select(UsersAndRoles).where(
            UsersAndRoles.user_id == id,
            UsersAndRoles.role_id == role_id
        )
    )
    user_role = result.scalars().first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Связь пользователь-роль не найдена")

    user_role.is_deleted = True
    await session.commit()
    return {"status": "success"}


@ref.post("/{id}/role/{role_id}/restore", dependencies=[Depends(require_permission("restore_role_user"))])
async def restore_role(id: int, role_id: int, session: AsyncSession = Depends(db_async_session)):
    """Восстановление мягко удаленной роли у пользователя"""
    result = await session.execute(
        select(UsersAndRoles).where(
            UsersAndRoles.user_id == id,
            UsersAndRoles.role_id == role_id,
            UsersAndRoles.is_deleted == True
        )
    )
    user_role = result.scalars().first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Удаленная связь пользователь-роль не найдена")

    user_role.is_deleted = False
    await session.commit()
    return {"status": "success"}


@ref.delete("/{id}/permission/{role_id}/soft", dependencies=[Depends(require_permission("soft_delete_role_user"))])
async def soft_delete_permission(id: int, role_id: int, session: AsyncSession = Depends(db_async_session)):
    """Мягкое удаление разрешения у роли"""
    result = await session.execute(
        select(RolesAndPermissions).where(
            RolesAndPermissions.permission_id == id,
            RolesAndPermissions.role_id == role_id
        )
    )
    user_role = result.scalars().first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Связь азрешение-роль не найдена")

    user_role.is_deleted = True
    await session.commit()
    return {"status": "success"}
