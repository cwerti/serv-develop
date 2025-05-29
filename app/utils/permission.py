from fastapi import HTTPException

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models import User, Role
from utils.auth.passwwords import get_current_user
from utils.database_connection import db_async_session


async def get_user_permissions(user: User, db: AsyncSession):
    # Загружаем пользователя заново, включая роли и permissions
    result = await db.execute(
        select(User)
        .where(User.id == user.id)
        .options(
            selectinload(User.user_roles)  # Загружаем роли
            .selectinload(Role.role_permissions)  # Загружаем permissions для каждой роли
        )
    )
    user = result.scalars().first()

    permissions = set()
    for role in user.user_roles:
        for perm in role.role_permissions:
            if not perm.is_deleted and not role.is_deleted:
                permissions.add(perm.code)
    return permissions


def require_permission(permission_code: str):
    async def dependency(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(db_async_session)
    ):
        perms = await get_user_permissions(current_user, db)
        if permission_code not in perms:
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission_code}' required"
            )
        return True

    return dependency
