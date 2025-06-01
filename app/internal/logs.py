from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import ConfigLog
from models import ChangeLogs, Role, Permission
from schemas.exception import UserNotFoundError, RoleNotFoundError, PermissionNotFoundError


async def get_user_logs(session: AsyncSession, user_id: int):
    result = await session.execute(
        select(ChangeLogs).where(
            ChangeLogs.entity_type == ConfigLog.User,
            ChangeLogs.entity_id == user_id
        )
    )
    logs = result.scalars().all()

    if not logs:
        raise UserNotFoundError()

    return logs


async def get_all_roles(session: AsyncSession, role_id: int):
    result = await session.execute(
        select(ChangeLogs).where(
            ChangeLogs.entity_type == ConfigLog.Role,
            ChangeLogs.entity_id == role_id
        )
    )
    logs = result.scalars().all()

    if not logs:
        raise RoleNotFoundError()

    return logs


async def get_all_permission(session: AsyncSession, permiossion_id: int):
    result = await session.execute(
        select(Permission).where(
            ChangeLogs.entity_type == ConfigLog.Permission,
            ChangeLogs.entity_id == permiossion_id
        )
    )
    logs = result.scalars().all()

    if not logs:
        raise PermissionNotFoundError()

    return logs

# async def get_role_permissions(session: AsyncSession, role_id: int):
#     role = await session.get(Role, role_id)
#     if not role:
#         raise RoleNotFoundError()
#
#     result = await session.execute(
#         select(Permission)
#         .join(Role.permissions)
#         .where(Role.id == role_id)
#     )
#     return result.scalars().all()
