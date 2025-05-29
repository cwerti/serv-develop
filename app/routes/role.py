from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from requests import Session
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Role, User
from schemas.role import RoleCreateRequest, RoleDTO, RoleCollectionDTO, RoleUpdateRequest
from utils.auth.passwwords import get_current_user
from utils.database_connection import db_async_session
from utils.permission import require_permission

role = APIRouter()


@role.post("/", response_model=RoleDTO, dependencies=[Depends(require_permission("create_role"))])
async def create_role(request: RoleCreateRequest, session: AsyncSession = Depends(db_async_session)):
    # Проверка уникальности с использованием асинхронных запросов
    result = await session.execute(
        select(Role).where((Role.name == request.name) | (Role.code == request.code)))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Role name or code must be unique")

    role = Role(name=request.name, description=request.description, code=request.code)
    session.add(role)
    await session.commit()
    await session.refresh(role)
    return role


@role.get("/", response_model=RoleCollectionDTO, dependencies=[Depends(require_permission("get-list_role"))])
async def list_roles(session: AsyncSession = Depends(db_async_session)):
    result = await session.execute(select(Role).where(Role.is_deleted == False))
    roles = result.scalars().all()
    return RoleCollectionDTO(roles=roles)


@role.get("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("read_role"))])
async def get_role(role_id: int, session: AsyncSession = Depends(db_async_session)):
    result = await session.execute(
        select(Role).where(Role.id == role_id, Role.is_deleted == False)
    )
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


@role.put("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("update_role"))])
async def update_role(role_id: int, request: RoleUpdateRequest, session: AsyncSession = Depends(db_async_session)):
    # Получаем роль
    result = await session.execute(
        select(Role).where(Role.id == role_id, Role.is_deleted == False)
    )
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    # Проверяем уникальность имени
    if request.name:
        name_result = await session.execute(
            select(Role).where(Role.name == request.name, Role.id != role_id)
        )
        if name_result.scalars().first():
            raise HTTPException(status_code=400, detail="Role name must be unique")

    # Проверяем уникальность кода
    if request.code:
        code_result = await session.execute(
            select(Role).where(Role.code == request.code, Role.id != role_id)
        )
        if code_result.scalars().first():
            raise HTTPException(status_code=400, detail="Role code must be unique")

    # Обновляем поля
    for field, value in request.dict(exclude_unset=True).items():
        setattr(role, field, value)

    await session.commit()
    await session.refresh(role)
    return role





@role.delete("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("soft_delete_role"))])
async def soft_delete_role(
        role_id: int,
        session: AsyncSession = Depends(db_async_session),
        current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление роли (установка флага is_deleted)
    """
    try:
        # Проверяем существование роли
        result = await session.execute(
            select(Role).where(
                Role.id == role_id,
                Role.is_deleted == False
            )
        )
        role = result.scalars().first()

        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или уже удалена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить системную роль"
            )

        # Помечаем роль как удаленную
        role.is_deleted = True
        role.deleted_by = current_user.id
        role.deleted_at = datetime.utcnow()

        await session.commit()
        await session.refresh(role)
        return role

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при удалении роли: {str(e)}"
        )


@role.delete("/{role_id}/hard", response_model=RoleDTO,
               dependencies=[Depends(require_permission("hard_delete_role"))])
async def hard_delete_role(
        role_id: int,
        session: AsyncSession = Depends(db_async_session),
        current_user: User = Depends(get_current_user)
):
    """
    Жесткое удаление роли (физическое удаление из БД)
    """
    try:
        # Проверяем существование роли
        result = await session.execute(
            select(Role).where(Role.id == role_id)
        )
        role = result.scalars().first()

        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить системную роль"
            )

        # Проверяем, есть ли связанные пользователи
        if len(role.users) > 0:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить роль, пока она назначена пользователям"
            )

        # Физически удаляем роль
        await session.delete(role)
        await session.commit()
        return role

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при физическом удалении роли: {str(e)}"
        )


@role.post("/{role_id}/restore", response_model=RoleDTO, dependencies=[Depends(require_permission("restore_role"))])
async def restore_role(
        role_id: int,
        session: AsyncSession = Depends(db_async_session),
        current_user: User = Depends(get_current_user)
):
    """
    Восстановление мягко удаленной роли
    """
    try:
        result = await session.execute(
            select(Role).where(
                Role.id == role_id,
                Role.is_deleted == True
            )
        )
        role = result.scalars().first()

        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или не была удалена")

        role.is_deleted = False
        role.deleted_by = None
        role.deleted_at = None

        await session.commit()
        await session.refresh(role)
        return role

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при восстановлении роли: {str(e)}"
        )