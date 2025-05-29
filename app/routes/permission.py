from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from datetime import datetime

from models import Permission, User, RolesAndPermissions
from schemas.session import PermissionDTO, PermissionCreateRequest, PermissionCollectionDTO, PermissionUpdateRequest
from utils.auth.passwwords import get_current_user
from utils.database_connection import db_async_session
from utils.permission import require_permission

permissions = APIRouter()


@permissions.post("/", response_model=PermissionDTO, dependencies=[Depends(require_permission("create_permission"))])
async def create_permission(request: PermissionCreateRequest, session: AsyncSession = Depends(db_async_session)):
    # Проверка уникальности
    result = await session.execute(
        select(Permission).where(
            (Permission.name == request.name) |
            (Permission.code == request.code)
        )
    )
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Permission name or code must be unique")

    perm = Permission(name=request.name, description=request.description, code=request.code)
    session.add(perm)
    await session.commit()
    await session.refresh(perm)
    return perm


@permissions.get("/", response_model=PermissionCollectionDTO,
                 dependencies=[Depends(require_permission("get-list_permission"))])
async def list_permissions(session: AsyncSession = Depends(db_async_session)):
    result = await session.execute(
        select(Permission).where(Permission.is_deleted == False)
    )
    perms = result.scalars().all()
    return PermissionCollectionDTO(permissions=perms)


@permissions.get("/{permission_id}", response_model=PermissionDTO,
                 dependencies=[Depends(require_permission("read_permission"))])
async def get_permission(permission_id: int, session: AsyncSession = Depends(db_async_session)):
    result = await session.execute(
        select(Permission).where(
            Permission.id == permission_id,
            Permission.is_deleted == False
        )
    )
    perm = result.scalars().first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    return perm


@permissions.put("/{permission_id}", response_model=PermissionDTO,
                 dependencies=[Depends(require_permission("update_permission"))])
async def update_permission(permission_id: int, request: PermissionUpdateRequest,
                            session: AsyncSession = Depends(db_async_session)):
    # Получаем разрешение для обновления
    result = await session.execute(
        select(Permission).where(
            Permission.id == permission_id,
            Permission.is_deleted == False
        )
    )
    perm = result.scalars().first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Проверка уникальности name
    if request.name:
        name_result = await session.execute(
            select(Permission).where(
                Permission.name == request.name,
                Permission.id != permission_id
            )
        )
        if name_result.scalars().first():
            raise HTTPException(status_code=400, detail="Permission name must be unique")

    # Проверка уникальности code
    if request.code:
        code_result = await session.execute(
            select(Permission).where(
                Permission.code == request.code,
                Permission.id != permission_id
            )
        )
        if code_result.scalars().first():
            raise HTTPException(status_code=400, detail="Permission code must be unique")

    # Обновление полей
    for field, value in request.dict(exclude_unset=True).items():
        setattr(perm, field, value)

    await session.commit()
    await session.refresh(perm)
    return perm


@permissions.delete("/{permission_id}", response_model=PermissionDTO,
                    dependencies=[Depends(require_permission("soft_delete_permission"))])
async def soft_delete_permission(
        permission_id: int,
        session: AsyncSession = Depends(db_async_session),
        current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление разрешения (установка флага is_deleted)
    """
    try:
        # Проверяем существование разрешения
        result = await session.execute(
            select(Permission)
            .where(
                Permission.id == permission_id,
                Permission.is_deleted == False
            )
        )
        perm = result.scalars().first()

        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено или уже удалено")

        # Проверяем, не является ли разрешение системным
        if any(perm.code.startswith(prefix) for prefix in
               ["create_", "read_", "update_", "delete_", "get-list_", "restore_"]):
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить системное разрешение"
            )

        # Помечаем разрешение как удаленное
        perm.is_deleted = True
        perm.deleted_by = current_user.id
        perm.deleted_at = datetime.utcnow()

        await session.commit()
        await session.refresh(perm)
        return perm

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при удалении разрешения: {str(e)}"
        )


@permissions.delete("/{permission_id}/hard", response_model=PermissionDTO,
                    dependencies=[Depends(require_permission("hard_delete_permission"))])
async def hard_delete_permission(
        permission_id: int,
        session: AsyncSession = Depends(db_async_session),
        current_user: User = Depends(get_current_user)
):
    """
    Жесткое удаление разрешения (физическое удаление из БД)
    """
    try:
        # Проверяем существование разрешения
        result = await session.execute(
            select(Permission)
            .where(Permission.id == permission_id)
        )
        perm = result.scalars().first()

        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено")

        # Проверяем, не является ли разрешение системным
        if any(perm.code.startswith(prefix) for prefix in
               ["create_", "read_", "update_", "delete_", "get-list_", "restore_"]):
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить системное разрешение"
            )

        # Проверяем, есть ли связанные роли
        role_links_count = await session.scalar(
            select(func.count())
            .select_from(RolesAndPermissions)
            .where(RolesAndPermissions.permission_id == permission_id)
        )

        if role_links_count > 0:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить разрешение, пока оно назначено ролям. Сначала удалите все связи с ролями."
            )

        # Физически удаляем разрешение
        await session.delete(perm)
        await session.commit()
        return perm

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при физическом удалении разрешения: {str(e)}"
        )


@permissions.post("/{permission_id}/restore", response_model=PermissionDTO,
                  dependencies=[Depends(require_permission("restore_permission"))])
async def restore_permission(
        permission_id: int,
        session: AsyncSession = Depends(db_async_session),
        current_user: User = Depends(get_current_user)
):
    """
    Восстановление мягко удаленного разрешения
    """
    try:
        result = await session.execute(
            select(Permission)
            .where(
                Permission.id == permission_id,
                Permission.is_deleted == True
            )
        )
        perm = result.scalars().first()

        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено или не было удалено")

        perm.is_deleted = False
        perm.deleted_by = None
        perm.deleted_at = None

        await session.commit()
        await session.refresh(perm)
        return perm

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при восстановлении разрешения: {str(e)}"
        )
