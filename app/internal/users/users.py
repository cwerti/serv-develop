from typing import Optional

import fastapi
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, or_, select, insert
from sqlalchemy.exc import IntegrityError
from models import User, Role, UsersAndRoles
from schemas.auth import RegisterRequest

from utils.auth.passwwords import generate_password_hash


async def user_exists(
        session: AsyncSession,
        login: str,
        email: str,
        user_id: int = None,
        include_deleted: bool = False,
        options=None,  # noqa: ANN001
) -> Optional[User]:
    """
    Проверка на существование юзера по логину или почте.

    При наличии нескольких пользователей под 1 почтой (если пользователь удалён, то его почта не уникальна)
    будет выдан неудалённый пользователь (при наличии)
    """
    users = await users_exists(session, login, email, user_id, include_deleted=include_deleted, options=options)
    return users[0] if len(users) > 0 else None


async def users_exists(
        session: AsyncSession,
        login: str,
        email: str,
        user_id: int = None,
        include_deleted: bool = False,
        options=None,  # noqa: ANN001
) -> list[User]:
    """Извращённая проверка на существование нескольких пользователей с указанными данными."""

    query = (
        select(User)
        .where(or_(func.lower(User.username) == func.lower(login), func.lower(User.email) == func.lower(email)))
        .order_by(User.deleted_at.desc())
    )

    if user_id:
        query = query.where(User.id != user_id)

    if not include_deleted:
        query = query.where(User.deleted_at.is_(None))

    if options:
        query = query.options(*options)

    users = (await session.execute(query)).scalars().all()

    return users


async def check_credentials(session: AsyncSession, login: str, email: str, user_id: int = None) -> None:  # noqa: C901
    """
    Проверка данных для регистрации или создания нового пользователя.

    :param session: сессия бд
    :param login: логин пользователя
    :param email: почта для пользователя
    :raises fastapi.HTTPException: 409 ошибка, при конфликте пользователей
    """
    # т.к. почта не уникальна, то нам нужно проверить всех пользователей
    if users := (await users_exists(session, login, email, include_deleted=True, user_id=user_id)):
        exists_exception = fastapi.HTTPException(
            409, detail="Пользователь с указанным логином или почтой уже существует"
        )

        # логин уникален и создавать второго такого нельзя
        for existing_user in users:
            if existing_user.login == login:
                raise exists_exception

        for existing_user in users:
            if existing_user.deleted_at is None:
                raise exists_exception
    await session.flush()


async def user_create(
        session: AsyncSession,
        user_data: RegisterRequest,
        options: list | None = None
) -> User:
    if user_data.password != user_data.confirm_password:
        raise fastapi.HTTPException(
            status_code=400,
            detail={"message": "Пароли не совпадают"},
        )

    password = generate_password_hash(user_data.password)

    try:
        # Создаем пользователя через обычное добавление в сессию
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            password=password,
            birthday=user_data.birthday,
            is_active=True
        )
        session.add(new_user)

        # Получаем роль "user"
        role_result = await session.execute(
            select(Role).where(Role.code == "user")
        )
        user_role = role_result.scalar_one_or_none()

        if user_role:
            user_role_link = UsersAndRoles(
                user_id=new_user.id,
                role_id=user_role.id
            )
            session.add(user_role_link)

        await session.commit()
        await session.refresh(new_user)

        return new_user

    except IntegrityError as e:
        await session.rollback()
        if "duplicate key" in str(e):
            raise ValueError("Пользователь с таким email или username уже существует") from e
        raise ValueError("Ошибка целостности базы данных") from e
    except Exception as e:
        await session.rollback()
        raise ValueError(f"Ошибка при создании пользователя: {str(e)}") from e


async def get_user(session: AsyncSession, user_id: int) -> User:
    query = (
        select(User)
        .where(User.id == user_id)
        .order_by(User.deleted_at.desc())
    )
    user = (await session.execute(query)).scalar_one_or_none()
    return user
