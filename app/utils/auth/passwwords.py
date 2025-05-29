from datetime import timedelta, datetime

import fastapi
import jwt
from fastapi import HTTPException, Request, Depends, status
from passlib.handlers.pbkdf2 import pbkdf2_sha512
from sqlalchemy import select

from sqlalchemy.ext.asyncio import AsyncSession

from core import Config
from models import User
from utils.database_connection import db_async_session


def generate_password_hash(password: str) -> str:
    """
    Создаёт хэш пароля для хранения в БД
    """
    return pbkdf2_sha512.hash(password)


def verify_password(input_password: str, password_hash: str) -> bool:
    """
    Сравнивает полученный вариант пароля с захэшированным вариантом
    """
    return pbkdf2_sha512.verify(input_password, password_hash)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
    return encoded_jwt


def get_token(request: fastapi.Request) -> str:
    token = request.cookies.get('access_token')
    if not token and token not in Config.cache:
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_401_UNAUTHORIZED, detail='Token not found')

    return token


async def get_current_user(
        request: Request,
        db: AsyncSession = Depends(db_async_session)
) -> User:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не предоставлен токен аутентификации"
        )

    try:
        # Декодируем токен
        payload = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=[Config.ALGORITHM]  # Обратите внимание на параметр algorithms (множественное число)
        )

        if not payload or "id" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Недействительный токен"
            )

        # Выполняем асинхронный запрос к базе данных
        stmt = select(User).where(User.id == payload["id"])
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь не найден"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь деактивирован"
            )

        # Добавляем токен к объекту пользователя
        return user

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Срок действия токена истек"
        )
    except (jwt.InvalidTokenError, jwt.DecodeError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Недействительный токен: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка сервера: {str(e)}"
        )
