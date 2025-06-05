import datetime
from typing import List

import fastapi
import jwt
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core import Config, ConfigLog
from core.exceptions import NotAuthorized
from internal.logs import get_user_logs
from internal.users.users import user_exists, user_create, get_user
from models.general import User, ChangeLogs

from schemas.auth import LoginRequest, RegisterRequest
from schemas.change_log import ChangeLogResponse
from schemas.exception import UserNotFoundError
from utils.auth.passwwords import verify_password, create_access_token, get_token, get_current_user
from utils.database_connection import db_async_session
from utils.permission import require_permission

auth = fastapi.APIRouter()


@auth.post(
    "/login",
    status_code=200,
    responses={409: {"description": "User with specified login or email already exists"}},
)
async def login(response: fastapi.Response,
                data: LoginRequest,
                session: AsyncSession = fastapi.Depends(db_async_session),
                ):
    """
    Регистрация в системе.
    """
    login = data.username
    password = data.password
    incorrect_data_exception = NotAuthorized("Неверный логин или пароль")

    user: User = await user_exists(session, login, login, include_deleted=True)

    if not user:
        raise incorrect_data_exception

    user = await user_exists(session, login, login)

    if (not user) or (not verify_password(password, user.password)):
        raise incorrect_data_exception
    else:
        if len(Config.cache) == Config.max_quantity_token:
            raise fastapi.HTTPException(
                400,
                detail={"message": "Сейчас вошло слишком много пользователей, повторите попытку позже"},
            )
        access_token = create_access_token(data={"login": user.username, "id": user.id})
        Config.cache.append(access_token)
        response.set_cookie(key="access_token", value=access_token, httponly=True)

        log = ChangeLogs(entity_type="User",
                         entity_id=user.id,
                         action="Login",
                         old_value="",
                         new_value=access_token,
                         created_at=datetime.datetime.now())

        session.add(log)
        await session.commit()
        await session.refresh(log)

    return access_token


@auth.post(
    "/register",
    status_code=201,
    responses={409: {"description": "User with specified login or email already exists"}},
)
async def register(
        user_info: RegisterRequest,
        session: AsyncSession = fastapi.Depends(db_async_session),
):
    """
    Регистрация в системе.
    """

    user_from_db: User = await user_exists(session, user_info.username, user_info.email, include_deleted=False)
    if user_from_db is not None:
        raise fastapi.HTTPException(
            400,
            detail={"message": "Такой пользователь уже существует"},
        )
    new_user = await user_create(session, user_info)

    log = ChangeLogs(entity_type="User",
                     entity_id=new_user["id"],
                     action="Create",
                     old_value="{}",
                     new_value=str(new_user),
                     created_at=datetime.datetime.now())

    session.add(log)
    await session.commit()
    await session.refresh(log)

    return {"statuses": 201, "news_user": user_info}


@auth.get(
    "/me",
    status_code=201,
    responses={409: {"description": "User with specified login or email already exists"}}
)
async def user_info(
        token: str = Depends(get_token),
        session: AsyncSession = fastapi.Depends(db_async_session)
):
    """
    Регистрация в системе.
    """
    user_id = jwt.decode(token, Config.SECRET_KEY, Config.ALGORITHM)['id']
    user: User = await get_user(session, user_id)
    if not user:
        raise fastapi.HTTPException(
            400,
            detail={
                "user_id": user_id,
                "message": "Такой пользователь не найден"},
        )
    return user


@auth.post("/logout")
async def logout_user(response: fastapi.Response,
                      token: str = Depends(get_token),
                      session: AsyncSession = fastapi.Depends(db_async_session), ):
    user_jwt = jwt.decode(token, Config.SECRET_KEY, Config.ALGORITHM)

    response.delete_cookie(key="access_token")
    Config.cache.remove(token)

    log = ChangeLogs(entity_type="User",
                     entity_id=user_jwt["id"],
                     action="Logout",
                     old_value=token,
                     new_value="",
                     created_at=datetime.datetime.now())

    session.add(log)
    await session.commit()
    await session.refresh(log)

    return {'message': 'Пользователь успешно вышел из системы'}


@auth.get("/tokens")
async def user_auth_list(token: str = Depends(get_token),
                         session: AsyncSession = fastapi.Depends(db_async_session)):
    res = []
    for user_token in Config.cache:
        user_id = jwt.decode(user_token, Config.SECRET_KEY, Config.ALGORITHM)['id']
        user: User = await get_user(session, user_id)
        res.append(user)

    return Config.cache


@auth.post("/out_all")
async def logout_user(response: fastapi.Response,
                      token: str = Depends(get_token)):
    response.delete_cookie(key="access_token")
    Config.cache = []

    return {'message': 'Все пользователи успешно вышели из системы'}


@auth.get("/{user_id}/logs",
          dependencies=[Depends(require_permission("get_story_user")), Depends(get_current_user)])
async def logs_user(
        user_id: int,
        session: AsyncSession = Depends(db_async_session), ):
    try:
        res = await get_user_logs(session, user_id)
        resp = [{"id": i.id, "entity_type": i.entity_type, "entity_id": i.entity_id, "action": i.action,
                 "old_value": i.old_value, "new_value": i.new_value, "created_at": i.created_at} for i in res]
        return resp
    except UserNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Информация по логам не найдена"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении логов: {str(e)}"
        )
