"""add data

Revision ID: 076493af6cc0
Revises: b202ee330569
Create Date: 2025-05-29 16:29:38.716927

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import table, column, Integer, String, Text

# revision identifiers, used by Alembic.
revision: str = '076493af6cc0'
down_revision: Union[str, None] = 'b202ee330569'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Создаем временные таблицы для вставки данных
    role_table = table(
        'roles',
        column('id', Integer),
        column('name', String),
        column('description', Text),
        column('code', String)
    )

    permission_table = table(
        'permissions',
        column('id', Integer),
        column('name', String),
        column('description', Text),
        column('code', String)
    )

    roles_and_permissions_table = table(
        'roles_and_permissions',
        column('role_id', Integer),
        column('permission_id', Integer)
    )

    # Вставляем роли
    op.bulk_insert(role_table,
                   [
                       {"name": "Admin", "description": "Администратор", "code": "admin"},
                       {"name": "User", "description": "Пользователь", "code": "user"},
                       {"name": "Guest", "description": "Гость", "code": "guest"},
                   ]
                   )

    # Вставляем базовые разрешения
    entities = ["users", "roles", "permissions"]
    perm_actions = ["get-list", "read", "create", "update", "delete", "restore"]
    permissions = []

    for entity in entities:
        for action in perm_actions:
            permissions.append({
                "name": f"{action}-{entity}",
                "description": f"{action} {entity}",
                "code": f"{action}_{entity}"
            })

    # Добавляем дополнительные разрешения
    additional_permissions = [
        {"name": "assign-role-user", "description": "Присвоение роли пользователю", "code": "assign_role_user"},
        {"name": "get-roles-user", "description": "Получение ролей пользователя", "code": "get_roles_user"},
        {"name": "hard-delete-role-user", "description": "Жесткое удаление роли у пользователя",
         "code": "hard_delete_role_user"},
        {"name": "soft-delete-role-user", "description": "Мягкое удаление роли у пользователя",
         "code": "soft_delete_role_user"},
        {"name": "restore-role-user", "description": "Восстановление роли у пользователя", "code": "restore_role_user"},
        {"name": "hard-delete-role", "description": "Жесткое удаление роли", "code": "hard_delete_role"},
        {"name": "soft-delete-role", "description": "Мягкое удаление роли", "code": "soft_delete_role"},
        {"name": "hard-delete-permission", "description": "Жесткое удаление разрешения",
         "code": "hard_delete_permission"},
        {"name": "soft-delete-permission", "description": "Мягкое удаление разрешения",
         "code": "soft_delete_permission"},
        {"name": "get-story-user", "description": "Получать логи юзера",
         "code": "get_story_user"
         },
        {"name": "get-story-permission", "description": "Получать логи разрешений",
         "code": "get_story_permission"
         },
        {"name": "get-story-role", "description": "Получать логи ролей",
         "code": "get_story_role"
         }
    ]

    permissions.extend(additional_permissions)
    op.bulk_insert(permission_table, permissions)

    # Связываем роли и разрешения (используем сырые SQL, так как ID могут отличаться)
    op.execute("""
        -- Админ получает все разрешения
        INSERT INTO roles_and_permissions (role_id, permission_id)
        SELECT r.id, p.id 
        FROM roles r, permissions p 
        WHERE r.code = 'admin'
    """)

    op.execute("""
        -- Пользователь получает ограниченные права
        INSERT INTO roles_and_permissions (role_id, permission_id)
        SELECT r.id, p.id 
        FROM roles r, permissions p 
        WHERE r.code = 'user' AND p.code IN (
            'get-list_user', 'read_user', 'update_user',
            'get-list_role', 'read_role', 'get_roles_user',
            'assign_role_user'
        )
    """)

    op.execute("""
        -- Гость получает только чтение пользователей
        INSERT INTO roles_and_permissions (role_id, permission_id)
        SELECT r.id, p.id 
        FROM roles r, permissions p 
        WHERE r.code = 'guest' AND p.code = 'get-list_user'
    """)


def downgrade():
    # Удаляем все созданные данные
    op.execute("DELETE FROM roles_and_permissions")
    op.execute("DELETE FROM permissions")
    op.execute("DELETE FROM roles")
