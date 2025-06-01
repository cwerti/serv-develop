from datetime import datetime

from schemas.core import Model


class ChangeLogBase(Model):
    """Базовый DTO класс для лога изменений."""
    entity_type: str
    entity_id: int
    action: str
    old_value: str
    new_value: str


class ChangeLogCreate(ChangeLogBase):
    """DTO класс для создания лога изменений."""
    pass


class ChangeLogResponse(ChangeLogBase):
    """DTO класс для ответа с логом изменений."""
    id: int
    created_at: datetime

    class Config:
        orm_mode = True
        from_orm = True

class ChangeLogCollection(Model):
    """DTO класс для коллекции логов изменений.

    Attributes:
        items (list[ChangeLogResponse]): Список логов изменений.
        total (int): Общее количество логов.
    """
    items: list[ChangeLogResponse]
    total: int
