from sqlalchemy import Column, Integer, String, Date

from app.models.core import Base
from datetime import date
from sqlalchemy.ext.hybrid import hybrid_property


class User(Base):
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}
    id = Column(Integer, primary_key=True, index=True, )
    username = Column(String(50), unique=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    birthday = Column(Date)

    @hybrid_property
    def age(self):
        if self.birthday:
            today = date.today()
            return today.year - self.birthday.year - (
                    (today.month, today.day) < (self.birthday.month, self.birthday.day))
        return None
