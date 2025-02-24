from sqlalchemy import Column, Integer, String, DateTime,Boolean, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base
from passlib.hash import bcrypt
from datetime import datetime
import enum #выбор между возможными вариантами(админ или юзер)
import pytz

moscow_tz = pytz.timezone('Europe/Moscow')

class RoleEnum(str, enum.Enum):
    admin = "admin"
    user = "user"

#Таблица с происшествиями
class Incident(Base): #Создай таблицу с именем incidents 📑 Каждая запись (объект) — это строка в таблице.
    __tablename__ = "incident"
    id = Column(Integer, primary_key = True, index = True)

    created_at = Column(DateTime, default=lambda: datetime.now(moscow_tz))
    organization = Column(String, nullable=False)  # ДО (Организация)
    field = Column(String, nullable=False)         # Месторождение/лицензионный участок

    event_area = Column(String, nullable=False)    # Область события (текст)
    event_type = Column(String, nullable=False)    # Тип события (текст)

    description = Column(Text, nullable=True)      # Описание происшествия
    consequences = Column(Text, nullable=True)     # Последствия
    comments = Column(Text, nullable=True)         # Комментарии

    user_id = Column(Integer, ForeignKey("user.id"))  # Внешний ключ на пользователя
    user = relationship("User", back_populates="incidents")  # Связь с User

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key = True, index = True)
    username = Column(String, unique=True, index = True)
    hashed_password = Column(String, nullable=False)
    name = Column(String, index = True)
    surname = Column(String, index = True)
    organization = Column(String, index = True)
    is_active = Column(Boolean, default=True)        
    role = Column(Enum(RoleEnum), default="user")
    telegram_id = Column(String, unique=True, nullable=True)

    incidents = relationship("Incident", back_populates="user")  # Связь с Incident

