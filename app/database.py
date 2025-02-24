from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# URL подключения к базе
DATABASE_URL = "postgresql://postgres:123@localhost/incident_db"

# Подключение к базе (engine)
engine = create_engine(DATABASE_URL)

# Сессия для работы с базой
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Базовый класс для моделей
Base = declarative_base()

# Функция для использования сессии в эндпоинтах
def get_db():
    db = SessionLocal()
    try:
        yield db  # Отдаёт сессию эндпоинту
    finally:
        db.close()  # Закрывает сессию после запроса
