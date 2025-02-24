from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database import get_db, engine, Base
from sqlalchemy import text
from app.models import Incident, User
from passlib.hash import bcrypt
from pydantic import BaseModel #проверка что данные переданы в нужном типе
from datetime import datetime, timedelta
from jose.constants import Algorithms
from jose.exceptions import JWTError
from jose import jwt
from .auth import SECRET_KEY, ALGORITHM, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, verify_password, get_password_hash
import uvicorn
from app.auth import get_current_user 
from typing import Optional


Base.metadata.create_all(bind=engine)

app = FastAPI()

# Простой эндпоинт для проверки работы API
@app.get("/")
def root():
    return {"message": "API работает!"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)


# Эндпоинт для проверки подключения к базе
@app.get("/check_db")
def check_db_connection(db: Session = Depends(get_db)):
    try:
        # Используем text() для SQL-запроса
        db.execute(text("SELECT 1"))
        return {"message": "Подключение к базе данных успешно!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка подключения к БД: {str(e)}")
    
class IncidentCreate(BaseModel):
    field: str
    event_area: str
    event_type: str
    description: Optional[str] = None
    consequences: Optional[str] = None
    comments: Optional[str] = None


@app.post("/add_incident")
def add_incident(
    incident: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)  # Получаем пользователя из токена
):
    # Проверка заполненности личного кабинета
    if not current_user.surname or not current_user.organization:
        raise HTTPException(
            status_code=403,detail="Заполните личный кабинет (ФИО и организация), чтобы добавлять происшествия"
        )
    new_incident = Incident(
        field=incident.field,
        event_area=incident.event_area,
        event_type=incident.event_type,
        description=incident.description,
        consequences=incident.consequences,
        comments=incident.comments,
        user_id=current_user.id
    )
    db.add(new_incident)      # Добавляем в сессию
    db.commit()              # Сохраняем изменения в базе
    db.refresh(new_incident)  # Обновляем объект из базы
    return {
        "message": "Происшествие добавлено",
        "incident_id": new_incident.id,
        "author": current_user.surname  # Возвращаем имя автора
    }

@app.get("/show_all_incident")
def show_incident(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    return [
        {
            "id": incident.id,
            "description": incident.description,
            "location": incident.location,
            "created_at": incident.created_at
        }
        for incident in incidents
    ]


class UserCreate(BaseModel):
    username: str
    password: str
    role: str

@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    #проверка на одинаковый логин
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")
    
    hashed_password = get_password_hash(user.password)  # Хэшируем пароль

    new_user = User(
        username=user.username,
        hashed_password=hashed_password,
        role=user.role
    )

    db.add(new_user)  # Добавляем пользователя в БД
    db.commit()  # Сохраняем изменения
    db.refresh(new_user)  # Обновляем объект

    return {"message": f"Пользователь {user.username} успешно зарегистрирован!"}



class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(user: LoginRequest, db: Session = Depends(get_db)):
    # Ищем пользователя по логину
    db_user = db.query(User).filter(User.username == user.username).first()
    
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

class UserUpdate(BaseModel):
    name: str
    surname: str
    organization: str
    telegram_id: str

@app.get("/profile")
def get_profile(current_user:User = Depends(get_current_user)):
        return {
        "username": current_user.username,
        "name": current_user.name,
        "surname": current_user.surname,
        "organization": current_user.organization,
        "telegram_id": current_user.telegram_id
    }

@app.put("/profile")
def update_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.name = user_update.name
    current_user.surname = user_update.surname
    current_user.organization = user_update.organization
    current_user.telegram_id = user_update.telegram_id
    db.commit()
    db.refresh(current_user)
    return {"message": "Данные профиля обновлены"}


# 1. у пользователя должен быть "личный кабинет". После логина уведомление о том, что ему нужно заполнить данные об аккаунте. (ФИО, оргинизация (ДО))
# 2. Настройка для смены региона, чтобы при автоматическом времен (ЭТО НЕ НУЖНО, будет время по мск). Иначе будет неразбириха
# 3. При создании события, нужен внешний ключ, который будет указывать на создателя события
# 4. После остановки сервера появляется ошибка.
# 5. Пользователя регестрируют; пользователь логинится(вводит логин и пароль); пользователь может просматривать события;
# пользователь не может создавать события, пока не заполнит свои личные данные в личном кабинете; пользователь создаёт(регестрирует) событие,
# жмёт кнопку добавить событие, открывается удобная форма для заполнения. Заполняет Месторождение/лицензионные участки,
# область события (выбор из предложенного: люди, бурение, ТКРС, пожарная безопасность, энергетика, Нефтепромысловое оборудование, Экология,
# транспорт, трубопроводы, скважины, др.), Тип(выбор из предложенного: Отказ, Запуск, Происшесвтие, Инцидент, Остановка), 
# Описание (не обязателньое поле), Комментарий(не обязательное поле), Последсвтия (не обязательное поле)
# 6. Придумать "балл важности" для каждого события, который будет складываться из разных параметров происшествия (Отказ + 1 балл, люди + 8 баллов
# как-то их суммировать и получить оценку от 1-10 и в зависимости от неё оповещать разных лиц)


# 7. Как лучше сделать лк

#8. Бд исправить столбец organization