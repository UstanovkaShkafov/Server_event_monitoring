from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Response, Query
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
import pandas as pd
from io import BytesIO


Base.metadata.create_all(bind=engine)

app = FastAPI()


def process_excel(file: UploadFile, db: Session, user_id: int):
    try:
        # 1️⃣ Читаем Excel-файл с указанием строки заголовков (третья строка → `header=2`)
        df = pd.read_excel(file.file, engine="openpyxl",header=2)  
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ошибка чтения файла: {str(e)}")

    # 2️⃣ Проверяем наличие необходимых столбцов
    expected_columns = {"Дата", "ДО", "Месторождение/\nлицензионные участки", 
                        "Область события", "Тип", "Описание происшествия", 
                        "Последствия", "Комментарии"}
    #print(df.columns)  #проверка столбцов
    if not expected_columns.issubset(df.columns):
        raise HTTPException(status_code=400, detail="Некорректный формат файла. Проверьте названия столбцов.")

    # 3️⃣ Построчное считывание данных
    incidents_to_add = []
    for _, row in df.iterrows():
        # 4️⃣ Обрабатываем дату (Excel может хранить дату в числовом формате)
        try:
            event_date = pd.to_datetime(row["Дата"], errors="coerce")
            if pd.isnull(event_date):  # Если дата не распозналась, ставим текущую
                event_date = datetime.utcnow()
        except Exception:
            event_date = datetime.utcnow()

        # 5️⃣ Создаём объект происшествия
        incident = Incident(
            created_at=event_date,
            organization = row["ДО"],
            field=row["Месторождение/\nлицензионные участки"],
            event_area=row["Область события"],
            event_type=row["Тип"],
            description=row.get("Описание происшествия", ""),  # .get() чтобы не было ошибки, если пустое поле
            consequences=row.get("Последствия", ""),
            comments=row.get("Комментарии", ""),
            user_id=user_id  # Привязываем к текущему пользователю
        )
        incidents_to_add.append(incident)

    # 6️⃣ Добавляем все записи одним запросом
    db.bulk_save_objects(incidents_to_add)
    db.commit()

    return {"message": f"Успешно добавлено {len(incidents_to_add)} происшествий"}

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
def show_incident(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    event_type: Optional[str] = Query(None, description="Фильтр по типу события"), #GET /show_all_incident?event_type=Инцидент
    organization: Optional[str] = Query(None, description="Фильтр по организации"),
    only_my: Optional[bool] = Query(False, description="Вывести только мои происшествия")
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")

    # Базовый запрос
    query = db.query(Incident)

    # Применяем фильтры
    if event_type:
        query = query.filter(Incident.event_type == event_type)
    if organization:
        query = query.filter(Incident.organization == organization)
    if only_my:
        query = query.filter(Incident.user_id == current_user.id)

    # Получаем отфильтрованные происшествия
    incidents = query.all()

    return [
        {
            "id": incident.id,
            "Дата": incident.created_at.strftime("%Y-%m-%d %H:%M"),
            "ДО": incident.organization,
            "Месторождение/лицензионные участки": incident.field,
            "Область события": incident.event_area,
            "Тип": incident.event_type,
            "Описание": incident.description,
            "Последствия": incident.consequences,
            "Комментарии": incident.comments,
            "Создал": f"{incident.user.surname} {incident.user.name}" if incident.user else "Неизвестно"
        }
        for incident in incidents
    ]


@app.delete("/delete_incident/{incident_id}")
def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    # Находим происшествие в базе данных
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Происшествие не найдено")
    
    # Проверяем, является ли текущий пользователь автором происшествия или админом
    if current_user.role != "admin" and incident.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Вы не можете удалить это происшествие")

    # Удаляем происшествие
    db.delete(incident)
    db.commit()

    return {"message": "Происшествие успешно удалено"}


#Конкретное происшествие
@app.put("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    incident_update: dict,  # Принимаем JSON как словарь
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Получаем происшествие по ID
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Происшествие не найдено")

    # Проверяем права: только автор или админ может редактировать
    if incident.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Недостаточно прав для редактирования")

    # Обновляем только переданные поля
    for key, value in incident_update.items():
        if hasattr(incident, key):  # Проверяем, есть ли такое поле в модели
            setattr(incident, key, value)

    db.commit()
    db.refresh(incident)

    return {"message": "Происшествие обновлено", "incident": incident}




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

@app.get("/users")
def get_users(user_id: int = None, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    # Проверка прав администратора
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещен. Только для администраторов.")

    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        return {
            "id": user.id,
            "Логин": user.username,
            "ФИО": f"{user.surname or ''} {user.name or ''}".strip(),
            "Роль": user.role
        }
    
    users = db.query(User).all()
    return [{"id": u.id, "Логин": u.username, "ФИО": f"{u.surname or ''} {u.name or ''}".strip(), "Роль": u.role} for u in users]


@app.delete("/delete_user/{user_id}")
def delete_user(user_id: int, current_user = Depends(get_current_user) ,db: Session = Depends(get_db)):
    #найти юзера в бд
    db_user = db.query(User).filter(User.id == user_id).first()

    #Проверка на существование
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    #Проверка на права админа
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Вы не можете удалить этого пользвателя. Недостаточно прав.")
    
    username = db_user.username
    surname = db_user.surname
    name = db_user.name
    db.delete(db_user)
    db.commit()

    full_name = f"( {surname} {name})" if surname and name else ""
    return f"Пользователь {username}{full_name} был удалён."






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

# Эндпоинт для загрузки Excel
@app.post("/upload_excel")
def upload_excel(file: UploadFile = File(...), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")

    return process_excel(file, db, current_user.id)



@app.get("/export_incidents")
def export_incidents(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    event_type: Optional[str] = Query(None, description="Фильтр по типу события"),
    organization: Optional[str] = Query(None, description="Фильтр по организации"),
    only_my: Optional[bool] = Query(False, description="Выводить только мои происшествия")
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")

    # Базовый запрос
    query = db.query(Incident)

    # Применяем фильтры
    if event_type:
        query = query.filter(Incident.event_type == event_type)
    if organization:
        query = query.filter(Incident.organization == organization)
    if only_my:
        query = query.filter(Incident.user_id == current_user.id)

    # Получаем отфильтрованные происшествия
    incidents = query.all()

    # Преобразуем в DataFrame
    data = [
        {
            "Дата": incident.created_at.strftime("%Y-%m-%d %H:%M"),
            "ДО": incident.organization,
            "Месторождение/лицензионные участки": incident.field,
            "Область события": incident.event_area,
            "Тип": incident.event_type,
            "Описание": incident.description,
            "Последствия": incident.consequences,
            "Комментарии": incident.comments,
            "Создал": f"{incident.user.surname} {incident.user.name}" if incident.user else "Неизвестно"
        }
        for incident in incidents
    ]

    df = pd.DataFrame(data)

    # Сохраняем в буфер
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Происшествия")

    output.seek(0)

    # Возвращаем Excel-файл
    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=export.xlsx"}
    )


# 1. у пользователя должен быть "личный кабинет". После логина уведомление о том, что ему нужно заполнить данные об аккаунте. (ФИО, оргинизация (ДО))
# 2. Настройка для смены региона, чтобы при автоматическом времен (ЭТО НЕ НУЖНО, будет время по мск). Иначе будет неразбириха
# 3. При создании события, нужен внешний ключ, который будет указывать на создателя события
# 4. После остановки сервера появляется ошибка.
# 5. Пользователя регестрируют; пользователь логинится(вводит логин и пароль); пользователь может просматривать события;
# пользователь не может создавать события, пока не заполнит свои личные данные в личном кабинете; пользователь создаёт(регестрирует) событие,
# жмёт кнопку добавить событие, открывается удобная форма для заполнения. Заполняет Месторождение/лицензионные участки,
# область события (выбор из предложенного: люди, бурение, ТКРС, пожарная безопасность, энергетика, Нефтепромысловое оборудование, Экология,
# транспорт, трубопроводы, скважины, др.),  , 
# Описание (не обязателньое поле), Комментарий(не обязательное поле), Последсвтия (не обязательное поле)
# 6. Придумать "балл важности" для каждого события, который будет складываться из разных параметров происшествия (Отказ + 1 балл, люди + 8 баллов
# как-то их суммировать и получить оценку от 1-10 и в зависимости от неё оповещать разных лиц)


# 7. Как лучше сделать лк
# 8. Убрать organization у юзера

