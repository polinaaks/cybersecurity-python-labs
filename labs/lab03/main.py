"""FastAPI-застосунок: підключення маршрутів і обробка помилок."""  # документація модуля

import logging  # журналювання технічних помилок
import sqlite3  # типи помилок SQLite
from collections.abc import AsyncIterator  # тип для lifespan
from contextlib import asynccontextmanager  # декоратор життєвого циклу

from fastapi import FastAPI, Request  # застосунок і тип запиту
from fastapi.responses import JSONResponse  # JSON-відповідь для помилок

from shared import student  # дані студента з ЛР №1 (імпорт як пакета)

from . import config, repository  # налаштування варіанта та шар даних
from .database import initialize_database  # створення таблиць
from .routers import categories, records  # модулі маршрутів
from .schemas import PingRead, StudentRead  # моделі відповідей

logger = logging.getLogger(__name__)  # логер цього модуля


@asynccontextmanager  # життєвий цикл застосунку
async def lifespan(
    _app: FastAPI,
) -> AsyncIterator[None]:  # виконується під час старту і зупинки
    """Створити відсутні таблиці під час запуску (дані не змінюються)."""  # опис
    initialize_database()  # IF NOT EXISTS: наявні дані зберігаються
    yield  # застосунок працює


app = FastAPI(  # створюємо застосунок
    title=config.APP_TITLE,  # назва у Swagger
    description=config.APP_DESCRIPTION,  # опис предметної області
    version=config.APP_VERSION,  # версія
    lifespan=lifespan,  # підключаємо життєвий цикл
)  # кінець створення app
app.include_router(categories.router)  # підключаємо маршрути категорій
app.include_router(records.router)  # підключаємо маршрути записів


@app.get(
    "/ping",
    response_model=PingRead,
    tags=["service"],
    summary="Перевірка доступності API",
)  # GET /ping
def ping() -> PingRead:  # обробник
    """Повернути статус ok."""  # опис
    return PingRead(status="ok")  # {"status": "ok"}


@app.get(
    "/student", response_model=StudentRead, tags=["service"], summary="Дані студента"
)  # GET /student
def get_student() -> StudentRead:  # обробник
    """Повернути ПІБ, групу та номер варіанта з shared/student.py."""  # опис
    return StudentRead(  # формуємо відповідь
        student_name=student.STUDENT_NAME,  # ПІБ
        group_name=student.GROUP_NAME,  # група
        variant_number=student.VARIANT_NUMBER,  # варіант
    )  # кінець відповіді


def _error(
    status_code: int, detail: str
) -> JSONResponse:  # допоміжна функція відповіді з помилкою
    """Сформувати JSON {"detail": ...} без технічних подробиць."""  # опис
    return JSONResponse(
        status_code=status_code, content={"detail": detail}
    )  # відповідь клієнту


@app.exception_handler(repository.RecordNotFoundError)  # запис не знайдено
async def record_not_found(
    _request: Request, _exc: repository.RecordNotFoundError
) -> JSONResponse:  # обробник
    """Перетворити RecordNotFoundError на 404."""  # опис
    return _error(404, "Запис не знайдено")  # 404


@app.exception_handler(repository.CategoryNotFoundError)  # категорію не знайдено
async def category_not_found(
    _request: Request, _exc: repository.CategoryNotFoundError
) -> JSONResponse:  # обробник
    """Перетворити CategoryNotFoundError на 404."""  # опис
    return _error(404, "Категорію не знайдено")  # 404


@app.exception_handler(repository.CategoryNotEmptyError)  # категорія непорожня
async def category_not_empty(
    _request: Request, _exc: repository.CategoryNotEmptyError
) -> JSONResponse:  # обробник
    """Перетворити CategoryNotEmptyError на 409."""  # опис
    return _error(409, "Категорія містить записи, її не можна видалити")  # 409


@app.exception_handler(sqlite3.IntegrityError)  # порушення обмежень БД
async def integrity_error(
    _request: Request, exc: sqlite3.IntegrityError
) -> JSONResponse:  # обробник
    """Перетворити порушення унікальності на 409, інші — на 500."""  # опис
    message = str(exc)  # текст помилки SQLite (клієнту не віддаємо)
    if "records.code" in message:  # дубль коду запису
        logger.warning("Конфлікт унікальності: %s", message)  # технічна деталь у журнал
        return _error(409, "Запис із таким code вже існує")  # 409
    if "categories.name" in message:  # дубль назви категорії
        logger.warning("Конфлікт унікальності: %s", message)  # технічна деталь у журнал
        return _error(409, "Категорія з такою назвою вже існує")  # 409
    if "FOREIGN KEY" in message:  # порушення зовнішнього ключа
        logger.warning(
            "Конфлікт зовнішнього ключа: %s", message
        )  # технічна деталь у журнал
        return _error(409, "Операція порушує зв'язок між таблицями")  # 409
    logger.exception("Неочікуване порушення обмежень")  # решта — неочікувані
    return _error(500, "Внутрішня помилка сервера")  # 500


@app.exception_handler(sqlite3.Error)  # будь-яка інша помилка SQLite
async def database_error(
    _request: Request, _exc: sqlite3.Error
) -> JSONResponse:  # обробник
    """Перетворити технічну помилку БД на 500 без подробиць."""  # опис
    logger.exception("Помилка бази даних")  # деталі лише в журнал
    return _error(500, "Внутрішня помилка сервера")  # 500
