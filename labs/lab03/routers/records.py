"""Маршрути для записів."""  # документація модуля

from typing import Annotated  # Annotated для опису параметрів

from fastapi import APIRouter, Body, Path, Query, Response  # інструменти FastAPI

from .. import repository  # шар доступу до даних
from ..config import (  # налаштування варіанта
    DEFAULT_LIMIT,  # типовий limit
    MAX_BATCH_SIZE,  # максимум елементів пакета
    MAX_LIMIT,  # максимальний limit
    VALUE_MAX,  # верхня межа value
    VALUE_MIN,  # нижня межа value
    RecordStatus,  # тип статусу
)
from ..schemas import ErrorRead, RecordCreate, RecordRead, RecordReplace  # моделі

router = APIRouter(prefix="/records", tags=["records"])  # усі маршрути починаються з /records

NOT_FOUND = {404: {"model": ErrorRead, "description": "Запис або категорію не знайдено"}}  # опис 404
CONFLICT = {409: {"model": ErrorRead, "description": "Дублікат унікального значення code"}}  # опис 409

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису")]  # параметр шляху record_id


@router.get(  # GET /records
    "",  # шлях без додаткової частини
    response_model=list[RecordRead],  # відповідь — список RecordRead
    summary="Список записів із фільтрами",  # назва операції
)  # кінець декоратора
def list_records(  # обробник
    category_id: Annotated[int | None, Query(gt=0, description="Лише записи цієї категорії")] = None,  # фільтр
    status: Annotated[RecordStatus | None, Query(description="Лише записи з цим статусом")] = None,  # фільтр
    min_value: Annotated[  # фільтр за мінімальним значенням
        float | None,  # необов'язковий float
        Query(ge=VALUE_MIN, le=VALUE_MAX, allow_inf_nan=False, description="value >= min_value"),  # межі варіанта
    ] = None,  # типово не задано
    q: Annotated[str | None, Query(min_length=1, max_length=120, description="Підрядок у title (з урахуванням регістру)")] = None,  # пошук
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Максимум записів")] = DEFAULT_LIMIT,  # ліміт
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,  # зсув
) -> list[RecordRead]:  # повертає список
    """Повернути записи за фільтрами, відсортовані за id."""  # опис
    rows = repository.list_records(category_id, status, min_value, q, limit, offset)  # запит до бази
    return [RecordRead(**row) for row in rows]  # перетворюємо на моделі


@router.post(  # POST /records/bulk (оголошено до /{record_id} для наочності)
    "/bulk",  # шлях пакетного створення
    response_model=list[RecordRead],  # відповідь — список створених записів
    status_code=201,  # успішне створення
    summary="Пакетне створення записів",  # назва операції
    responses={**NOT_FOUND, **CONFLICT},  # можливі 404 і 409
)  # кінець декоратора
def create_records_bulk(  # обробник
    items: Annotated[list[RecordCreate], Body(min_length=1, max_length=MAX_BATCH_SIZE, description="Від 1 до 100 записів")],  # пакет
) -> list[RecordRead]:  # повертає створені записи
    """Атомарно створити пакет записів."""  # опис
    created = repository.create_records_bulk([item.model_dump() for item in items])  # одна транзакція
    return [RecordRead(**row) for row in created]  # перетворюємо на моделі


@router.post(  # POST /records
    "",  # шлях без додаткової частини
    response_model=RecordRead,  # відповідь — RecordRead
    status_code=201,  # успішне створення
    summary="Створити запис",  # назва операції
    responses={**NOT_FOUND, **CONFLICT},  # можливі 404 і 409
)  # кінець декоратора
def create_record(payload: RecordCreate) -> RecordRead:  # обробник
    """Створити запис; id створює база."""  # опис
    return RecordRead(**repository.create_record(payload.model_dump()))  # зберігаємо й повертаємо


@router.get(  # GET /records/{record_id}
    "/{record_id}",  # параметр шляху
    response_model=RecordRead,  # відповідь — RecordRead
    summary="Отримати запис",  # назва операції
    responses=NOT_FOUND,  # можливий 404
)  # кінець декоратора
def get_record(record_id: RecordId) -> RecordRead:  # обробник
    """Повернути один запис за id."""  # опис
    return RecordRead(**repository.get_record(record_id))  # читаємо запис


@router.put(  # PUT /records/{record_id}
    "/{record_id}",  # параметр шляху
    response_model=RecordRead,  # відповідь — RecordRead
    summary="Замінити змінювані поля запису",  # назва операції
    responses={**NOT_FOUND, **CONFLICT},  # можливі 404 і 409
)  # кінець декоратора
def replace_record(record_id: RecordId, payload: RecordReplace) -> RecordRead:  # обробник
    """Повністю замінити п'ять змінюваних полів."""  # опис
    return RecordRead(**repository.replace_record(record_id, payload.model_dump()))  # оновлюємо й повертаємо


@router.delete(  # DELETE /records/{record_id}
    "/{record_id}",  # параметр шляху
    status_code=204,  # успішне видалення без тіла
    summary="Видалити запис",  # назва операції
    responses=NOT_FOUND,  # можливий 404
)  # кінець декоратора
def delete_record(record_id: RecordId) -> Response:  # обробник
    """Видалити запис за id."""  # опис
    repository.delete_record(record_id)  # видаляємо (винятки обробляє main.py)
    return Response(status_code=204)  # порожнє тіло
