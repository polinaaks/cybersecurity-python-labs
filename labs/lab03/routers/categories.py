"""Маршрути для категорій."""  # документація модуля

from typing import Annotated  # Annotated для опису параметрів

from fastapi import APIRouter, Path, Response  # роутер, параметр шляху, відповідь

from .. import repository  # шар доступу до даних
from ..schemas import CategoryCreate, CategoryRead, ErrorRead  # моделі

router = APIRouter(
    prefix="/categories", tags=["categories"]
)  # усі маршрути починаються з /categories


@router.get(  # GET /categories
    "",  # шлях без додаткової частини
    response_model=list[CategoryRead],  # відповідь — список CategoryRead
    summary="Список категорій",  # назва операції у Swagger
)  # кінець декоратора
def list_categories() -> list[CategoryRead]:  # обробник
    """Повернути всі категорії за зростанням id."""  # опис
    return [
        CategoryRead(**row) for row in repository.list_categories()
    ]  # перетворюємо словники на моделі


@router.post(  # POST /categories
    "",  # шлях без додаткової частини
    response_model=CategoryRead,  # відповідь — CategoryRead
    status_code=201,  # успішне створення
    summary="Створити категорію",  # назва операції
    responses={
        409: {"model": ErrorRead, "description": "Категорія з такою назвою вже існує"}
    },  # можливий 409
)  # кінець декоратора
def create_category(payload: CategoryCreate) -> CategoryRead:  # обробник
    """Створити категорію; дублікат назви дає 409."""  # опис
    return CategoryRead(
        **repository.create_category(payload.name)
    )  # зберігаємо й повертаємо категорію


@router.delete(  # DELETE /categories/{category_id}
    "/{category_id}",  # параметр шляху
    status_code=204,  # успішне видалення без тіла
    summary="Видалити порожню категорію",  # назва операції
    responses={  # можливі помилки
        404: {
            "model": ErrorRead,
            "description": "Категорію не знайдено",
        },  # немає категорії
        409: {
            "model": ErrorRead,
            "description": "Категорія містить записи",
        },  # категорія непорожня
    },  # кінець responses
)  # кінець декоратора
def delete_category(  # обробник
    category_id: Annotated[
        int, Path(gt=0, description="Ідентифікатор категорії")
    ],  # додатний id
) -> Response:  # повертає порожню відповідь
    """Видалити категорію, якщо в ній немає записів."""  # опис
    repository.delete_category(category_id)  # видаляємо (винятки обробляє main.py)
    return Response(status_code=204)  # порожнє тіло
