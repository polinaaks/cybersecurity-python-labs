"""Pydantic-моделі запитів і відповідей API."""  # документація модуля

from typing import Any  # Any — для довільного типу

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)  # інструменти Pydantic 2

from .config import (  # межі value та тип статусу
    VALUE_MAX,  # верхня межа value
    VALUE_MIN,  # нижня межа value
    RecordStatus,  # тип дозволених статусів
)


class CategoryCreate(BaseModel):  # модель створення категорії
    """Дані для створення категорії."""  # опис моделі

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")  # обрізаємо пробіли, забороняємо зайві поля

    name: str = Field(min_length=2, max_length=40, description="Назва категорії")  # назва 2-40 символів


class CategoryRead(CategoryCreate):  # модель відповіді для категорії
    """Категорія у відповіді API."""  # опис моделі

    id: int  # ідентифікатор, створений базою


class RecordCreate(BaseModel):  # модель створення запису
    """Дані для створення запису (знахідки)."""  # опис моделі

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")  # обрізаємо пробіли, забороняємо зайві поля

    code: str = Field(min_length=3, max_length=40, description="Унікальний код запису")  # код 3-40 символів
    title: str = Field(min_length=3, max_length=120, description="Заголовок знахідки")  # заголовок 3-120 символів
    category_id: int = Field(gt=0, description="Ідентифікатор категорії")  # додатний id категорії
    value: float = Field(  # навчальна оцінка небезпеки
        ge=VALUE_MIN,  # не менше 0
        le=VALUE_MAX,  # не більше 10
        allow_inf_nan=False,  # відхиляємо нескінченність і NaN
        description="Навчальна оцінка небезпеки (score) від 0 до 10",  # опис для Swagger
    )  # кінець опису поля value
    status: RecordStatus = Field(description="Стан опрацювання: new, in_progress, done")  # дозволений статус

    @field_validator("value", "category_id", mode="before")  # перевірка до перетворення типів
    @classmethod  # валідатор працює на рівні класу
    def reject_bool(cls, raw: Any) -> Any:  # відхиляємо true/false замість чисел
        """Не допускати булевих значень у числових полях."""  # опис валідатора
        if isinstance(raw, bool):  # bool у Python є підкласом int
            # Pydantic перетворює на 422 лише ValueError, а TypeError дав би 500, тому правило TRY004 тут вимкнено
            raise ValueError("Очікується число, а не логічне значення")  # noqa: TRY004
        return raw  # інакше повертаємо значення без змін


class RecordReplace(RecordCreate):  # модель повної заміни запису (PUT)
    """Усі змінювані поля запису обов'язкові."""  # опис моделі


class RecordRead(RecordCreate):  # модель відповіді для запису
    """Запис у відповіді API."""  # опис моделі

    id: int  # ідентифікатор запису
    category_name: str  # назва категорії з JOIN


class PingRead(BaseModel):  # відповідь для /ping
    """Відповідь перевірки доступності."""  # опис моделі

    status: str  # значення "ok"


class StudentRead(BaseModel):  # відповідь для /student
    """Дані студента."""  # опис моделі

    student_name: str  # ПІБ
    group_name: str  # група
    variant_number: int  # номер варіанта


class ErrorRead(BaseModel):  # формат помилки для документації
    """Тіло відповіді з помилкою."""  # опис моделі

    detail: str  # зрозуміле повідомлення для клієнта
