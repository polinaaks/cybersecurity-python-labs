"""Налаштування варіанта 1: реєстр вразливостей вебзастосунку."""  # документація модуля

from typing import Final, Literal  # Final — для констант, Literal — для набору статусів

VARIANT_NUMBER: Final[int] = 1  # номер варіанта студента
APP_TITLE: Final[str] = (
    "Реєстр вразливостей вебзастосунку"  # назва застосунку для Swagger
)
APP_VERSION: Final[str] = "1.0.0"  # версія API
APP_DESCRIPTION: Final[str] = (  # опис предметної області для Swagger UI
    "Навчальний сервіс обліку знахідок перевірки вебзастосунку. "  # що робить сервіс
    "Категорія визначає компонент (web, api, database), "  # зміст категорії
    "value — навчальна оцінка небезпеки вразливості (score) від 0 до 10, "  # зміст value
    "status — стан опрацювання знахідки (new, in_progress, done). "  # зміст status
    "Порогове значення оцінки для варіанта: 7.0."  # поріг варіанта
)  # кінець багаторядкового опису
UNIT: Final[str] = "score"  # одиниця вимірювання value
THRESHOLD: Final[float] = 7.0  # поріг варіанта (інформаційний)
VALUE_MIN: Final[float] = 0.0  # нижня межа value
VALUE_MAX: Final[float] = 10.0  # верхня межа value

RecordStatus = Literal["new", "in_progress", "done"]  # дозволені статуси запису

DEFAULT_LIMIT: Final[int] = 20  # типова кількість записів на сторінці
MAX_LIMIT: Final[int] = 100  # максимальна кількість записів на сторінці
MAX_BATCH_SIZE: Final[int] = 100  # максимальний розмір пакета для /records/bulk
