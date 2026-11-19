"""HTTP-клієнт для NVD CVE API 2.0.

Модуль робить рівно одну річ: формує заголовки й виконує ОДИН GET-запит.
Семантичну перевірку даних (чи є в JSON потрібні поля) тут не робимо —
це відповідальність analysis.py ("відокремлюємо отримання від аналізу").
"""

from __future__ import annotations

import os
from typing import Any

import requests

# Фіксована адреса API. Її НЕ можна задавати через аргументи CLI
# (інакше програма могла б надсилати запити на довільні сервери).
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (час на встановлення з'єднання, час очікування наступної порції даних).
# Це НЕ загальний ліміт запиту: read-timeout діє між отриманими даними.
REQUEST_TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервер відповів успішним, але не очікуваним статусом (не 200).

    Приклад: 204 або 3xx (перенаправлення ми вимкнули, тому 301/302
    не "проходять" автоматично, а потрапляють сюди).
    """

    def __init__(self, status_code: int) -> None:
        # У повідомленні лише код статусу: без тіла, заголовків і ключів.
        super().__init__(f"Неочікуваний HTTP-статус: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає HTTP-заголовки запиту.

    Accept є завжди. Заголовок apiKey додається лише якщо змінна середовища
    NVD_API_KEY містить непорожнє значення (пробіли по краях відкидаємо).
    Змінну читаємо під час ВИКЛИКУ, а не при імпорті: так тести можуть
    змінювати її через monkeypatch.setenv/delenv.
    """
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None and api_key.strip():
        # Ключ іде саме в заголовок, а не в URL і не як "Bearer ...".
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD і повертає декодований JSON.

    Послідовність: запит -> raise_for_status() (4xx/5xx -> HTTPError)
    -> перевірка, що статус саме 200 -> response.json().
    Усі винятки requests навмисно НЕ перехоплюються тут: їх обробляє main(),
    щоб показати користувачеві зрозуміле повідомлення.
    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},  # requests сам закодує параметр в URL
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,  # перенаправлення не приймаємо
        # verify не вказуємо: за замовчуванням TLS-сертифікат перевіряється.
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
