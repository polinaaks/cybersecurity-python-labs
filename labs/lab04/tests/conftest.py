"""Спільні фікстури для тестів ЛР №4."""

import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Перед КОЖНИМ тестом: прибрати успадкований ключ і заборонити справжню мережу."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    # Якщо тест випадково дійде до справжнього запиту Requests — він впаде.
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_path() -> Path:
    return SAMPLE_PATH


@pytest.fixture
def sample_payload() -> dict:
    # Читаємо файл заново -> кожен тест отримує свій окремий словник.
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
