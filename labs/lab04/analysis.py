"""Перевірка відповіді NVD і правило аналізу за варіантом.

Модуль "чистий": не читає файлів і змінних середовища, не звертається до
мережі, нічого не друкує і не змінює отриманий payload. Це робить його
легким для модульного тестування.
"""

from __future__ import annotations

import math
from typing import Any

SUPPORTED_CVSS_VERSION = "3.1"
MIN_VARIANT = 1
MAX_VARIANT = 15

# Допустимі значення полів cvssData (таблиця з розділу 2.2 методички).
_IMPACT = ("NONE", "LOW", "HIGH")
ALLOWED_VALUES: dict[str, tuple[str, ...]] = {
    "attackVector": ("NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"),
    "attackComplexity": ("LOW", "HIGH"),
    "privilegesRequired": ("NONE", "LOW", "HIGH"),
    "userInteraction": ("NONE", "REQUIRED"),
    "scope": ("UNCHANGED", "CHANGED"),
    "confidentialityImpact": _IMPACT,
    "integrityImpact": _IMPACT,
    "availabilityImpact": _IMPACT,
}

# Правила варіантів (розділ 4): номер -> (поріг T, поле field, значення expected).
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


def _is_valid_score(value: Any) -> bool:
    """True, якщо value — скінченне число 0..10, що не є bool.

    bool є підкласом int, тому True/False треба відсікати окремо;
    рядок "9.8" не є JSON-числом; NaN та inf відхиляємо через isfinite.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and 0 <= value <= 10


def _is_valid_variant(variant: Any) -> bool:
    return (
        isinstance(variant, int)
        and not isinstance(variant, bool)
        and MIN_VARIANT <= variant <= MAX_VARIANT
    )


def _optional_str(container: dict[str, Any], key: str, label: str) -> str | None:
    """Необов'язкове рядкове поле: немає -> None; є -> має бути непорожнім рядком.

    Саме тут розрізняємо "поля немає" (None, брак даних) і "поле є, але
    неправильне" (ValueError, помилка даних): null чи число не підміняємо.
    """
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} має бути непорожнім рядком")
    return value


def _pick_description(cve: dict[str, Any]) -> str | None:
    """Повертає перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise ValueError("descriptions має бути списком")
    chosen: str | None = None
    for item in descriptions:
        # Перевіряємо ВСІ елементи, навіть після того, як опис уже знайдено.
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("lang"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise ValueError("елемент descriptions має містити рядки lang і value")
        if chosen is None and item["lang"] == "en" and item["value"].strip():
            chosen = item["value"]
    return chosen


def _select_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає оцінку CVSS v3.1: перша Primary, інакше перша в списку.

    None означає "оцінки немає" (метрик немає або список порожній).
    Якщо структура є, але неправильна — ValueError.
    """
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None  # можуть бути лише інші версії CVSS — для нас це "немає v3.1"
    items = metrics["cvssMetricV31"]
    if not isinstance(items, list):
        raise ValueError("cvssMetricV31 має бути списком")
    if not items:
        return None
    if not all(isinstance(item, dict) for item in items):
        raise ValueError("елементи cvssMetricV31 мають бути об'єктами")
    for item in items:
        if item.get("type") == "Primary":
            return item
    return items[0]


def _parse_metric(metric: dict[str, Any]) -> dict[str, Any]:
    """Перевіряє вибрану оцінку й повертає її у внутрішньому форматі."""
    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("cvssData має бути об'єктом")
    score = cvss_data.get("baseScore")
    if not _is_valid_score(score):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10")
    version = _optional_str(cvss_data, "version", "cvssData.version")
    if version is not None and version != SUPPORTED_CVSS_VERSION:
        raise ValueError(f"cvssData.version має дорівнювати {SUPPORTED_CVSS_VERSION}")
    return {
        "score": score,
        "source": _optional_str(metric, "source", "source"),
        "version": version,
        "vector": _optional_str(cvss_data, "vectorString", "cvssData.vectorString"),
        # Поверхнева копія: payload ми не змінюємо і не віддаємо посилання на нього.
        "cvss_data": dict(cvss_data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    Формат запису (словник):
        {
            "vuln_status": str | None,   # статус NVD (None, якщо відсутній)
            "description": str | None,   # перший непорожній англ. опис
            "metric": {                  # None для Rejected / без статусу / без оцінки v3.1
                "score": int | float,    # перевірений baseScore
                "source": str | None,
                "version": str | None,   # "3.1" або None
                "vector": str | None,
                "cvss_data": dict,       # копія cvssData для перевірки поля варіанта
            } | None,
        }
    Повертає None, якщо vulnerabilities порожній ("запис не знайдено").
    Піднімає ValueError, якщо структура відповіді порушує контракт.
    """
    if not isinstance(payload, dict):
        raise ValueError("відповідь NVD має бути JSON-об'єктом")
    if "vulnerabilities" not in payload:
        raise ValueError("у відповіді немає поля vulnerabilities")
    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise ValueError("vulnerabilities має бути списком")
    if not vulnerabilities:
        return None  # порожній результат пошуку — це НЕ помилка
    if len(vulnerabilities) > 1:
        raise ValueError("для точного cveId очікується не більше одного запису")

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_str(cve, "vulnStatus", "vulnStatus")
    description = _pick_description(cve)

    # Для Rejected і для відсутнього статусу оцінки взагалі не аналізуємо
    # (навіть їхня некоректна структура не викликає помилки).
    metric = None
    if status is not None and status != "Rejected":
        selected = _select_metric(cve)
        if selected is not None:
            metric = _parse_metric(selected)

    return {"vuln_status": status, "description": description, "metric": metric}


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта й повертає словник звіту (усі ключі завжди є).

    Порядок станів: not_found -> rejected -> insufficient_data -> review/other.
    ValueError — якщо номер варіанта чи значення поля варіанта некоректні.
    """
    if not _is_valid_variant(variant):
        raise ValueError(f"номер варіанта має бути цілим від {MIN_VARIANT} до {MAX_VARIANT}")
    threshold, field, expected = VARIANT_RULES[variant]

    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    if record["vuln_status"] is None or record["metric"] is None:
        report["decision"] = "insufficient_data"
        return report

    metric = record["metric"]
    report["cvss_version"] = metric["version"]
    report["score"] = metric["score"]
    report["score_source"] = metric["source"]
    report["vector"] = metric["vector"]

    cvss_data = metric["cvss_data"]
    if field not in cvss_data:
        # Поля немає — це брак даних, а не помилка.
        report["decision"] = "insufficient_data"
        return report

    observed = cvss_data[field]
    # Поле є, але null / не рядок / значення поза таблицею — помилка даних.
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"недопустиме значення поля {field}")
    report["observed"] = observed

    # Обидві умови беремо з ТІЄЇ САМОЇ вибраної оцінки.
    if metric["score"] >= threshold and observed == expected:
        report["decision"] = "review"
    else:
        report["decision"] = "other"
    return report
