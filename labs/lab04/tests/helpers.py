"""Допоміжні функції для зручного доступу до вкладених частин відповіді."""

from typing import Any


def cve_of(payload: dict[str, Any]) -> dict[str, Any]:
    return payload["vulnerabilities"][0]["cve"]


def metric_of(payload: dict[str, Any]) -> dict[str, Any]:
    return cve_of(payload)["metrics"]["cvssMetricV31"][0]


def cvss_of(payload: dict[str, Any]) -> dict[str, Any]:
    return metric_of(payload)["cvssData"]


def make_metric(score: float, vector: str, source: str, kind: str) -> dict[str, Any]:
    """Мінімальна оцінка v3.1 для тестів вибору Primary/Secondary."""
    return {
        "source": source,
        "type": kind,
        "cvssData": {"version": "3.1", "baseScore": score, "attackVector": vector},
    }
