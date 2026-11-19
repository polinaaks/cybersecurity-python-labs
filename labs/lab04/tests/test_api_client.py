"""Тести api_client.py: підміняємо requests.get там, де його шукає клієнт."""

from unittest.mock import Mock

import pytest
import requests

from lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def make_response(status: int = 200, payload=None) -> Mock:
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload if payload is not None else {}
    return response


def test_build_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_blank_key_means_no_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_key_is_stripped_and_sent_as_api_key_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(200, payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response("CVE-2099-10001") == payload

    fake_get.assert_called_once_with(
        URL,
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_in_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    fake_get = Mock(return_value=make_response())
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response("CVE-2099-10001")

    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"] == {"Accept": "application/json", "apiKey": "fake-key-123"}
    assert kwargs["params"] == {"cveId": "CVE-2099-10001"}
    assert "fake-key-123" not in fake_get.call_args.args[0]


def test_http_error_is_propagated(monkeypatch):
    response = make_response(500)
    # Сам status_code=500 виняток НЕ піднімає: Mock потрібно навчити цього явно.
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Server Error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.HTTPError) as info:
        api_client.fetch_response("CVE-2099-10001")

    assert info.value.response.status_code == 500
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [204, 301, 302])
def test_non_200_success_status_is_rejected(monkeypatch, status):
    response = make_response(status)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(api_client.UnexpectedStatusError) as info:
        api_client.fetch_response("CVE-2099-10001")

    assert info.value.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("timeout"),
        requests.exceptions.ReadTimeout("timeout"),
        requests.exceptions.ConnectionError("no route"),
    ],
)
def test_network_errors_are_propagated(monkeypatch, error):
    monkeypatch.setattr(api_client.requests, "get", Mock(side_effect=error))
    with pytest.raises(type(error)):
        api_client.fetch_response("CVE-2099-10001")


def test_invalid_json_is_propagated(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_autouse_fixture_blocks_real_requests():
    # Без підміни справжній запит неможливий: Session.request видалено фікстурою.
    with pytest.raises(AttributeError):
        requests.get("https://example.invalid")
