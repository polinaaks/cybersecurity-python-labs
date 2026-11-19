"""Тести CLI (main.py): локальний режим, помилки, коди завершення."""

import json
from unittest.mock import Mock

import pytest
import requests

from lab04 import api_client
from lab04 import main as cli
from lab04.tests.helpers import cve_of

CVE = "CVE-2099-10001"


def run_local(path, capsys, cve=CVE):
    code = cli.main(["--cve", cve, "--input", str(path)])
    return code, capsys.readouterr()


def write_json(tmp_path, data):
    path = tmp_path / "response.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def test_local_mode_prints_report_and_does_not_use_network(monkeypatch, capsys, sample_path):
    fake_fetch = Mock(side_effect=AssertionError("мережа не повинна викликатись"))
    monkeypatch.setattr(cli.api_client, "fetch_response", fake_fetch)

    code, out = run_local(sample_path, capsys)

    assert code == 0
    assert out.err == ""
    assert out.out.count("\n") == 1  # рівно один JSON-об'єкт
    report = json.loads(out.out)
    assert report["decision"] == "review"
    assert report["variant"] == 1
    assert report["score"] == 9.8
    fake_fetch.assert_not_called()


def test_output_keeps_non_ascii_characters(tmp_path, capsys, sample_payload):
    cve_of(sample_payload)["descriptions"][0]["value"] = "Тестовий опис"
    code, out = run_local(write_json(tmp_path, sample_payload), capsys)
    assert code == 0
    assert "Тестовий опис" in out.out  # ensure_ascii=False


def test_not_found_is_exit_code_zero(tmp_path, capsys):
    code, out = run_local(write_json(tmp_path, {"vulnerabilities": []}), capsys)
    assert code == 0
    assert json.loads(out.out)["decision"] == "not_found"


def test_network_mode_passes_cve_to_client(monkeypatch, capsys, sample_payload):
    fake_fetch = Mock(return_value=sample_payload)
    monkeypatch.setattr(cli.api_client, "fetch_response", fake_fetch)

    code = cli.main(["--cve", CVE])

    assert code == 0
    fake_fetch.assert_called_once_with(CVE)
    assert json.loads(capsys.readouterr().out)["decision"] == "review"


def _http_error(status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.exceptions.HTTPError("boom", response=response)


@pytest.mark.parametrize(
    "error, expected_text",
    [
        (requests.exceptions.ConnectTimeout("x"), "час очікування"),
        (requests.exceptions.ReadTimeout("x"), "час очікування"),
        (requests.exceptions.ConnectionError("x"), "з'єднатися"),
        (_http_error(404), "404"),
        (_http_error(500), "500"),
        (api_client.UnexpectedStatusError(302), "302"),
        (requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1), "JSON"),
        (requests.exceptions.RequestException("x"), "HTTP-запит"),
    ],
)
def test_network_errors_give_exit_code_1(monkeypatch, capsys, error, expected_text):
    monkeypatch.setattr(cli.api_client, "fetch_response", Mock(side_effect=error))

    code = cli.main(["--cve", CVE])
    out = capsys.readouterr()

    assert code == 1  # зокрема 404 — це помилка, а не not_found
    assert out.out == ""
    assert expected_text in out.err
    assert "Traceback" not in out.err


def test_secrets_and_exception_text_are_not_printed(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    error = requests.exceptions.ConnectionError("GET ...?apiKey=fake-secret-key failed")
    monkeypatch.setattr(cli.api_client, "fetch_response", Mock(side_effect=error))

    assert cli.main(["--cve", CVE]) == 1
    out = capsys.readouterr()
    assert "fake-secret-key" not in out.err
    assert "apiKey" not in out.err


def test_missing_file_gives_exit_code_1(tmp_path, capsys):
    code, out = run_local(tmp_path / "missing.json", capsys)
    assert code == 1
    assert out.out == ""
    assert "файл" in out.err


def test_directory_instead_of_file_gives_exit_code_1(tmp_path, capsys):
    code, out = run_local(tmp_path, capsys)
    assert code == 1
    assert out.out == ""


def test_invalid_json_file_gives_exit_code_1(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, out = run_local(path, capsys)
    assert code == 1
    assert out.out == ""
    assert "JSON" in out.err
    assert "Traceback" not in out.err


def test_non_utf8_file_gives_exit_code_1(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe\x00\x80")
    code, out = run_local(path, capsys)
    assert code == 1
    assert "UTF-8" in out.err


def test_invalid_data_gives_exit_code_1(tmp_path, capsys, sample_payload):
    cve_of(sample_payload)["id"] = "CVE-2099-99999"  # інший ідентифікатор
    code, out = run_local(write_json(tmp_path, sample_payload), capsys)
    assert code == 1
    assert out.out == ""
    assert "Помилка" in out.err
    assert "Traceback" not in out.err


@pytest.mark.parametrize(
    "bad_cve",
    [
        "cve-2099-10001",  # регістр має значення
        "CVE-99-10001",
        "CVE-2099-123",  # менше 4 цифр
        " CVE-2099-10001",
        "CVE-2099-10001 ",
        "CVE-2099-10001\n",
        "XCVE-2099-10001",
        "",
    ],
)
def test_invalid_cve_is_rejected_with_exit_code_2(capsys, sample_path, bad_cve):
    with pytest.raises(SystemExit) as info:
        cli.main(["--cve", bad_cve, "--input", str(sample_path)])
    assert info.value.code == 2
    assert capsys.readouterr().out == ""


def test_missing_cve_argument_exits_with_2(capsys):
    with pytest.raises(SystemExit) as info:
        cli.main([])
    assert info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, -3, True, "1", 1.0, None])
def test_invalid_variant_number_gives_exit_code_2(monkeypatch, capsys, sample_path, variant):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", variant)
    code, out = run_local(sample_path, capsys)
    assert code == 2
    assert out.out == ""
    assert "VARIANT_NUMBER" in out.err


def test_other_variant_number_changes_rule(monkeypatch, capsys, sample_path):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", 8)
    code, out = run_local(sample_path, capsys)
    report = json.loads(out.out)
    assert code == 0
    assert report["variant"] == 8
    assert report["rule"] == {"threshold": 9.0, "field": "scope", "expected": "CHANGED"}
    assert report["decision"] == "other"
