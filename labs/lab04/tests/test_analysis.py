"""Тести analysis.py (варіант 1: score >= 7.0 і attackVector == NETWORK)."""

import copy
import math

import pytest

from lab04.analysis import build_report, extract_record
from lab04.tests.helpers import cve_of, cvss_of, make_metric

CVE = "CVE-2099-10001"


def run(payload, variant=1):
    return build_report(extract_record(payload, CVE), CVE, variant)


def test_sample_report_matches_expected_for_variant_1(sample_payload):
    assert run(sample_payload) == {
        "cve_id": CVE,
        "variant": 1,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
        "observed": "NETWORK",
        "decision": "review",
    }


@pytest.mark.parametrize(
    "score, vector, expected",
    [
        (6.9, "NETWORK", "other"),  # нижче порога
        (7.0, "NETWORK", "review"),  # рівно на порозі (>=)
        (7, "NETWORK", "review"),  # ціле число теж коректне
        (7.1, "NETWORK", "review"),  # вище порога
        (10.0, "NETWORK", "review"),  # верхня межа діапазону
        (0.0, "NETWORK", "other"),  # нижня межа діапазону
        (9.8, "LOCAL", "other"),  # висока оцінка, але інша ознака
        (9.8, "ADJACENT_NETWORK", "other"),
        (7.0, "PHYSICAL", "other"),
    ],
)
def test_variant_1_decision(sample_payload, score, vector, expected):
    cvss_of(sample_payload).update(baseScore=score, attackVector=vector)
    assert run(sample_payload)["decision"] == expected


def test_empty_vulnerabilities_gives_not_found():
    payload = {"vulnerabilities": []}
    assert extract_record(payload, CVE) is None
    assert build_report(None, CVE, 1) == {
        "cve_id": CVE,
        "variant": 1,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score(sample_payload):
    cve_of(sample_payload)["vulnStatus"] = "Rejected"
    report = run(sample_payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None
    assert report["vector"] is None


def test_rejected_does_not_validate_metrics(sample_payload):
    cve_of(sample_payload).update(vulnStatus="Rejected", metrics=None)
    assert run(sample_payload)["decision"] == "rejected"


def test_missing_status_gives_insufficient_data(sample_payload):
    del cve_of(sample_payload)["vulnStatus"]
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["description"] == "Synthetic vulnerability for offline API testing."


def test_missing_status_does_not_validate_metrics(sample_payload):
    del cve_of(sample_payload)["vulnStatus"]
    cve_of(sample_payload)["metrics"] = "garbage"
    assert run(sample_payload)["decision"] == "insufficient_data"


def _no_metrics_key(p):
    del cve_of(p)["metrics"]


def _no_v31_key(p):
    cve_of(p)["metrics"] = {"cvssMetricV40": [{"cvssData": {"baseScore": 9.9}}]}


def _empty_v31_list(p):
    cve_of(p)["metrics"]["cvssMetricV31"] = []


@pytest.mark.parametrize("mutate", [_no_metrics_key, _no_v31_key, _empty_v31_list])
def test_missing_score_gives_insufficient_data(sample_payload, mutate):
    mutate(sample_payload)
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_rule_field_gives_insufficient_data(sample_payload):
    del cvss_of(sample_payload)["attackVector"]
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8  # оцінка є, бракує лише поля правила
    assert report["observed"] is None


@pytest.mark.parametrize(
    "bad_value", [None, "network", "BOGUS", 5, True, ["NETWORK"], ""]
)
def test_invalid_rule_field_raises(sample_payload, bad_value):
    cvss_of(sample_payload)["attackVector"] = bad_value
    with pytest.raises(ValueError):
        run(sample_payload)


def test_primary_has_priority_over_earlier_secondary(sample_payload):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_metric(9.0, "LOCAL", "secondary@example.org", "Secondary"),
        make_metric(7.5, "NETWORK", "nvd@nist.gov", "Primary"),
    ]
    report = run(sample_payload)
    assert report["score"] == 7.5
    assert report["score_source"] == "nvd@nist.gov"
    assert report["observed"] == "NETWORK"
    assert report["decision"] == "review"


def test_first_item_is_used_when_no_primary(sample_payload):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_metric(8.0, "NETWORK", "first@example.org", "Secondary"),
        make_metric(3.0, "LOCAL", "second@example.org", "Secondary"),
    ]
    report = run(sample_payload)
    assert report["score_source"] == "first@example.org"
    assert report["score"] == 8.0
    assert report["decision"] == "review"


def test_score_and_feature_come_from_the_same_metric(sample_payload):
    # Primary: низька оцінка. Secondary: висока оцінка з NETWORK. Змішувати не можна.
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_metric(9.8, "NETWORK", "secondary@example.org", "Secondary"),
        make_metric(5.0, "NETWORK", "nvd@nist.gov", "Primary"),
    ]
    assert run(sample_payload)["decision"] == "other"


@pytest.mark.parametrize(
    "descriptions, expected",
    [
        ([{"lang": "es", "value": "Hola"}, {"lang": "en", "value": "Hello"}], "Hello"),
        ([{"lang": "en", "value": ""}, {"lang": "en", "value": "Second"}], "Second"),
        ([{"lang": "en", "value": "A"}, {"lang": "en", "value": "B"}], "A"),
        ([{"lang": "es", "value": "Hola"}], None),
        ([], None),
    ],
)
def test_description_selection(sample_payload, descriptions, expected):
    cve_of(sample_payload)["descriptions"] = descriptions
    assert run(sample_payload)["description"] == expected


def test_missing_descriptions_gives_none(sample_payload):
    del cve_of(sample_payload)["descriptions"]
    assert run(sample_payload)["description"] is None


def test_missing_optional_report_fields_become_none(sample_payload):
    del cvss_of(sample_payload)["version"]
    del cvss_of(sample_payload)["vectorString"]
    del cve_of(sample_payload)["metrics"]["cvssMetricV31"][0]["source"]
    report = run(sample_payload)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None
    assert report["decision"] == "review"


@pytest.mark.parametrize("payload", [[], None, "text", 5])
def test_payload_must_be_dict(payload):
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("vulnerabilities"),
        lambda p: p.update(vulnerabilities=None),
        lambda p: p.update(vulnerabilities={}),
        lambda p: p["vulnerabilities"].append(copy.deepcopy(p["vulnerabilities"][0])),
        lambda p: p.update(vulnerabilities=["x"]),
        lambda p: p["vulnerabilities"][0].pop("cve"),
        lambda p: p["vulnerabilities"][0].update(cve=[]),
        lambda p: cve_of(p).pop("id"),
        lambda p: cve_of(p).update(id="CVE-2099-99999"),
        lambda p: cve_of(p).update(vulnStatus=""),
        lambda p: cve_of(p).update(vulnStatus=None),
        lambda p: cve_of(p).update(vulnStatus=5),
        lambda p: cve_of(p).update(descriptions=None),
        lambda p: cve_of(p).update(descriptions={}),
        lambda p: cve_of(p).update(descriptions=["x"]),
        lambda p: cve_of(p).update(descriptions=[{"lang": "en"}]),
        lambda p: cve_of(p).update(descriptions=[{"lang": 1, "value": "x"}]),
        lambda p: cve_of(p).update(metrics=None),
        lambda p: cve_of(p).update(metrics=[]),
        lambda p: cve_of(p)["metrics"].update(cvssMetricV31=None),
        lambda p: cve_of(p)["metrics"].update(cvssMetricV31={}),
        lambda p: cve_of(p)["metrics"].update(cvssMetricV31=["x"]),
        lambda p: cve_of(p)["metrics"]["cvssMetricV31"][0].pop("cvssData"),
        lambda p: cve_of(p)["metrics"]["cvssMetricV31"][0].update(cvssData=[]),
        lambda p: cve_of(p)["metrics"]["cvssMetricV31"][0].update(source=None),
        lambda p: cve_of(p)["metrics"]["cvssMetricV31"][0].update(source=""),
        lambda p: cvss_of(p).pop("baseScore"),
        lambda p: cvss_of(p).update(baseScore=None),
        lambda p: cvss_of(p).update(baseScore="9.8"),
        lambda p: cvss_of(p).update(baseScore=True),
        lambda p: cvss_of(p).update(baseScore=math.nan),
        lambda p: cvss_of(p).update(baseScore=math.inf),
        lambda p: cvss_of(p).update(baseScore=-0.1),
        lambda p: cvss_of(p).update(baseScore=10.1),
        lambda p: cvss_of(p).update(version="3.0"),
        lambda p: cvss_of(p).update(version=None),
        lambda p: cvss_of(p).update(vectorString=""),
        lambda p: cvss_of(p).update(vectorString=None),
    ],
)
def test_contract_violation_raises_value_error(sample_payload, mutate):
    mutate(sample_payload)
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE)


def test_extract_and_build_do_not_modify_payload(sample_payload):
    before = copy.deepcopy(sample_payload)
    run(sample_payload)
    assert sample_payload == before


@pytest.mark.parametrize("variant", [0, 16, -1, True, False, "1", 1.0, None])
def test_invalid_variant_raises(sample_payload, variant):
    record = extract_record(sample_payload, CVE)
    with pytest.raises(ValueError):
        build_report(record, CVE, variant)


@pytest.mark.parametrize(
    "variant, threshold, field, expected",
    [
        (1, 7.0, "attackVector", "NETWORK"),
        (2, 8.0, "attackComplexity", "LOW"),
        (3, 7.0, "privilegesRequired", "NONE"),
        (4, 8.0, "userInteraction", "NONE"),
        (5, 7.0, "confidentialityImpact", "HIGH"),
        (6, 7.0, "integrityImpact", "HIGH"),
        (7, 7.0, "availabilityImpact", "HIGH"),
        (8, 9.0, "scope", "CHANGED"),
        (9, 5.0, "attackVector", "LOCAL"),
        (10, 6.0, "privilegesRequired", "LOW"),
        (11, 6.0, "userInteraction", "REQUIRED"),
        (12, 6.0, "confidentialityImpact", "LOW"),
        (13, 6.0, "integrityImpact", "LOW"),
        (14, 6.0, "availabilityImpact", "LOW"),
        (15, 8.0, "attackComplexity", "HIGH"),
    ],
)
def test_rule_table(sample_payload, variant, threshold, field, expected):
    rule = run(sample_payload, variant)["rule"]
    assert rule == {"threshold": threshold, "field": field, "expected": expected}


@pytest.mark.parametrize("variant", range(1, 8))
def test_sample_gives_review_for_variants_1_to_7(sample_payload, variant):
    assert run(sample_payload, variant)["decision"] == "review"


@pytest.mark.parametrize("variant", range(8, 16))
def test_sample_gives_other_for_variants_8_to_15(sample_payload, variant):
    assert run(sample_payload, variant)["decision"] == "other"
