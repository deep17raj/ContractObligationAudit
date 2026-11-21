"""miner.yaml must satisfy Telegraph's closed schema.

Registration is rejected outright on any unknown key, so these tests are the cheap way to
find that out before spending the MACHINA bond on a failing transaction.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RAW = (ROOT / "miner.yaml").read_bytes()
DOC = yaml.safe_load(RAW)

TOP = {"version", "kind", "id", "slug", "protocol", "name", "description", "base_url",
       "input_schema", "output_schema", "intent_mapping", "polling", "cache_ttl_sec",
       "rate_limit_per_sec", "circuit_threshold", "circuit_cooldown_seconds", "docs",
       "limitations", "errors", "auth", "endpoints", "semantics"}
ENDPOINT = {"path", "external_path", "method", "description", "intents", "params",
            "endpoint_base_url", "content_type", "multipart_fields", "param_map"}
AUTH = {"type", "env_var", "header_name", "value_prefix", "inject"}
SIGNAL = {"confidence_field", "label_field", "reason_field"}
SEMANTICS = {"signal_mapping", "supported_intents"}
PARAM = {"name", "type", "intents", "description", "accepted_fields"}
REQUIRED = {"version", "kind", "id", "slug", "name", "base_url"}

INTENT = "CONTRACT_OBLIGATION_AUDIT_GENERAL"


def test_no_unknown_keys_anywhere():
    assert set(DOC) <= TOP, set(DOC) - TOP
    assert REQUIRED <= set(DOC)
    assert set(DOC["auth"]) <= AUTH and DOC["auth"]["type"] in {"bearer", "header", "none"}
    assert set(DOC["semantics"]) <= SEMANTICS
    assert set(DOC["semantics"]["signal_mapping"]) <= SIGNAL
    for ep in DOC["endpoints"]:
        assert set(ep) <= ENDPOINT, set(ep) - ENDPOINT
        # the classic rejection: these are top-level keys only, never nested in an endpoint
        assert "input_schema" not in ep and "output_schema" not in ep


def test_identity_fields():
    assert DOC["version"] == "1" and DOC["kind"] == "miner"
    assert DOC["protocol"] in {"generic", "bittensor"}
    assert isinstance(DOC["id"], int) and DOC["id"] > 0
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", DOC["slug"])
    assert DOC["base_url"].startswith(("http://", "https://"))
    assert DOC["description"].strip() and DOC["name"].strip()


def test_endpoint_contract_matches_the_served_api():
    (ep,) = DOC["endpoints"]
    assert ep["path"] == "/audit" and ep["external_path"] == "/audit"
    assert ep["method"] == "POST"
    assert ep["description"].strip() and ep["intents"] == [INTENT]
    (p,) = ep["params"]["body"]["required"]
    assert p["name"] == "contract" and p["type"] == "string"
    assert p["intents"] == ["*"] and p["description"]
    assert set(p) <= PARAM, set(p) - PARAM


def test_the_declared_param_is_the_one_the_service_reads():
    from audit.app import _INPUT_FIELDS

    (ep,) = DOC["endpoints"]
    (p,) = ep["params"]["body"]["required"]
    assert p["name"] in _INPUT_FIELDS


def test_signal_mapping_names_real_response_fields():
    from audit.app import AuditResponse

    fields = set(AuditResponse.model_fields)
    sm = DOC["semantics"]["signal_mapping"]
    # There is no numeric confidence in this intent's response, so the key is omitted.
    assert sm == {"label_field": "verdict", "reason_field": "summary"}
    assert "confidence_field" not in sm
    for key, value in sm.items():
        assert value in fields, f"{key}={value} is not a field this service returns"


def test_the_label_field_is_the_enum_telegraph_records_on_chain():
    from audit.models import Verdict

    assert DOC["semantics"]["signal_mapping"]["label_field"] == "verdict"
    assert {v.value for v in Verdict} == {"Compliant", "Partially compliant", "Non-compliant",
                                          "Unclear"}


def test_supported_intents_are_consistent():
    supported = set(DOC["semantics"]["supported_intents"])
    assert supported == {INTENT}
    assert all(set(ep["intents"]) <= supported for ep in DOC["endpoints"])


def test_file_is_lf_only_and_utf8():
    """The on-chain sha256 must match the bytes served at YAML_URL byte for byte."""
    assert b"\r" not in RAW
    assert not RAW.startswith(b"\xef\xbb\xbf"), "a UTF-8 BOM would change the hash"
    RAW.decode("utf-8")


def test_placeholder_host_cannot_be_registered_silently():
    """Until the service is deployed, register.sh must refuse to proceed."""
    script = (ROOT / "register.sh").read_text(encoding="utf-8")
    if "REPLACE-WITH" in DOC["base_url"]:
        assert "REPLACE-WITH" in script, "the guard that blocks a placeholder base_url is missing"


def test_register_script_targets_this_intent_and_keeps_no_secrets():
    script = (ROOT / "register.sh").read_text(encoding="utf-8")
    assert INTENT in script
    assert "sha256" in script.lower()
    assert "/audit" in script, "the pre-flight probe must hit the real endpoint"
    for secret in ("MINER_PRIVATE_KEY=0x", "0x1234"):
        assert f"\n{secret}" not in script, "no real or dummy key may be hardcoded"


def test_register_script_checks_the_enum_before_spending_the_bond():
    script = (ROOT / "register.sh").read_text(encoding="utf-8")
    for value in ("Compliant", "Partially compliant", "Non-compliant", "Unclear"):
        assert value in script, f"the pre-flight enum check does not cover {value!r}"


def test_the_service_serves_the_yaml_bytes_unmodified():
    """YAML_URL can point at the running service, so this route must be byte-exact."""
    from fastapi.testclient import TestClient

    from audit.app import create_app
    from tests.conftest import make_settings
    from tests.test_api import StubPipeline

    with TestClient(create_app(make_settings(), pipeline=StubPipeline())) as client:
        r = client.get("/miner.yaml")
    assert r.status_code == 200
    assert r.content == RAW, "served bytes differ from miner.yaml on disk"
    assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(RAW).hexdigest()
    assert b"\r" not in r.content
