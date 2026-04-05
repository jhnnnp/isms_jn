from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from isms_pii_toolkit.api import GENERIC_DECRYPT_ERROR, MAX_UPLOAD_BYTES, app, run
from isms_pii_toolkit.schemas import MAX_TEXT_LENGTH

client = TestClient(app)

SAMPLE_TEXT = "홍길동 900101-1234568, 010-1234-5678, hong@example.com"
AES_KEY = "a" * 64


def test_health_endpoint_returns_service_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_root_page_returns_demo_ui() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "개인정보 탐지 및 비식별화 시연" in response.text
    assert "샘플 입력" in response.text
    assert "간편 튜토리얼" in response.text
    assert "화면과 API 대응" in response.text
    assert "실시간 처리 흐름" in response.text
    assert "결과 요약" in response.text


def test_scan_text_returns_detected_matches_and_summary() -> None:
    response = client.post("/scan/text", json={"text": SAMPLE_TEXT})

    payload = response.json()
    assert response.status_code == 200
    assert payload["summary"] == {
        "totalMatches": 3,
        "counts": {"rrn": 1, "phone": 1, "email": 1},
    }
    assert [match["piiType"] for match in payload["matches"]] == ["rrn", "phone", "email"]
    assert [match["validationMethod"] for match in payload["matches"]] == [
        "rrn_checksum",
        "regex_pattern",
        "regex_pattern",
    ]


def test_scan_text_rejects_oversized_payload() -> None:
    response = client.post("/scan/text", json={"text": "A" * (MAX_TEXT_LENGTH + 1)})

    assert response.status_code == 422


def test_redact_text_masks_by_default() -> None:
    response = client.post("/redact/text", json={"text": SAMPLE_TEXT})

    payload = response.json()
    assert response.status_code == 200
    assert "900101-1******" in payload["outputText"]
    assert "010-****-5678" in payload["outputText"]
    assert "h***@example.com" in payload["outputText"]
    assert {match["strategy"] for match in payload["matches"]} == {"mask"}
    assert [(m["piiType"], m["start"], m["end"]) for m in payload["matches"]] == [
        ("rrn", 4, 18),
        ("phone", 20, 33),
        ("email", 35, 51),
    ]


def test_redact_text_requires_key_when_encrypt_types_are_requested() -> None:
    response = client.post(
        "/redact/text",
        json={"text": SAMPLE_TEXT, "encryptTypes": ["rrn"]},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "encryptionKey is required when encryptTypes is provided."


def test_redact_and_decrypt_text_round_trip() -> None:
    redact_response = client.post(
        "/redact/text",
        json={
            "text": SAMPLE_TEXT,
            "encryptTypes": ["rrn"],
            "encryptionKey": AES_KEY,
        },
    )

    redacted_text = redact_response.json()["outputText"]
    assert "ENC::rrn::" in redacted_text

    decrypt_response = client.post(
        "/decrypt/text",
        json={"text": redacted_text, "encryptionKey": AES_KEY},
    )

    assert decrypt_response.status_code == 200
    assert "900101-1234568" in decrypt_response.json()["outputText"]


def test_decrypt_text_rejects_invalid_token() -> None:
    response = client.post(
        "/decrypt/text",
        json={"text": "ENC::rrn::broken-token", "encryptionKey": AES_KEY},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == GENERIC_DECRYPT_ERROR


def test_decrypt_text_rejects_wrong_key() -> None:
    redact_response = client.post(
        "/redact/text",
        json={
            "text": SAMPLE_TEXT,
            "encryptTypes": ["rrn"],
            "encryptionKey": AES_KEY,
        },
    )

    response = client.post(
        "/decrypt/text",
        json={"text": redact_response.json()["outputText"], "encryptionKey": "b" * 64},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == GENERIC_DECRYPT_ERROR


def test_scan_file_returns_file_metadata() -> None:
    response = client.post(
        "/scan/file",
        files={"upload": ("sample.txt", SAMPLE_TEXT.encode("utf-8"), "text/plain")},
    )

    payload = response.json()
    assert response.status_code == 200
    assert payload["file"] == {
        "filename": "sample.txt",
        "contentType": "text/plain",
        "sizeBytes": len(SAMPLE_TEXT.encode("utf-8")),
    }
    assert payload["summary"]["totalMatches"] == 3


def test_scan_file_rejects_non_text_plain_upload() -> None:
    response = client.post(
        "/scan/file",
        files={"upload": ("sample.json", b"{}", "application/json")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only text/plain uploads are supported."


def test_redact_file_rejects_oversized_upload() -> None:
    response = client.post(
        "/redact/file",
        files={"upload": ("large.txt", b"A" * (MAX_UPLOAD_BYTES + 1), "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded file exceeds the maximum allowed size."


def test_redact_file_rejects_non_utf8_text_upload() -> None:
    response = client.post(
        "/redact/file",
        files={"upload": ("broken.txt", b"\xff\xfe\x00", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded file must be valid UTF-8 text."


def test_redact_file_supports_encrypt_types_in_multipart_form() -> None:
    response = client.post(
        "/redact/file",
        data={"encryptTypes": "rrn", "encryptionKey": AES_KEY},
        files={"upload": ("sample.txt", SAMPLE_TEXT.encode("utf-8"), "text/plain")},
    )

    payload = response.json()
    assert response.status_code == 200
    assert "ENC::rrn::" in payload["outputText"]
    assert payload["file"]["filename"] == "sample.txt"
    assert [match["strategy"] for match in payload["matches"]].count("encrypt") == 1


def test_redact_file_requires_key_when_encrypt_types_are_requested() -> None:
    response = client.post(
        "/redact/file",
        data={"encryptTypes": "rrn"},
        files={"upload": ("sample.txt", SAMPLE_TEXT.encode("utf-8"), "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "encryptionKey is required when encryptTypes is provided."


def test_run_binds_to_localhost_by_default(monkeypatch) -> None:
    monkeypatch.delenv("PII_TOOLKIT_API_HOST", raising=False)
    monkeypatch.delenv("PII_TOOLKIT_API_PORT", raising=False)

    with patch("uvicorn.run") as mock_run:
        run()

    mock_run.assert_called_once_with(
        "isms_pii_toolkit.api:app",
        host="127.0.0.1",
        port=8000,
    )
