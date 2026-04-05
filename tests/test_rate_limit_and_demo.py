from __future__ import annotations

from fastapi.testclient import TestClient

from isms_pii_toolkit.api import create_app


def test_rate_limit_returns_429_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("PII_TOOLKIT_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("PII_TOOLKIT_RATE_LIMIT_PER_MINUTE", "3")
    app = create_app()
    client = TestClient(app)
    for _ in range(3):
        response = client.post("/scan/text", json={"text": "ping"})
        assert response.status_code == 200
    blocked = client.post("/scan/text", json={"text": "ping"})
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "Too many requests. Try again later."


def test_health_exempt_from_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("PII_TOOLKIT_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("PII_TOOLKIT_RATE_LIMIT_PER_MINUTE", "2")
    app = create_app()
    client = TestClient(app)
    for _ in range(5):
        assert client.get("/health").status_code == 200


def test_demo_page_disabled_returns_404(monkeypatch) -> None:
    monkeypatch.setenv("PII_TOOLKIT_ENABLE_DEMO", "0")
    app = create_app()
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 404
