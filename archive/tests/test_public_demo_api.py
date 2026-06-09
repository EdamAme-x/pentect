from fastapi.testclient import TestClient

from server.main import _rate_windows, app


def test_public_demo_health_has_pentect_and_presidio():
    _rate_windows.clear()
    client = TestClient(app)

    res = client.get("/api/health")

    assert res.status_code == 200
    payload = res.json()
    assert payload["available_backends"] == ["opf_pf", "presidio"]
    assert payload["recovery_enabled"] is False


def test_public_demo_rejects_disabled_backend():
    _rate_windows.clear()
    client = TestClient(app)

    res = client.post(
        "/api/mask",
        json={
            "text": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "backend": "gemma",
        },
    )

    assert res.status_code == 400
    assert "disabled" in res.json()["detail"]


def test_public_demo_rejects_oversized_input():
    _rate_windows.clear()
    client = TestClient(app)

    res = client.post("/api/mask", json={"text": "x" * 50001, "backend": "rule"})

    assert res.status_code == 413
    assert "input too large" in res.json()["detail"]
