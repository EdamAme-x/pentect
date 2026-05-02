"""Drive WebGoat with a representative attack scenario, save HAR to disk.

Usage:
  cd demo/webgoat && docker compose up -d
  python demo/webgoat/capture.py

Result: demo/webgoat/captured.har with all requests/responses recorded.

WebGoat is a Spring Boot training app -- responses look very different from
Juice Shop (which is Node/Express). The leak surface is also different
(Spring Security CSRF tokens, JSESSIONID cookies, HTML lesson content
embedded in JSON, etc.), which is exactly what we want to stress-test
Pentect on a fresh distribution.
"""
from __future__ import annotations

import time
import urllib.request
from pathlib import Path


BASE = "http://127.0.0.1:8089/WebGoat"
HAR_PATH = Path(__file__).parent / "captured.har"


def _wait_until_up(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/login", timeout=2).read()
            return
        except Exception:
            time.sleep(1.0)
    raise SystemExit(f"WebGoat at {BASE} did not come up within {timeout}s")


def _attack(page, ctx) -> None:
    # 1. login page
    page.goto(f"{BASE}/login")

    # 2. register a new user (creates a session)
    page.goto(f"{BASE}/registration")
    try:
        page.fill("#username", "pentect_demo")
        page.fill("#password", "Hunter2pass!")
        page.fill("#matchingPassword", "Hunter2pass!")
        page.fill("#agree", "agree", timeout=2000)
    except Exception:
        pass  # form structure varies between WebGoat versions
    try:
        page.click("button[type=submit]", timeout=3000)
    except Exception:
        pass

    # 3. login (whether registration worked or not, default credentials exist)
    page.goto(f"{BASE}/login")
    try:
        page.fill("#username", "pentect_demo")
        page.fill("#password", "Hunter2pass!")
        page.click("button[type=submit]")
    except Exception:
        pass
    page.wait_for_timeout(2000)

    # 4. visit the welcome / lessons listing
    page.goto(f"{BASE}/start.mvc")
    page.wait_for_timeout(1500)

    # 5. exercise a few lesson endpoints (these emit JSON / HTML responses)
    lesson_paths = [
        "/lesson_info.mvc",
        "/service/lessonmenu.mvc",
        "/service/lessonprogress.mvc",
        "/service/hint.mvc?lessonName=SqlInjection",
        "/SqlInjection.lesson.lesson",
        "/IDOR.lesson.lesson",
        "/HttpBasics.lesson.lesson",
        "/CrossSiteScripting.lesson.lesson",
    ]
    for p in lesson_paths:
        try:
            page.goto(f"{BASE}{p}")
            page.wait_for_timeout(300)
        except Exception:
            pass

    # 6. simulate an SQLi attempt against the WebGoat lesson endpoint
    try:
        ctx.request.post(
            f"{BASE}/SqlInjection/attack2",
            form={"query": "SELECT * FROM users WHERE name='Smith' OR '1'='1'"},
        )
    except Exception:
        pass

    # 7. an IDOR enumeration shape on the user info endpoint
    for uid in (1, 2, 3, 9999):
        try:
            ctx.request.get(f"{BASE}/users/{uid}")
        except Exception:
            pass


def main() -> None:
    from playwright.sync_api import sync_playwright

    _wait_until_up()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(
            record_har_path=str(HAR_PATH),
            record_har_content="embed",
            ignore_https_errors=True,
        )
        page = ctx.new_page()
        try:
            _attack(page, ctx)
        finally:
            ctx.close()
            browser.close()
    print(f"wrote {HAR_PATH} ({HAR_PATH.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
