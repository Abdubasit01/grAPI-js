#!/usr/bin/env python3
import argparse
import asyncio
import json
import re
import sys
import threading
import uuid
from playwright.async_api import async_playwright

# Color codes
GREEN = "\033[92m"
RESET = "\033[0m"
COLORS = {
    "GET": "\033[92m",
    "POST": "\033[93m",
    "PUT": "\033[94m",
    "DELETE": "\033[95m",
    "OTHER": "\033[0m",
}

BANNER = f"""{GREEN}
            _   ___ ___ 
  __ _ _ _ /_\\ | _ \\_ _|
 / _` | '_/ _ \\|  _/| | 
 \\__, |_|/_/ \\_\\_| |___|
 |___/          by iPsalmy
{RESET}
"""

# Improved API detection
def is_potential_api(url: str) -> bool:
    lowered = url.lower()
    return any(
        keyword in lowered
        for keyword in ["/api/", "/graphql", "/openapi", "/user", "/swagger", ".json"]
    ) or bool(re.search(r"/v[0-9]+(?:/|$)", lowered))

def save_output(endpoints, filename):
    if filename.endswith(".json"):
        with open(filename, "w") as f:
            json.dump(sorted(endpoints), f, indent=2)
    else:
        with open(filename, "w") as f:
            f.write("\n".join(sorted(endpoints)))
    print(f"[+] Saved {len(endpoints)} endpoints to {filename}")

def generate_postman_collection(endpoints, filename):
    collection = {
        "info": {
            "name": "Extracted API Endpoints",
            "_postman_id": str(uuid.uuid4()),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": [
            {
                "name": path,
                "request": {"method": "GET", "header": [], "url": {"raw": path}},
                "response": [],
            }
            for path in sorted(endpoints)
        ],
    }
    with open(filename, "w") as f:
        json.dump(collection, f, indent=2)
    print(f"[+] Saved Postman collection to {filename}")

async def scan_js_files(page):
    js_urls = await page.evaluate(
        "() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)"
    )
    potential = set()
    for js_url in js_urls:
        try:
            content = await (await page.request.get(js_url)).text()
            matches = re.findall(r"(https?://[^\s'\"<>]+|/[A-Za-z0-9_\-/.]+)", content)
            for match in matches:
                if is_potential_api(match):
                    potential.add(match)
        except:
            continue
    return potential

async def intercept_apis(target_url, timeout, auto_scroll=False):
    apis = set()
    stop_event = threading.Event()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()

        def handle_request(request):
            url = request.url
            method = request.method.upper()
            color = COLORS.get(method, COLORS["OTHER"])
            if is_potential_api(url) and url not in apis:
                apis.add(url)
                sys.stdout.write(f"{color}[API detected] {method}: {url}{RESET}\n")
                sys.stdout.flush()

        context.on("request", handle_request)
        page = await context.new_page()

        def wait_for_user():
            sys.stdout.write("[*] Interactive mode — hit ENTER in terminal when you’re finished\n")
            sys.stdout.flush()
            input()
            stop_event.set()

        threading.Thread(target=wait_for_user, daemon=True).start()

        sys.stdout.write(f"[*] Visiting {target_url}. Interact manually.\n")
        sys.stdout.flush()

        # Load page with timeout handling
        try:
            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=timeout * 1000 if timeout > 0 else 0,
            )
        except Exception as e:
            sys.stdout.write(f"[!] Could not fully load page ({e}), continuing to intercept requests...\n")

        # optional auto-scroll
        if auto_scroll:
            for _ in range(10):
                if stop_event.is_set():
                    break
                await page.evaluate("window.scrollBy(0, document.body.scrollHeight);")
                await asyncio.sleep(1)

        js_apis = await scan_js_files(page)
        for api in js_apis:
            if api not in apis:
                apis.add(api)
                sys.stdout.write(f"{COLORS['OTHER']}[JS-detected] {api}{RESET}\n")
                sys.stdout.flush()

        # Keep alive until user presses ENTER
        while not stop_event.is_set():
            await asyncio.sleep(0.2)

        await browser.close()

    return apis

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Manually browse a site and capture its API endpoints."
    )
    parser.add_argument("--url", required=True, help="Target page URL")
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Page load timeout (seconds). Enter 0 for unlimited.",
    )
    parser.add_argument(
        "--scroll",
        action="store_true",
        help="Auto-scroll the page to trigger lazy-loaded content.",
    )
    parser.add_argument("-o", "--output", help="Output file (.json or .txt)")
    parser.add_argument(
        "-p",
        "--postman",
        help="Postman collection file (.postman.json)",
    )
    args = parser.parse_args()

    endpoints = asyncio.run(
        intercept_apis(
            args.url,
            timeout=args.timeout,
            auto_scroll=args.scroll,
        )
    )
    if endpoints:
        print(f"\n[+] Total API endpoints captured: {len(endpoints)}")
    else:
        print("[!] No API endpoints detected.")

    if args.output:
        save_output(endpoints, args.output)
    if args.postman:
        generate_postman_collection(endpoints, args.postman)

if __name__ == "__main__":
    main()
