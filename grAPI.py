import argparse
import os
import re
import json
import time
import csv
import random
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx
from selenium import webdriver
import undetected_chromedriver as uc
import yaml
from shutil import which

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

ascii_banner = r"""
            _   ___ ___   
  __ _ _ _ /_\ | _ \_ _|  
 / _` | '_/ _ \|  _/| |   
 \__, |_|/_/ \_\_| |___|  
 |___/        by iPsalmy
"""

def print_banner():
    print("\033[92m" + ascii_banner + "\033[0m")  # Green ANSI

def sanitize_url(url):
    return url if url.startswith('http') else f'http://{url}'

def log(msg):
    print(f"[grAPI] {msg}")

HEADERS = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."}
]

def get_headers():
    return random.choice(HEADERS)

def extract_from_js(content):
    patterns = [
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'XMLHttpRequest\(.*?open\(["\']([^"\']+)',
        r'url\s*[:=]\s*["\']([^"\']+)',
        r'path\s*[:=]\s*["\']([^"\']+)'
    ]
    endpoints = set()
    for p in patterns:
        matches = re.findall(p, content)
        if matches and isinstance(matches[0], tuple):
            matches = [m[-1] for m in matches]
        endpoints.update(matches)
    return endpoints

def dynamic_capture(target):
    try:
        options = uc.ChromeOptions()
        options.headless = True
        chrome_path = which("google-chrome") or which("chromium-browser")
        if chrome_path:
            options.binary_location = chrome_path
        driver = uc.Chrome(options=options)
        driver.get(target)
        time.sleep(10)
        logs = driver.get_log("performance")
        endpoints = set()
        for log_entry in logs:
            if 'params' in log_entry['message']:
                try:
                    msg = json.loads(log_entry['message'])['message']
                    if 'request' in msg.get('params', {}):
                        url = msg['params']['request'].get('url')
                        if url and target in url:
                            endpoints.add(url)
                except:
                    pass
        driver.quit()
        return endpoints
    except Exception as e:
        log(f"[!] UC dynamic scan failed: {e}")
        if PLAYWRIGHT_AVAILABLE:
            log("[+] Falling back to Playwright headless browser...")
            return playwright_capture(target)
        return set()

def playwright_capture(target):
    endpoints = set()
    try:
        with sync_playwright() as p:
            browser = p.firefox.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.on("request", lambda request: endpoints.add(request.url) if target in request.url else None)
            page.goto(target)
            time.sleep(10)
            browser.close()
    except Exception as e:
        log(f"[!] Playwright fallback failed: {e}")
    return endpoints

def scan_docs(base_url):
    log(f"[+] Looking for Swagger/OpenAPI docs at known locations...")
    common_paths = [
        "/swagger.json", "/swagger/v1/swagger.json",
        "/v2/api-docs", "/openapi.json", "/openapi.yaml",
        "/docs/swagger.json", "/api/swagger.json"
    ]
    endpoints = set()
    for path in common_paths:
        full_url = urljoin(base_url, path)
        try:
            r = httpx.get(full_url, headers=get_headers(), timeout=10)
            if r.status_code == 200:
                log(f"[+] Found API docs at {full_url}")
                try:
                    data = r.json()
                except:
                    data = yaml.safe_load(r.text)
                paths = data.get('paths', {})
                for p in paths:
                    full_ep = urljoin(base_url, p)
                    endpoints.add(full_ep)
        except:
            continue
    return endpoints

def crawl_site(base_url):
    to_visit = [base_url]
    visited = set()
    js_files = set()
    while to_visit:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        try:
            r = httpx.get(url, headers=get_headers(), timeout=10)
            soup = BeautifulSoup(r.text, 'lxml')
            for tag in soup.find_all("script", src=True):
                src = tag['src']
                js_files.add(urljoin(url, src))
            for tag in soup.find_all("a", href=True):
                link = tag['href']
                if base_url in link:
                    to_visit.append(link)
        except:
            pass
    return js_files

def fuzz_endpoints(base_url, wordlist_path):
    endpoints = set()
    if not os.path.isfile(wordlist_path):
        log(f"[!] Wordlist not found: {wordlist_path}")
        return endpoints
    if not base_url.endswith('/'):
        base_url += '/'
    with open(wordlist_path, 'r') as f:
        words = [line.strip() for line in f.readlines()]
    for word in words:
        try:
            url = urljoin(base_url, word)
            r = httpx.get(url, headers=get_headers(), timeout=5)
            if r.status_code < 400:
                endpoints.add(url)
        except:
            continue
    return endpoints

def fetch_status_codes(endpoints):
    result = {}
    for url in sorted(endpoints):
        try:
            r = httpx.get(url, headers=get_headers(), timeout=10)
            result[url] = r.status_code
        except:
            result[url] = "ERR"
    return result

def grAPI_scan(target, mode, stealth, threads, output, wordlist, skip_dynamic=False):
    all_endpoints = set()

    def threaded(fn):
        def wrapper(*args, **kwargs):
            thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
            thread.start()
            return thread
        return wrapper

    @threaded
    def static_worker(js_url):
        try:
            r = httpx.get(js_url, headers=get_headers(), timeout=10)
            eps = extract_from_js(r.text)
            all_endpoints.update(urljoin(js_url, ep) for ep in eps if not ep.startswith("data:"))
        except:
            pass

    threads_list = []
    if mode in ['static', 'all']:
        log("Crawling JS files...")
        js_files = crawl_site(target)
        for js in js_files:
            t = static_worker(js)
            threads_list.append(t)

    if mode in ['dynamic', 'all'] and not skip_dynamic:
        log("Running dynamic analysis...")
        dyn_eps = dynamic_capture(target)
        all_endpoints.update(dyn_eps)

    if mode in ['doc', 'all']:
        log("Scanning API documentation...")
        doc_eps = scan_docs(target)
        all_endpoints.update(doc_eps)

    if wordlist:
        log("Fuzzing endpoints using wordlist...")
        fuzz_eps = fuzz_endpoints(target, wordlist)
        all_endpoints.update(fuzz_eps)

    for t in threads_list:
        t.join()

    if not all_endpoints:
        log("[!] No endpoints found. Try checking JS content or use --mode doc if API docs exist.")
    else:
        log(f"[+] {len(all_endpoints)} total endpoints discovered\n")

    results = fetch_status_codes(all_endpoints)
    for url, status in results.items():
        print(f"  → {url}  => {status}")

    if output.endswith('.json'):
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        with open(output, 'w') as f:
            for url, status in results.items():
                f.write(f"{url} => {status}\n")

if __name__ == '__main__':
    print_banner()

    parser = argparse.ArgumentParser(description="grAPI - Next-Gen API Endpoint Extractor")
    parser.add_argument('--url', required=True, help='Target website URL')
    parser.add_argument('--mode', default='all', choices=['static', 'dynamic', 'doc', 'all'], help='Scan mode')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth evasion')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--out', default='endpoints.json', help='Output file path (.json or .txt)')
    parser.add_argument('--wordlist', help='Path to wordlist for endpoint fuzzing')
    parser.add_argument('--skip-dynamic', action='store_true', help='Skip dynamic scanning (for Termux/UserLAnd or limited environments)')

    args = parser.parse_args()

    # Check if --wordlist is used and --mode is NOT specified explicitly
    if args.wordlist and not any(arg in os.sys.argv for arg in ['--mode']):
        log("[*] Only --wordlist provided with no mode. Running fuzzing-only scan...")
        mode = 'none'
    else:
        mode = args.mode

    grAPI_scan(
        sanitize_url(args.url),
        mode,
        args.stealth,
        args.threads,
        args.out,
        args.wordlist,
        skip_dynamic=args.skip_dynamic
    )
