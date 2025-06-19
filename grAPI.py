#!/usr/bin/env python3
import argparse, requests, re, random, time, json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

ascii_banner = "\033[92m" + r"""
            _   ___ ___   
  __ _ _ _ /_\ | _ \_ _|  
 / _` | '_/ _ \|  _/| |   
 \__, |_|/_/ \_\_| |___|  
 |___/        by iPsalmy
""" + "\033[0m"


HEADERS = [
    {"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
    {"User-Agent": "Chrome/108.0", "Accept": "application/json"},
    {"User-Agent": "Safari/537.36", "Accept": "*/*"},
]

endpoint_tags = {
    "auth": ["auth", "login", "logout", "token"],
    "signup": ["signup", "register", "createaccount"],
    "admin": ["admin", "dashboard", "panel"],
    "debug": ["debug", "test", "dev"],
    "user": ["user", "profile", "account"]
}

output_lock = Lock()
proxy_cfg = {}

def get_headers():
    return random.choice(HEADERS)

def get_proxies(proxy_url):
    return {"http": proxy_url, "https": proxy_url} if proxy_url else {}

def extract_js_urls(html, base):
    soup = BeautifulSoup(html, "html.parser")
    return [urljoin(base, s["src"]) for s in soup.find_all("script", src=True)]

def extract_apis(text):
    return re.findall(r"(\/api\/[a-zA-Z0-9\/_\-\?\=\&\.]*)", text)

def classify(path):
    tags = []
    for label, keys in endpoint_tags.items():
        if any(k in path.lower() for k in keys):
            tags.append(label)
    return tags

def request_url(url, proxy=None):
    try:
        return requests.get(url, headers=get_headers(), proxies=get_proxies(proxy), verify=False, timeout=6)
    except:
        return None

def passive_recon(base, proxy=None):
    print(f"\n[+] Passive Recon: {base}")
    found = set()
    res = request_url(base, proxy)
    if not res:
        print("[-] Can't reach target.")
        return []

    found.update(extract_apis(res.text))
    for js_url in extract_js_urls(res.text, base):
        r = request_url(js_url, proxy)
        if r and r.status_code == 200:
            found.update(extract_apis(r.text))

    for path in ["/robots.txt", "/sitemap.xml"]:
        r = request_url(urljoin(base, path), proxy)
        if r and r.status_code == 200:
            found.update(extract_apis(r.text))

    return list(set(found))

def fuzz_path(base, path, proxy=None):
    url = urljoin(base, path)
    try:
        r = requests.get(url, headers=get_headers(), proxies=get_proxies(proxy), timeout=5, verify=False)
        tags = classify(path)
        length = len(r.content)
        with output_lock:
            print(f"[+] GET {path:35} => {r.status_code} ({length}) {tags}")
        return ("GET", path, r.status_code, length, tags)
    except:
        return None

def active_fuzz(base, paths, threads=10, proxy=None):
    print("\n[+] Active Fuzzing")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as exec:
        futures = [exec.submit(fuzz_path, base, p, proxy) for p in paths]
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
    return results

def bruteforce(base, wordlist, threads=10, proxy=None):
    print("\n[+] Brute-forcing Wordlist...")
    try:
        with open(wordlist) as f:
            paths = ["/" + l.strip().lstrip("/") for l in f if l.strip()]
    except:
        print("[-] Wordlist error.")
        return []
    return active_fuzz(base, paths, threads, proxy)

def export_clean(results, output_file):
    raw_paths = sorted({r[1] for r in results})
    if output_file.endswith(".txt"):
        with open(output_file, "w") as f:
            f.write("\n".join(raw_paths))
    elif output_file.endswith(".json"):
        with open(output_file, "w") as f:
            json.dump({"endpoints": raw_paths}, f, indent=2)
    print(f"[+] Saved clean output to: {output_file}")

def main():
    print(ascii_banner)

    parser = argparse.ArgumentParser(description="grAPI - API Fuzzer & Classifier")
    parser.add_argument("target", help="Target base URL")
    parser.add_argument("-p", "--passive", action="store_true", help="Passive only")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable active fuzzing")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for brute force")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default 10)")
    parser.add_argument("-x", "--proxy", help="Proxy like http://127.0.0.1:8080")
    parser.add_argument("-o", "--output", help="Export clean endpoints (.txt or .json)")
    args = parser.parse_args()

    base = args.target if args.target.endswith("/") else args.target + "/"
    proxy = args.proxy

    endpoints = passive_recon(base, proxy)

    all_results = []

    if args.passive:
        for ep in endpoints:
            tags = classify(ep)
            print(f"[+] GET {ep:35} => [?] (passive) {tags}")
        all_results = [("GET", ep, "?", 0, classify(ep)) for ep in endpoints]

    if args.aggressive:
        results = active_fuzz(base, endpoints, args.threads, proxy)
        all_results.extend(results)

    if args.wordlist:
        results = bruteforce(base, args.wordlist, args.threads, proxy)
        all_results.extend(results)

    if args.output:
        export_clean(all_results, args.output)

if __name__ == "__main__":
    main()
