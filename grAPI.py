#!/usr/bin/env python3
import argparse, requests, re, json, random, time, os
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

FILE_EXTENSIONS = [".json", ".env", ".conf", ".js"]
output_lock = Lock()

def get_headers():
    return random.choice(HEADERS)

def get_proxies(proxy_url):
    return {"http": proxy_url, "https": proxy_url} if proxy_url else {}

def request_url(url, proxy=None):
    try:
        return requests.get(url, headers=get_headers(), proxies=get_proxies(proxy), verify=False, timeout=6)
    except:
        return None

def extract_js_urls(html, base):
    soup = BeautifulSoup(html, "html.parser")
    return [urljoin(base, s["src"]) for s in soup.find_all("script", src=True)]

def extract_file_links(html, base):
    soup = BeautifulSoup(html, "html.parser")
    file_links = []
    for tag in soup.find_all(["a", "script", "link"], href=True):
        href = tag.get("href", "")
        if any(href.endswith(ext) for ext in FILE_EXTENSIONS):
            file_links.append(urljoin(base, href))
    for tag in soup.find_all("script", src=True):
        if any(tag["src"].endswith(ext) for ext in FILE_EXTENSIONS):
            file_links.append(urljoin(base, tag["src"]))
    return list(set(file_links))

def extract_apis(text):
    # Match hardcoded endpoints + string-built patterns
    regex = r'(\/api\/[a-zA-Z0-9\/_\-\?\=\&\.]+)'
    dynamic = re.findall(r'["\']([^"\']*\/api\/[^"\']*)["\']', text)
    return list(set(re.findall(regex, text) + dynamic))

def extract_from_swagger(text):
    try:
        data = json.loads(text)
        if "paths" in data:
            return [p for p in data["paths"].keys() if p.startswith("/api/")]
    except:
        pass
    return []

def passive_recon(base, proxy=None):
    print(f"\n[+] Passive Recon: {base}")
    found = set()
    visited_files = set()

    res = request_url(base, proxy)
    if not res:
        print("[-] Can't reach target.")
        return []

    # HTML
    found.update(extract_apis(res.text))

    # JS & Resource Files
    script_urls = extract_js_urls(res.text, base) + extract_file_links(res.text, base)
    for url in set(script_urls):
        if url in visited_files:
            continue
        visited_files.add(url)
        r = request_url(url, proxy)
        if r and r.status_code == 200:
            if url.endswith("swagger.json"):
                found.update(extract_from_swagger(r.text))
            else:
                found.update(extract_apis(r.text))

    # robots.txt & sitemap.xml
    for path in ["/robots.txt", "/sitemap.xml"]:
        r = request_url(urljoin(base, path), proxy)
        if r and r.status_code == 200:
            found.update(extract_apis(r.text))

    return sorted(set([x.strip() for x in found if x.startswith("/api/")]))

def fuzz_path(base, path, proxy=None, color=None):
    url = urljoin(base, path)
    try:
        r = requests.get(url, headers=get_headers(), proxies=get_proxies(proxy), timeout=5, verify=False)
        length = len(r.content)
        with output_lock:
            prefix = f"\033[{color}m" if color else ""
            suffix = "\033[0m" if color else ""
            print(f"{prefix}[+] GET {path:35} => {r.status_code} ({length}){suffix}")
        return ("GET", path, r.status_code, length)
    except:
        return None

def active_fuzz(base, paths, threads=10, proxy=None):
    print("\n[+] Active Fuzzing")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as exec:
        futures = [exec.submit(fuzz_path, base, p, proxy, "92") for p in paths]
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

    results = []
    with ThreadPoolExecutor(max_workers=threads) as exec:
        futures = [exec.submit(fuzz_path, base, p, proxy, None) for p in paths]
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
    return results

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

    parser = argparse.ArgumentParser(description="grAPI - Next-Gen API Fuzzer")
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
            print(f"\033[94m[+] GET {ep:35} => [?] (passive)\033[0m")
        all_results = [("GET", ep, "?", 0) for ep in endpoints]

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
