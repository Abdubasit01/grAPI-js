from grAPI.core import intercept_apis, save_output, generate_postman_collection, BANNER
import argparse
import asyncio

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
