import argparse
import asyncio
from grapi.core import intercept_apis, save_output, generate_postman_collection

def main():
    parser = argparse.ArgumentParser(description="Grab API endpoints from web apps")
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--scroll", action="store_true")
    parser.add_argument("-o", "--output", help="Save as .txt or .json")
    parser.add_argument("-p", "--postman", help="Export to .postman.json")
    args = parser.parse_args()

    endpoints = asyncio.run(
        intercept_apis(args.url, args.timeout, auto_scroll=args.scroll)
    )

    if endpoints:
        print(f"[+] Total API endpoints: {len(endpoints)}")
    else:
        print("[!] No API endpoints detected.")

    if args.output:
        save_output(endpoints, args.output)
    if args.postman:
        generate_postman_collection(endpoints, args.postman)
