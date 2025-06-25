# grAPI — Live API Discovery Tool

**grAPI** is a simple but powerful utility for pentesters and security researchers who need to discover API endpoints on websites by interacting with them in real time. It uses Playwright under the hood to launch a real browser so you can explore the target and see API calls pop up in your terminal as they happen.

---

## What It Does

This tool:

* Opens your target URL in a real browser so you can click around just like a user.
* Captures any API endpoints the page hits via XHR, Fetch or other network calls.
* Scans loaded JavaScript files for hidden or hardcoded API paths.
* Gives you color coded output instantly so you don’t have to wait.
* Lets you save the endpoints in a simple txt or json file.
* Generates a Postman collection for easy import into Postman or Burp.

---

## Why It’s Useful

Unlike traditional scanners that only look at source code, grAPI listens to actual traffic as you use the page. That means it catches dynamic APIs that appear after a click, form submit or other interaction.

And because you do the browsing yourself, you control exactly which parts of the app you want to explore. The output is kept clean and minimal so you can jump straight into testing.

---

## Installation

First, make sure you have Python 3.10 or higher. Clone this repo and install the dependencies:

```bash
git clone https://github.com/DghostNinja/grAPI.git
cd grAPI
pip install -r requirements.txt
playwright install
```

---

## Usage

Here’s a typical example:

```bash
python3 grAPI.py --url https://targetsite.com -o apis.txt -p apis.postman.json
```

This will:

1. Launch the browser and open the target.
2. Print API endpoints as they happen — color coded by HTTP method.
3. Save them into a file (`apis.txt`) and a Postman collection (`apis.postman.json`).

When you’re done exploring the app, hit Enter in your terminal to stop the scan.

---

## Optional Arguments

| Argument        | Description                                        |
| --------------- | -------------------------------------------------- |
| `--url`         | Target page URL.                                   |
| `--timeout`     | Page load timeout in seconds. `0` to wait forever. |
| `-o, --output`  | Save endpoints as a list in txt or json format.    |
| `-p, --postman` | Save as a Postman collection you can import.       |

---

## Notes

* This tool catches any URL containing common API keywords like `api`, `graphql`, `openapi`, `swagger` or `.json`.
* It also parses JavaScript files for hidden paths.
* The browser stays open so you can manually explore.
* Works great for SPAs or other JS-heavy sites.
* If you need more features like capturing request bodies or rate limiting, feel free to fork and enhance.

---

## Example Output

Here’s what you’d see as you browse:

```
[API detected] POST: http://crapi.apisec.ai/identity/api/auth/forget-password
[API detected] GET: http://crapi.apisec.ai/shop/api/products
[JS-detected] /user/profile/update-profile-picture/
```

And when you hit Enter:

```
[+] Total API endpoints captured: 3
[+] Saved 3 endpoints to apis.txt
[+] Saved Postman collection to apis.postman.json
```

---

## Contribute

Feel free to open an issue if you find bugs or have an idea. Pull requests are welcome too.

That’s it. Have fun breaking things and stay curious.

By [iPsalmy](https://github.com/DghostNinja)
