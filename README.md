# grAPI-js — Live API Discovery Tool

**grAPI-js** inspired by [DghostNinja](https://github.com/DghostNinja/grAPI) is a simple but powerful utility tool written in nodejs for pentesters and security researchers who need to discover API endpoints on websites by interacting with them in real time. It uses Playwright under the hood to launch a real browser so you can explore the target and see API calls pop up in your terminal as they happen.

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

Make sure you have **Nodejs v18.0+** installed.

You can install grAPI using npm on the command line:
```bash
# Install grapijs
npm install grapijs

# Install Playwright browser binaries:

playwright install
```
Or from source:

```bash
git clone https://github.com/Abdulbasit01/grAPI-js.git
cd grAPI-js

# Install grapi
npm i

# Install Playwright browser binaries
playwright install
```

- OPTIONAL:
  Add this line to your shell config (~/.bashrc, ~/.zshrc, or ~/.profile depending on your shell):
```bash
export PATH="$HOME/.local/bin:$PATH"
source ~/.bashrc   # or source ~/.zshrc
```

---

## 📦 Required Libraries for playwright browser
- ❌ Incase of OS or Dependency error:

```bash
sudo apt update && sudo apt install -y \
    libicu-dev \
    libjpeg-dev \
    libwebp-dev \
    libffi-dev \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libxss1 \
    libxtst6
```
- Re-run the playwright install command after
---

## Usage

Here’s a typical example:

```bash
node grapi.js --url https://example.com -o apis.txt -p apis.postman.json
```
OR(Recommended):

```bash
node grapi.js --url https://targetsite.com -o apis.txt -p apis.postman.json
```

This will:

1. Launch the browser and open the target.
2. Print API endpoints as they happen — color coded by HTTP method.
3. Save them into a file (`apis.txt`) and a Postman collection (`apis.postman.json`).

When you’re done exploring the app, hit **Enter** in your terminal to stop the scan.

---

## Optional Arguments

| Argument    | Description                                              |
| ----------- | -------------------------------------------------------- |
| `--url`     | Target page URL                                          |
| `--timeout` | Page load timeout in seconds. `0` disables timeout       |
| `--scroll`  | Automatically scrolls the page to trigger more API calls |
| `-o`        | Output filename for saving endpoints (txt or json)       |
| `-p`        | Export captured endpoints as a Postman collection file   |

---

## Example Output

```bash
[API detected] POST: http://crapi.apisec.ai/identity/api/auth/forget-password
[API detected] GET: http://crapi.apisec.ai/shop/api/products
[JS-detected] /user/profile/update-profile-picture/
```

After hitting Enter:

```bash
[+] Total API endpoints captured: 3
[+] Saved 3 endpoints to apis.txt
[+] Saved Postman collection to apis.postman.json
```

---

## License

This project is licensed under the terms of the [MIT License](LICENSE). You are free to use, modify, and distribute it as needed.

---

## Contribute

If you’ve got feature ideas or improvements, feel free to open an issue or send a pull request.

That’s it. Have fun breaking things and stay curious.

Made with ☕ by [Harbsart](https://github.com/Abdubasit01/)
