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

Make sure you have **Python 3.10+** installed.

You can install grAPI using pip from the local folder:

```bash
git clone https://github.com/DghostNinja/grAPI.git
cd grAPI
pip install grAPI
```
Or from source 

```baash
git clone https://github.com/yourusername/grAPI
cd grAPI
pip install .
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

Made with ☕ by [iPsalmy](https://github.com/DghostNinja)
