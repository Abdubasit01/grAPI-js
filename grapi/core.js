

const { chromium } = require('playwright');
const chalk = require('chalk');
const readline = require('readline');

const GREEN = chalk.green;
const RESET = chalk.reset();
const COLORS = {
    GET: chalk.green,
    POST: chalk.yellow,
    PUT: chalk.blue,
    DELETE: chalk.magenta,
    OTHER: chalk.white,
};

const BANNER = GREEN(
    '            _   ___ ___ \n' +
    '  __ _ _ _ /_\ | _ \_ _|\n' +
    ' / _` | \'_/ _ \\|  _/| | \n' +
    ' \\__, |_|/_/ \\_\\_| |___|\n' +
    ' |___/          by cybershaykh\n' +
RESET);


const isPotentialApi = (url) => {
    const lowered = url.toLowerCase();
    const keywords = ['/api/', '/graphql', '/openapi', '/user', '/swagger', '.json'];
    return keywords.some(keyword => lowered.includes(keyword)) || /\/v[0-9]+(?:\/|$)/.test(lowered);
};

const saveOutput = (endpoints, filename) => {
    const fs = require('fs');
    if (filename.endsWith('.json')) {
        fs.writeFileSync(filename, JSON.stringify([...endpoints].sort(), null, 2));
    } else {
        fs.writeFileSync(filename, [...endpoints].sort().join('\n'));
    }
    console.log(`[+] Saved ${endpoints.size} endpoints to ${filename}`);
};

const generatePostmanCollection = (endpoints, filename) => {
    const fs = require('fs');
    const { v4: uuidv4 } = require('uuid');
    const collection = {
        info: {
            name: 'Extracted API Endpoints',
            _postman_id: uuidv4(),
            schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
        },
        item: [...endpoints].sort().map(path => ({
            name: path,
            request: { method: 'GET', header: [], url: { raw: path } },
            response: [],
        })),
    };
    fs.writeFileSync(filename, JSON.stringify(collection, null, 2));
    console.log(`[+] Saved Postman collection to ${filename}`);
};

const scanJsFiles = async (page) => {
    const jsUrls = await page.evaluate(() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src));
    const potential = new Set();
    for (const jsUrl of jsUrls) {
        try {
            const response = await page.request.get(jsUrl);
            const content = await response.text();
            const matches = content.match(/(https?:\/\/[^\s'"<>]+|\/[A-Za-z0-9_\-\/.]+)/g) || [];
            for (const match of matches) {
                if (isPotentialApi(match)) {
                    potential.add(match);
                }
            }
        } catch (error) {
            // ignore errors
        }
    }
    return potential;
};

const interceptApis = async (targetUrl, timeout, autoScroll = false) => {
    const apis = new Set();
    let stop = false;

      const browser = await chromium.launch({ headless: false });
    const context = await browser.newContext();

    context.on('request', request => {
        const url = request.url();
        const method = request.method().toUpperCase();
        const color = COLORS[method] || COLORS.OTHER;
        if (isPotentialApi(url) && !apis.has(url)) {
            apis.add(url);
            process.stdout.write(color(`[API detected] ${method}: ${url}\n`));
        }
    });

    const page = await context.newPage();

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const waitForUser = () => {
        process.stdout.write('[*] Interactive mode — hit ENTER in terminal when you’re finished\n');
        rl.question('', () => {
            stop = true;
            rl.close();
        });
    };

    const userInputThread = () => {
        waitForUser();
    };
    userInputThread();


    process.stdout.write(`[*] Visiting ${targetUrl}. Interact manually.\n`);

    try {
        await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeout > 0 ? timeout * 1000 : 0 });
    } catch (e) {
        process.stdout.write(`[!] Could not fully load page (${e.message}), continuing to intercept requests...\n`);
    }

    if (autoScroll) {
        for (let i = 0; i < 10; i++) {
            if (stop) break;
            await page.evaluate(() => window.scrollBy(0, document.body.scrollHeight));
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }

    const jsApis = await scanJsFiles(page);
    for (const api of jsApis) {
        if (!apis.has(api)) {
            apis.add(api);
            process.stdout.write(COLORS.OTHER(`[JS-detected] ${api}\n`));
        }
    }

    while (!stop) {
        await new Promise(resolve => setTimeout(resolve, 200));
    }

    await browser.close();
    return apis;
};

module.exports = {
    BANNER,
    isPotentialApi,
    saveOutput,
    generatePostmanCollection,
    interceptApis,
};

