#!/usr/bin/env node

const { interceptApis, saveOutput, generatePostmanCollection, BANNER } = require('./grapi/core');
const argv = require('minimist')(process.argv.slice(2));

console.log(BANNER);

(async () => {
    const url = argv.url || argv.u;
    const outFile = argv.o || argv.output || 'apis.txt';
    const postmanFile = argv.p || argv.postman;
    const timeout = argv.t || argv.timeout || 30;
    const autoScroll = argv.scroll || false;

    if (!url) {
        console.error('Usage: node grapi.js --url <target> [-o apis.txt] [-p apis.postman.json]');
        process.exit(1);
    }

    const apis = await interceptApis(url, timeout, autoScroll);

    if (apis && apis.size > 0) {
        if (outFile) saveOutput(apis, outFile);
        if (postmanFile) generatePostmanCollection(apis, postmanFile);
    } else {
        console.log('[-] No API endpoints found.');
    }
})();