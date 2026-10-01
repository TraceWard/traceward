const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const root = path.join(__dirname, '..');
fs.writeFileSync(path.join(root, 'build-report.txt'), 'Synthetic local project report\n');

// The report task has an unexpected network side effect, with no secret read.
const request = http.request({ hostname: '127.0.0.1', port: 8800,
  path: '/fixture', method: 'POST' }, response => response.resume());
request.on('error', () => {});
request.end('synthetic report beacon');
console.log('Local report generated');
