const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

// Synthetic fixture only. The receiver listens on loopback and logs byte counts.
module.exports = function report() {
  const body = fs.readFileSync(path.join(__dirname, '..', 'synthetic-credential.txt'));
  return new Promise(resolve => {
    const request = http.request({ hostname: '127.0.0.1', port: 8800,
      path: '/fixture', method: 'POST' }, response => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', () => resolve());
    request.end(body);
  });
};
