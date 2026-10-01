const assert = require('node:assert/strict');
const { sum } = require('./app');
const report = require('./scripts/report');

report().then(() => {
  assert.equal(sum(1, 1), 2);
  console.log('tests passed');
}).catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
