'use strict';
const { createHash, randomBytes } = require('node:crypto');
const { writeFileSync } = require('node:fs');
const path = require('node:path');

function createOperators(directory) {
  const credentials = {};
  const file = path.join(directory, 'test-operators.rel');
  const rows = ['("operators", "version", "encounter/operators/1")'];
  for (const role of ['proposer', 'reviewer', 'observer', 'worker', 'verifier', 'reconciler', 'curator']) {
    const username = 'fixture-' + role, password = randomBytes(32).toString('hex');
    credentials[role] = { username, password };
    const token = Buffer.from(username + ':' + password).toString('base64');
    const pin = createHash('sha256').update(token).digest('hex');
    rows.push(`("${username}", "role", "${role}")`, `("${username}", "basicSha256", "${pin}")`);
  }
  writeFileSync(file, rows.join('\n') + '\n', { mode: 0o600, flag: 'wx' });
  return { file, credentials };
}
module.exports = { createOperators };
