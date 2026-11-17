'use strict';
const { operators } = require('../../encounter-claimipedia/bootstrap/operator.cjs');
const [file, headers] = process.argv.slice(2);
const verify = operators(file);
console.log(JSON.stringify(JSON.parse(headers).map(header => verify(header))));
