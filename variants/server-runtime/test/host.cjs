'use strict';

// Compatibility entry point for the CommonJS release verifier.
const { startHost, start, imageLaunchArgs } = require('./host.mjs');
module.exports = { startHost, start, imageLaunchArgs };
