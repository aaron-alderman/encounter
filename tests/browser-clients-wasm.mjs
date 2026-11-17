import assert from 'node:assert/strict';
import {execFileSync, spawn, spawnSync} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {once} from 'node:events';
import {cp, mkdir, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {createServer, get} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {chromium} from '../../../bin/browser-profile.mjs';
import {requireWasmScriptPolicy as requireCompilationPolicy} from '../../applications/appdev-projects/verification/assurance/wasm-csp.mjs';

const encounter = resolve(process.argv[2]);
const cspPreflight = process.argv.includes('--csp-preflight');
const previousOption = process.argv.indexOf('--previous-runtime', 3);
const previousPath = previousOption === -1 ? encounter : process.argv[previousOption + 1];
assert(previousPath && !previousPath.startsWith('--'), 'Expected an Encounter executable after --previous-runtime');
const previousRuntime = resolve(previousPath);
const packageOption = process.argv.indexOf('--package', 3);
const packagePath = packageOption === -1 ? null : process.argv[packageOption + 1];
assert(packageOption === -1 || (packagePath && !packagePath.startsWith('--')), 'Expected a directory after --package');
const previousPackageOption = process.argv.indexOf('--previous-package', 3);
const previousPackage = previousPackageOption === -1 ? null : process.argv[previousPackageOption + 1];
assert(previousPackageOption === -1 || (previousPackage && !previousPackage.startsWith('--')),
  'Expected a directory after --previous-package');
assert(!previousPackage || previousOption !== -1, '--previous-package requires --previous-runtime');
const enforceCsp = cspPreflight || process.env.ENCOUNTER_ENFORCE_BROWSER_CSP === '1';

async function checkPackagedRuntime(directory, runtime, expectedReceipt) {
  if (!directory) return;
  const root = resolve(directory);
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  const receiptPath = join(root, 'package-receipt.rel');
  const receipt = digest(await readFile(receiptPath));
  if (expectedReceipt !== undefined) {
    assert.equal(receipt, expectedReceipt, 'Package receipt changed at ' + root);
  }
  const packaged = await readFile(join(root, 'encounter'));
  const selected = await readFile(runtime);
  assert.equal(digest(selected), digest(packaged), 'Selected runtime differs from ' + join(root, 'encounter'));
  execFileSync(runtime, ['check-package', root], {timeout: 15000});
  assert.equal(digest(await readFile(receiptPath)), receipt, 'Package receipt changed during verification at ' + root);
  return receipt;
}

const candidateReceipt = await checkPackagedRuntime(packagePath, encounter);
const previousReceipt = await checkPackagedRuntime(previousPackage, previousRuntime);
if (candidateReceipt && previousReceipt) {
  assert.notEqual(candidateReceipt, previousReceipt, 'Standalone rollback requires a distinct retained package');
}
const stage = await mkdtemp(join(tmpdir(), 'encounter-clients-wasm-'));
const app = join(stage, 'app');
const entries = ['app.newSession', 'app.request', 'ui.styles', 'app.events', 'app.agentNext', 'app.agentResult', 'app.canvas'];
const pageMarkup = (sequence, stream = '/encounter-events', token = 'original') => '<!doctype html><html lang="en"><head><title>Live fixture</title>' +
  '<script src="/encounter-events.js" defer></script></head><body><main>' +
  '<h1>Sequence ' + sequence + '</h1>' +
  '<div data-encounter-events="' + stream + '" data-rendered="' + sequence + '"></div><p data-encounter-connection></p>' +
  '<form><input type="hidden" name="_csrf" value="' + token + '"><label>Draft <textarea data-encounter-draft></textarea></label></form>' +
  '<p data-encounter-pending></p><button data-encounter-apply hidden>Show update</button>' +
  '<label data-encounter-retained hidden>Retained draft <textarea data-encounter-retained-text></textarea></label>' +
  '</main></body></html>';
const canvasMarkup = '<!doctype html><html lang="en"><head><title>Canvas fixture</title>' +
  '<script src="/encounter-canvas.js" defer></script></head><body><main data-canvas-stage>' +
  '<canvas data-canvas-start="10" data-canvas-seconds="0.5"></canvas>' +
  '<i data-canvas-effect="still" data-canvas-from="10" data-canvas-to="10.5"></i>' +
  '<button data-canvas-play>Play shot</button><input type="range" step="0.01" max="0.5" data-canvas-scrub>' +
  '<audio data-canvas-audio></audio><input type="checkbox" data-canvas-sound><output data-canvas-time></output>' +
  '<p data-canvas-status></p><form id="canvas-settings"><input type="hidden" data-encounter-draft>' +
  Object.entries({motion:100, warmth:0, zoom:100, pan:0, light:100}).map(([key, value]) =>
    '<label><span>' + key + '</span><input type="number" data-canvas-setting="' + key + '" data-canvas-default="' + value + '" data-canvas-saved="' + value +
    '" data-canvas-unit="" value="' + value + '"></label><output data-canvas-value="' + key + '"></output>').join('') +
  '<button type="button" data-canvas-reset>Reset preview</button></form></main></body></html>';

async function observeWasm(page, names, optional = []) {
  await page.addInitScript(({names, optional}) => {
    const calls = window.wasmCalls = Object.fromEntries([...names, ...optional].map(name => [name, 0]));
    if (!window.WebAssembly) return;
    WebAssembly.Instance = new Proxy(WebAssembly.Instance, {
      construct(Instance, args) {
        const instance = new Instance(...args);
        const exports = instance.exports;
        if (names.every(name => typeof exports[name] === 'function')) {
          const observed = [...names, ...optional.filter(name => typeof exports[name] === 'function')];
          Object.defineProperty(instance, 'exports', {value: {...exports, ...Object.fromEntries(observed.map(name => [name, (...input) => {
            calls[name]++;
            return exports[name](...input);
          }]))}});
        }
        return instance;
      },
    });
  }, {names, optional});
}


function gatewayResponse(gatewayOrigin, url, cookie) {
  return new Promise((resolve, reject) => {
    get(gatewayOrigin + url.pathname + url.search, {
      headers: {Host: url.host, ...(cookie && {Cookie: cookie})}, signal: AbortSignal.timeout(5000),
    }, response => {
      response.setEncoding('utf8');
      let body = '';
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({status: response.statusCode, headers: response.headers, body}));
      response.on('error', reject);
    }).on('error', reject);
  });
}

function verifyCompilationPolicyCheck() {
  const grant = "script-src 'self' 'wasm-unsafe-eval'";
  requireCompilationPolicy(grant + ", frame-ancestors 'none'", 'Fixture');
  requireCompilationPolicy(grant + ", default-src 'self' 'wasm-unsafe-eval'", 'Fixture');
  requireCompilationPolicy(grant.toUpperCase(), 'Fixture');
  assert.throws(() => requireCompilationPolicy(null, 'Fixture'), /does not grant/);
  assert.throws(() => requireCompilationPolicy(grant + ", default-src 'none'", 'Fixture'), /does not grant/);
  assert.throws(() => requireCompilationPolicy("script-src 'self'; " + grant, 'Fixture'), /does not grant/);
  assert.throws(() => requireCompilationPolicy("default-src 'none'; script-src-elem 'wasm-unsafe-eval'", 'Fixture'),
    /does not grant/);
  assert.throws(() => requireCompilationPolicy(grant + " 'unsafe-eval'", 'Fixture'), /grants JavaScript evaluation/);
  assert.throws(() => requireCompilationPolicy(grant + ", " + grant + " 'UNSAFE-EVAL'", 'Fixture'),
    /grants JavaScript evaluation/);
  assert.throws(() => requireCompilationPolicy(grant + "; default-src 'unsafe-eval'", 'Fixture'),
    /grants JavaScript evaluation/);
}

async function copyClientBundle(sources, name, directory, fromPackage = packagePath) {
  if (fromPackage === null) {
    return execFileSync(encounter, ['build', '--browser', sources.pathname, name + '.rel', sources.pathname, directory],
      {encoding: 'utf8', timeout: 15000}).trim();
  }
  const root = resolve(fromPackage);
  const rows = text => text.trim().split('\n').map(line => JSON.parse('[' + line.slice(1, -1) + ']'));
  const pin = (facts, subject, key) => {
    const values = facts.filter(([name, property]) => name === subject && property === key);
    assert.equal(values.length, 1, subject + '.' + key);
    assert.match(values[0][2], /^[a-f0-9]{64}$/);
    return values[0][2];
  };
  const catalog = await readFile(join(root, 'standalone-browser-wasm.rel'), 'utf8');
  const receipt = rows(await readFile(join(root, 'package-receipt.rel'), 'utf8'));
  assert.equal(createHash('sha256').update(catalog).digest('hex'), pin(receipt, 'artifact', 'standalone-browser-wasm.rel'));
  await cp(join(root, 'standalone-browser-wasm', name), directory, {recursive: true, force: false, errorOnExist: true});
  return pin(rows(catalog), name, 'receiptSha256');
}

async function verifyPreviewCsp(origin, browser, sources) {
  const prefix = '/pilot';
  const previewPath = prefix + '/step-7/sick-leave';
  const provider = createServer((request, response) => {
    if (request.url === '/me') {
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({kind:'user', identity:{id:'fixture', email:'fixture@example.test',
        issuer:'https://accounts.google.com'}}));
      return;
    }
    const comments = request.url === '/preview-comments/';
    const body = comments
      ? '<section class="nr-preview-comments"><label>Context <select aria-label="Context"><option value="">Screen</option></select></label><ol aria-label="Preview comments"></ol></section>'
      : '<!doctype html><script src="/preview-context.js" defer></script><button id="pilot-context-picker" hidden>Pick on preview</button>' +
        '<p id="pilot-context-status"></p><div class="pilot-preview-surface"><div class="pilot-app-scope"></div><main>Preview</main></div>' +
        '<aside class="pilot-preview-comments"><iframe title="Comments" src="/preview-comments/"></iframe></aside>';
    response.setHeader('Content-Type', 'text/html');
    response.setHeader('Content-Length', Buffer.byteLength(body));
    response.setHeader('Content-Security-Policy', comments ? "default-src 'none'; frame-ancestors 'self'" : "default-src 'none'");
    response.end(body);
  });
  provider.listen(0, '127.0.0.1');
  await once(provider, 'listening');
  try {
    const gatewayRoot = join(stage, 'preview-csp-policy');
    await mkdir(gatewayRoot);
    await writeFile(join(gatewayRoot, 'gateway.rel'), [
      '("application", "stateProfile", "encounter/preview-csp-test/1")',
      '("application", "module", "gateway.encounter")',
      ...['gateway.route', 'gateway.page', 'gateway.styles'].map(entry => '("application", "entry", "' + entry + '")'),
    ].join('\n'));
    await writeFile(join(gatewayRoot, 'gateway.encounter'), [
      'process-module "temple/surface-process-module/1"',
      'process gateway.route:',
      '  let path = $eventInput.path',
      '  let script = eq($path, "/preview-context.js")',
      '  let page = eq($path, "/step-7/sick-leave")',
      '  let allowed = and(eq($eventInput.method, "GET"), not($eventInput.upgrade), if($script, true, if($page, true, eq($path, "/preview-comments/"))))',
      '  let result = { status = if($allowed, 200, 404); path = $path; previewContextScript = $script; previewCommentFrame = $page }',
      'process gateway.page:', '  let result = $eventInput.html',
      'process gateway.styles:', '  let result = ""',
    ].join('\n'));
    const preview = join(stage, 'preview-csp');
    const pin = await copyClientBundle(sources, 'preview', preview);
    const port = String(provider.address().port);
    const config = join(stage, 'preview-csp-gateway.rel');
    const rows = [
      ['gateway', 'version', 'encounter/gateway/1'], ['gateway', 'port', '0'], ['gateway', 'prefix', prefix],
      ['gateway', 'broker', 'https://broker.example.test'], ['gateway', 'owner', 'fixture@example.test'],
      ['gateway', 'identityPort', port], ['gateway', 'identityPath', '/me'], ['gateway', 'root', gatewayRoot],
      ['gateway', 'declaration', 'gateway.rel'], ['gateway', 'target', 'preview'],
      ['preview', 'origin', origin], ['preview', 'port', port], ['preview', 'authorization', 'Basic Zml4dHVyZQ=='],
      ['preview-client', 'directory', preview], ['preview-client', 'receiptSha256', pin],
    ];
    await writeFile(config, rows.map(row => '(' + row.map(value => JSON.stringify(value)).join(', ') + ')').join('\n'), {mode:0o600});
    gateway = spawn(encounter, ['gateway', config], {stdio:['ignore', 'pipe', 'inherit']});
    const [line] = await once(createInterface({input:gateway.stdout}), 'line', {signal:AbortSignal.timeout(8000)});
    const gatewayOrigin = line.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    assert(gatewayOrigin, line);
    const target = new URL(previewPath, origin);
    const start = await gatewayResponse(gatewayOrigin, target);
    assert.equal(start.status, 303);
    const broker = await gatewayResponse(gatewayOrigin, new URL(start.headers.location),
      '__Host-sourcery_session=src_session_' + 'A'.repeat(43));
    assert.equal(broker.status, 303);
    const state = start.headers['set-cookie'][0].split(';',1)[0];
    const finish = await gatewayResponse(gatewayOrigin, new URL(broker.headers.location), state);
    assert.equal(finish.status, 303);
    const session = finish.headers['set-cookie'][0].split(';',1)[0];
    const page = await browser.newPage();
    try {
      let scriptResponse;
      page.on('response', response => {
        if (new URL(response.url()).pathname === prefix + '/preview-context.js') scriptResponse = response;
      });
      await page.route(url => url.origin === origin && url.pathname.startsWith(prefix + '/'), async route => {
        const result = await gatewayResponse(gatewayOrigin, new URL(route.request().url()), session);
        const headers = {'content-type':result.headers['content-type']};
        for (const name of ['content-security-policy', 'x-encounter-browser-wasm']) {
          if (result.headers[name]) headers[name] = result.headers[name];
        }
        await route.fulfill({status:result.status, headers, body:result.body});
      });
      const document = await page.goto(target.href);
      assert.equal(document.status(), 200);
      const policy = await document.headerValue('content-security-policy');
      requireCompilationPolicy(policy, 'Preview');
      await page.getByRole('button', {name:'Pick on preview', exact:true}).waitFor();
      assert.equal(scriptResponse?.status(), 200);
      assert.equal(await scriptResponse.headerValue('x-encounter-browser-wasm'), pin);
      const comments = await gatewayResponse(gatewayOrigin, new URL(prefix + '/preview-comments/', origin), session);
      assert.equal(comments.status, 200);
      return {document: policy, comments: comments.headers['content-security-policy']};
    } finally {
      await page.context().close();
    }
  } finally {
    provider.close();
    await once(provider, 'close');
  }
}

async function verifyEnforcedCsp(origin, browser, sources, httpCredentials) {
  const errors = [];
  const policies = new Map();
  for (const [path, label, ready] of [
    ['/', 'Live Events', page => page.getByText('Live updates connected', {exact:true}).waitFor()],
    ['/canvas', 'Canvas', async page => {
      await page.getByRole('button', {name:'Play shot', exact:true}).click();
      await page.getByRole('button', {name:'Replay shot', exact:true}).waitFor();
    }],
  ]) {
    const page = await browser.newPage({httpCredentials});
    page.setDefaultTimeout(8000);
    try {
      const document = await page.goto(origin + path);
      assert.equal(document.status(), 200);
      const policy = await document.headerValue('content-security-policy');
      requireCompilationPolicy(policy, label);
      await ready(page);
      policies.set(path, policy);
      console.log('PASS: ' + label + ' started with CSP enforced');
    } catch (error) {
      errors.push(error.message);
    } finally {
      await page.context().close();
    }
  }
  try {
    policies.set('preview', await verifyPreviewCsp(origin, browser, sources));
    console.log('PASS: Preview started with CSP enforced');
  } catch (error) {
    errors.push(error.message);
  }
  assert.deepEqual(errors, [], 'The pinned clients did not qualify with CSP enforced');
  return policies;
}

function fulfillHtml(route, body, policy) {
  const headers = policy ? {'content-security-policy': policy} : {};
  return route.fulfill({contentType: 'text/html; charset=utf-8', headers, body});
}

async function verifyQueuedLiveUpdate(browser, origin, httpCredentials, reuseReply, routeChanges = false) {
  const page = await browser.newPage({bypassCSP: !enforceCsp, httpCredentials});
  const document = origin + '/';
  const release = Promise.withResolvers();
  let channel;
  let refreshes = 0;
  let newRouteRefreshes = 0;
  try {
    await observeWasm(page, ['finishQueued']);
    await page.routeWebSocket('**/encounter-events?*', route => { channel = route; });
    await page.route(document, async route => {
      if (route.request().isNavigationRequest()) return route.continue();
      const attempt = ++refreshes;
      await release.promise;
      const stream = attempt === 1 && !reuseReply ? '/unrelated-stream' : '/encounter-events';
      return route.fulfill({contentType: 'text/html', body: pageMarkup(1, stream)});
    });
    if (routeChanges) await page.route(document + '?other=1', route => {
      newRouteRefreshes++;
      return route.fulfill({contentType: 'text/html', body: pageMarkup(1)});
    });
    await page.goto(document);
    await page.getByText('Live updates connected', {exact: true}).waitFor();
    const draft = page.getByRole('textbox', {name: 'Draft', exact: true});
    const apply = page.getByRole('button', {name: 'Show update'});
    await draft.fill('Initial draft');
    channel.send(JSON.stringify({sequence: 1}));
    await apply.waitFor({state: 'visible'});
    const requested = page.waitForRequest(request => request.url() === document && !request.isNavigationRequest());
    await draft.fill('');
    await draft.blur();
    await requested;
    await draft.fill('Draft edited while the refresh was in flight');
    await apply.click();
    if (routeChanges) {
      const finished = await page.evaluate(() => {
        history.replaceState(null, '', '/?other=1');
        return window.wasmCalls.finishQueued;
      });
      release.resolve();
      await page.waitForFunction(before => window.wasmCalls.finishQueued > before, finished);
      assert.equal(await page.getByRole('heading', {name: 'Sequence 0'}).count(), 1);
      assert.equal(await draft.inputValue(), 'Draft edited while the refresh was in flight');
      assert.equal(newRouteRefreshes, 0);
      assert.equal(refreshes, 1);
      return;
    }
    release.resolve();
    await page.getByRole('heading', {name: 'Sequence 1'}).waitFor();
    assert.equal(await page.getByRole('textbox', {name: 'Retained draft'}).inputValue(),
      'Draft edited while the refresh was in flight');
    assert.equal(refreshes, reuseReply ? 1 : 2);
    assert((await page.evaluate(() => window.wasmCalls.finishQueued)) > 0);
  } finally {
    release.resolve();
    await page.context().close();
  }
}

async function verifyLiveCanvasRollback(browser, origin, previousOrigin, clients, policy, previousClients = []) {
  const page = await browser.newPage({bypassCSP: !enforceCsp});
  const document = origin + '/canvas?rollback=1';
  const markup = canvasMarkup.replace('<script src="/encounter-canvas.js"',
    '<script src="/encounter-events.js" defer></script><script src="/encounter-canvas.js"')
    .replace('<main data-canvas-stage>', '<main data-canvas-stage>' +
      '<div data-encounter-events="/encounter-events" data-rendered="7"></div><p data-encounter-connection></p>');
  let upstream = origin;
  let channel;
  const candidateScripts = new Map();
  try {
    await page.route(document, route => fulfillHtml(route, markup, policy));
    await page.route(url => url.origin === origin && clients.some(client => client.path === url.pathname), async route => {
      const path = new URL(route.request().url()).pathname;
      await route.fulfill({response: await route.fetch({url: upstream + path})});
    });
    await page.routeWebSocket('**/encounter-events?*', route => { channel = route; });
    await page.addInitScript(() => {
      if (sessionStorage.getItem('encounter-client-rollback') === '1') window.WebAssembly = undefined;
    });
    const cursorKey = 'encounter-events:/encounter-events';
    for (const phase of ['seed', 'rollback', 'restore']) {
      const rollback = phase === 'rollback';
      upstream = rollback ? previousOrigin : origin;
      if (phase !== 'seed') {
        await page.evaluate(rollback => {
          if (rollback) sessionStorage.setItem('encounter-client-rollback', '1');
          else sessionStorage.removeItem('encounter-client-rollback');
        }, rollback && !previousClients.length);
      }
      channel = undefined;
      const [scripts] = await Promise.all([
        Promise.all(clients.map(client => page.waitForResponse(response =>
          response.url() === origin + client.path && response.request().resourceType() === 'script'))),
        page.goto(document),
      ]);
      for (const [index, response] of scripts.entries()) {
        const client = clients[index];
        const expected = rollback ? previousClients[index] : client;
        assert.equal(response.status(), 200, client.path);
        assert.equal(await response.headerValue('x-encounter-browser-wasm'), expected?.pin ?? null);
        if (expected) {
          const body = await response.body();
          const script = body.toString('utf8');
          assert(script.includes(`const ${client.binding} = '${expected.module.toString('base64')}';`));
          assert(!script.includes('encounterLegacy'), client.path);
          const digest = createHash('sha256').update(body).digest('hex');
          if (phase === 'seed') candidateScripts.set(client.path, digest);
          if (rollback) {
            assert.equal(digest, expected.scriptDigest, 'Rollback script differs from retained host: ' + client.path);
          }
          if (phase === 'restore') {
            assert.equal(digest, candidateScripts.get(client.path), 'Restored script differs from seed: ' + client.path);
          }
        }
      }
      await page.getByText('Live updates connected', {exact: true}).waitFor();
      assert(channel, 'Expected a Live Events socket during ' + phase);
      assert.equal(new URL(channel.url()).searchParams.get('after'), phase === 'seed' ? '0' : '7');
      assert.equal(await page.evaluate(() => Boolean(window.WebAssembly)), !rollback || previousClients.length > 0);
      await page.getByRole('button', {name: 'Play shot', exact: true}).click();
      await page.getByRole('button', {name: 'Replay shot', exact: true}).waitFor();
      assert.equal(await page.locator('[data-canvas-scrub]').inputValue(), '0.5');
      if (phase === 'seed') {
        channel.send(JSON.stringify({sequence: 7}));
        await page.waitForFunction(key => sessionStorage.getItem(key) === '7', cursorKey);
      }
      assert.equal(page.url(), document);
    }
    const target = previousClients.length ? 'the retained Wasm package' : 'the unpinned runtime';
    console.log('PASS: Live Events retained its cursor and Canvas played through rollback to ' + target + ' and restore at the same URL');
  } finally {
    await page.context().close();
  }
}

let host;
let legacyHost;
let previousHost;
let gateway;
let browser;
async function exerciseClients() {
  await mkdir(app);
  await writeFile(join(app, 'application.rel'), [
    '("application", "stateProfile", "encounter/live-wasm-test/1")',
    '("application", "module", "app.encounter")',
    ...entries.map(entry => '("application", "entry", ' + JSON.stringify(entry) + ')'),
  ].join('\n'));
  await writeFile(join(app, 'app.encounter'), [
    'process-module "temple/surface-process-module/1"',
    'process app.newSession:', '  let result = {}',
    'process app.request:',
    '  let html = if(eq($eventInput.path, "/canvas"), ' + JSON.stringify(canvasMarkup) + ', ' + JSON.stringify(pageMarkup(0)) + ')',
    '  let result = { html = $html; session = $eventInput.session }',
    'process ui.styles:', '  let result = ""',
    'process app.events:', '  let result = list()',
    'process app.agentNext:', '  let result = null',
    'process app.agentResult:', '  let result = null',
    'process app.canvas:', '  let result = null',
  ].join('\n'));
  const image = join(stage, 'app.rel');
  const pin = execFileSync(encounter, ['build', app, 'application.rel', image], {encoding: 'utf8'}).trim();
  const username = 'fixture';
  const password = randomBytes(24).toString('hex');
  const basic = Buffer.from(username + ':' + password).toString('base64');
  const operator = createHash('sha256').update(basic).digest('hex');
  await writeFile(join(stage, 'operators.rel'), [
    '("operators", "version", "encounter/operators/1")',
    '("fixture", "basicSha256", "' + operator + '")',
    '("fixture", "role", "operator")',
  ].join('\n'), {mode: 0o600});
  const launch = join(stage, 'launch.rel');
  const launchRows = Object.entries({
    version: 'encounter/launch/1', mode: 'image', port: '0', image: 'app.rel', sha256: pin,
    store: 'store', operators: 'operators.rel', liveModel: 'ollama-loopback',
  }).map(([name, value]) => ['launch', name, value]);
  const sources = new URL('../browser/', import.meta.url);
  const clients = [
    {name: 'live-events', path: '/encounter-events.js', binding: 'encounterLiveEventsWasm', fallback: 'encounterLegacyLiveEvents'},
    {name: 'canvas', path: '/encounter-canvas.js', binding: 'encounterCanvasWasm', fallback: 'encounterLegacyCanvasControls'},
  ];
  for (const client of clients) {
    client.directory = join(stage, client.name);
    client.pin = await copyClientBundle(sources, client.name, client.directory);
    client.module = await readFile(join(client.directory, 'browser.wasm'));
    launchRows.push([client.name, 'directory', client.name], [client.name, 'receiptSha256', client.pin]);
  }
  const launchText = launchRows.map(row => '(' + row.map(value => JSON.stringify(value)).join(', ') + ')').join('\n');
  await writeFile(launch, launchText);
  const refusesLaunch = message => {
    const result = spawnSync(encounter, ['--config', launch, 'serve'], {encoding: 'utf8', timeout: 5000});
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, message);
  };
  for (const {name} of clients) {
    await writeFile(launch, launchText.split('\n').filter(line => !line.startsWith('("' + name + '",')).join('\n'));
    refusesLaunch(/a pinned Canvas application requires both Live Events and Canvas Wasm/);
  }
  const eventsOnlyDeclaration = (await readFile(join(app, 'application.rel'), 'utf8')).split('\n')
    .filter(line => line !== '("application", "entry", "app.canvas")').join('\n');
  await writeFile(join(app, 'events-only.rel'), eventsOnlyDeclaration);
  const eventsOnlyImage = join(stage, 'events-only.rel');
  const eventsOnlyPin = execFileSync(encounter, ['build', app, 'events-only.rel', eventsOnlyImage],
    {encoding: 'utf8'}).trim();
  const eventsOnlyLaunch = join(stage, 'events-only-launch.rel');
  await writeFile(eventsOnlyLaunch, launchText.split('\n').filter(line => !line.startsWith('("canvas",'))
    .join('\n').replace('"app.rel"', '"events-only.rel"').replace(pin, eventsOnlyPin)
    .replace('"store", "store"', '"store", "events-only-store"'));
  const eventsOnly = spawn(encounter, ['--config', eventsOnlyLaunch, 'serve'], {stdio: ['ignore', 'pipe', 'inherit']});
  try {
    const [line] = await once(createInterface({input: eventsOnly.stdout}), 'line', {signal: AbortSignal.timeout(8000)});
    const eventsOnlyOrigin = line.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    assert(eventsOnlyOrigin, line);
    const response = await fetch(eventsOnlyOrigin + '/encounter-events.js');
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-encounter-browser-wasm'), clients[0].pin);
    assert(!(await response.text()).includes(clients[0].fallback));
    const canvasResponse = await fetch(eventsOnlyOrigin + '/encounter-canvas.js');
    assert.equal(canvasResponse.headers.get('x-encounter-browser-wasm'), null);
    assert(!(await canvasResponse.text()).includes('encounterCanvasWasm'));
  } finally {
    if (eventsOnly.exitCode === null && eventsOnly.signalCode === null) {
      const exited = once(eventsOnly, 'exit');
      eventsOnly.kill('SIGTERM');
      await exited;
    }
  }
  console.log('PASS: Canvas requires both Wasm pins and a Live Events-only app can pin its sole client');
  await writeFile(launch, launchText.replace(clients[0].pin, '0'.repeat(64)));
  refusesLaunch(/browser Wasm receipt hash differs/);
  await writeFile(launch, launchText);
  const canvasMap = join(clients[1].directory, 'browser.wasm.map.rel');
  const originalMap = await readFile(canvasMap);
  await writeFile(canvasMap, Buffer.concat([originalMap, Buffer.from('changed')]));
  refusesLaunch(/browser Wasm source map differs/);
  await writeFile(canvasMap, originalMap);
  const eventClient = clients[0];
  const eventModule = join(eventClient.directory, 'browser.wasm');
  const eventMap = join(eventClient.directory, 'browser.wasm.map.rel');
  const eventReceipt = join(eventClient.directory, 'build-receipt.rel');
  const originalEventMap = await readFile(eventMap);
  const originalEventReceipt = await readFile(eventReceipt, 'utf8');
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const changedModule = Buffer.concat([eventClient.module, Buffer.from([0, 2, 1, 120])]);
  assert(WebAssembly.validate(changedModule));
  for (const [path, original, altered, message] of [
    [eventModule, eventClient.module, changedModule, /browser Wasm module differs from the Encounter build/],
    [eventMap, originalEventMap, Buffer.concat([originalEventMap, Buffer.from('\n')]),
      /browser Wasm source map differs from the Encounter build/],
  ]) {
    const receipt = originalEventReceipt.replace(hash(original), hash(altered));
    assert.notEqual(receipt, originalEventReceipt);
    await writeFile(path, altered);
    await writeFile(eventReceipt, receipt);
    await writeFile(launch, launchText.replace(eventClient.pin, hash(receipt)));
    refusesLaunch(message);
    await writeFile(path, original);
    await writeFile(eventReceipt, originalEventReceipt);
  }
  await writeFile(launch, launchText);
  host = spawn(encounter, ['--config', launch, 'serve'], {stdio: ['ignore', 'pipe', 'inherit']});
  const stdout = createInterface({input: host.stdout});
  const [line] = await once(stdout, 'line', {signal: AbortSignal.timeout(8000)});
  const origin = line.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  assert(origin, line);
  await writeFile(join(clients[0].directory, 'browser.wasm'), 'changed after startup');
  for (const {path, pin, binding, module, fallback} of clients) {
    const response = await fetch(origin + path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-encounter-browser-wasm'), pin);
    const script = await response.text();
    assert(script.includes(`const ${binding} = '${module.toString('base64')}';`));
    assert(!script.includes(fallback));
  }
  browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  const policies = enforceCsp
    ? await verifyEnforcedCsp(origin, browser, sources, {username, password})
    : new Map();
  if (cspPreflight) return;

  const legacyLaunch = join(stage, 'legacy-launch.rel');
  const overrides = {store: 'legacy-store'};
  if (previousRuntime !== encounter) {
    overrides.image = 'previous-app.rel';
    overrides.sha256 = execFileSync(previousRuntime, ['build', app, 'application.rel', join(stage, overrides.image)],
      {encoding: 'utf8', timeout: 15000}).trim();
  }
  const legacyRows = launchRows.filter(([subject]) => subject === 'launch')
    .map(([subject, field, value]) => [subject, field, overrides[field] ?? value]);
  await writeFile(legacyLaunch, legacyRows.map(row => '(' + row.map(value => JSON.stringify(value)).join(', ') + ')').join('\n'));
  legacyHost = spawn(previousRuntime, ['--config', legacyLaunch, 'serve'], {stdio: ['ignore', 'pipe', 'inherit']});
  const [legacyLine] = await once(createInterface({input: legacyHost.stdout}), 'line', {signal: AbortSignal.timeout(8000)});
  const legacyOrigin = legacyLine.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  assert(legacyOrigin, legacyLine);
  for (const {path, fallback} of clients) {
    const response = await fetch(legacyOrigin + path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-encounter-browser-wasm'), null);
    assert((await response.text()).includes(`const ${fallback} =`), 'The retained runtime must serve ' + fallback);
  }
  if (previousPackage) {
    const rows = legacyRows.map(([subject, field, value]) =>
      [subject, field, field === 'store' ? 'previous-store' : value]);
    const previousClients = [];
    for (const {name} of clients) {
      const directory = 'previous-' + name;
      const pin = await copyClientBundle(sources, name, join(stage, directory), previousPackage);
      const module = await readFile(join(stage, directory, 'browser.wasm'));
      previousClients.push({pin, module});
      rows.push([name, 'directory', directory], [name, 'receiptSha256', pin]);
    }
    const config = join(stage, 'previous-launch.rel');
    await writeFile(config, rows.map(row => '(' + row.map(value => JSON.stringify(value)).join(', ') + ')').join('\n'));
    previousHost = spawn(previousRuntime, ['--config', config, 'serve'], {stdio: ['ignore', 'pipe', 'inherit']});
    const [line] = await once(createInterface({input: previousHost.stdout}), 'line', {signal: AbortSignal.timeout(8000)});
    const previousOrigin = line.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    assert(previousOrigin, line);
    for (const [index, {path, binding}] of clients.entries()) {
      const expected = previousClients[index];
      const response = await fetch(previousOrigin + path);
      assert.equal(response.status, 200, path);
      assert.equal(response.headers.get('x-encounter-browser-wasm'), expected.pin, path);
      const body = Buffer.from(await response.arrayBuffer());
      const script = body.toString('utf8');
      assert(script.includes(`const ${binding} = '${expected.module.toString('base64')}';`), path);
      assert(!script.includes('encounterLegacy'), path);
      expected.scriptDigest = createHash('sha256').update(body).digest('hex');
    }
    await verifyLiveCanvasRollback(browser, origin, previousOrigin, clients, policies.get('/canvas'), previousClients);
  }
  await verifyLiveCanvasRollback(browser, origin, legacyOrigin, clients, policies.get('/canvas'));
  for (const reuseReply of [true, false]) await verifyQueuedLiveUpdate(browser, origin, {username, password}, reuseReply);
  await verifyQueuedLiveUpdate(browser, origin, {username, password}, true, true);
  console.log('PASS: Live Events retained an explicit update and the draft whether the in-flight reply was reused or retried');
  console.log('PASS: Live Events discarded the queued update after the route changed and kept the draft');
  if (!enforceCsp) {
    const blocked = await browser.newPage({httpCredentials: {username, password}});
    await blocked.addInitScript(() => {
      window.clientWasmBlocked = false;
      document.addEventListener('securitypolicyviolation', event => {
        if (event.blockedURI === 'wasm-eval' && event.effectiveDirective === 'script-src' &&
            event.disposition === 'enforce') window.clientWasmBlocked = true;
      });
    });
    let blockedSockets = 0;
    blocked.on('websocket', () => { blockedSockets++; });
    const blockedDocument = await blocked.goto(origin);
    const blockedPolicy = await blockedDocument.headerValue('content-security-policy');
    assert.match(blockedPolicy, /script-src 'self'/);
    assert.doesNotMatch(blockedPolicy, /'(?:wasm-)?unsafe-eval'/);
    assert.equal(await blocked.evaluate(() => typeof WebAssembly), 'object');
    await blocked.getByText('This release requires WebAssembly for live updates.', {exact: true}).waitFor();
    await blocked.waitForFunction(() => window.clientWasmBlocked);
    assert.equal(blockedSockets, 0);
    await blocked.goto(origin + '/canvas');
    await blocked.getByText('This release requires WebAssembly to play the canvas.', {exact: true}).waitFor();
    await blocked.waitForFunction(() => window.clientWasmBlocked);
    assert(await blocked.getByRole('button', {name: 'Play shot', exact: true}).isDisabled());
    await blocked.context().close();
    console.log('PASS: Chromium enforced the Wasm restriction for Live Events and Canvas');
  }
  const page = await browser.newPage({bypassCSP: !enforceCsp, httpCredentials: {username, password}});
  await observeWasm(page, ['resumeCursor', 'socketDelivery', 'refresh', 'replace', 'refreshReply', 'replaceReply',
    'reconnectRequest', 'reconnectAction', 'socketSchedule', 'cueCandidate', 'holdSubmit', 'pendingNotice',
    'mediaClockReady', 'seekCue', 'replaceToken', 'draftChanged', 'sameCoordinate', 'editorActive', 'updatePlan', 'applyQueued',
    'socketCoordinates', 'queuedApplied', 'inspectQueuedRoute', 'finishQueued']);
  const socket = Promise.withResolvers();
  await page.addInitScript(() => sessionStorage.setItem('encounter-events:/encounter-events', '1.5'));
  const reconnected = Promise.withResolvers();
  let attempts = 0;
  await page.routeWebSocket('**/encounter-events?*', route => {
    attempts++;
    if (attempts === 1) socket.resolve(route);
    if (attempts === 2) reconnected.resolve(route);
  });
  let refreshes = 0;
  let replyStream = '/unrelated-stream';
  let replySequence = 1;
  let replyHasMain = true;
  let reconnectStatus = null;
  await page.route(origin + '/', route => {
    if (route.request().isNavigationRequest()) return route.continue();
    if (reconnectStatus === 401) return route.fulfill({status: 401});
    if (reconnectStatus === 200) return route.fulfill({contentType: 'text/html', body: pageMarkup(1, '/encounter-events', 'replacement')});
    refreshes++;
    const html = pageMarkup(replySequence, replyStream);
    return route.fulfill({contentType: 'text/html',
      body: replyHasMain ? html : html.replace('<main>', '<section>').replace('</main>', '</section>')});
  });
  await page.goto(origin);
  const channel = await Promise.race([socket.promise, new Promise((_, reject) => {
    const timeout = setTimeout(() => reject(new Error('Missing live event socket')), 5000);
    timeout.unref();
  })]);
  assert.equal(new URL(channel.url()).searchParams.get('after'), '0');
  assert.equal(await page.evaluate(() => window.wasmCalls.resumeCursor), 1);
  const draft = page.getByRole('textbox', {name: 'Draft', exact: true});
  const original = 'x'.repeat(127) + '🙂' + 'x'.repeat(128) + 'Saved text';
  const edited = original.replace('Saved text', 'Draft text');
  await draft.evaluate((field, value) => { field.defaultValue = value; }, original);
  await draft.fill(edited);
  const deliveryCalls = await page.evaluate(() => window.wasmCalls.socketDelivery);
  const deliveryErrors = [];
  page.on('pageerror', error => deliveryErrors.push(error.message));
  channel.send('invalid JSON');
  channel.send('null');
  channel.send(JSON.stringify({sequence: 1.5}));
  channel.send(JSON.stringify({sequence: 1}));
  channel.send(JSON.stringify({sequence: 1}));
  channel.send(JSON.stringify({sequence: 0}));
  await page.waitForFunction(before => window.wasmCalls.socketDelivery >= before + 5, deliveryCalls);
  await page.getByText('New activity is ready. Your draft is still here.').waitFor();
  assert.equal(await page.evaluate(() => sessionStorage.getItem('encounter-events:/encounter-events')), '1');
  assert.deepEqual(deliveryErrors, []);
  assert.equal(refreshes, 0);
  await page.getByRole('button', {name: 'Show update'}).click();
  await page.waitForFunction(() => window.wasmCalls.replaceReply > 0);
  await page.getByRole('heading', {name: 'Sequence 0'}).waitFor();
  assert.equal(await page.getByRole('textbox', {name: 'Draft', exact: true}).inputValue(), edited);
  replyStream = '/encounter-events';
  replySequence = 'Infinity';
  const admissions = await page.evaluate(() => window.wasmCalls.replaceReply);
  await page.getByRole('button', {name: 'Show update'}).click();
  await page.waitForFunction(before => window.wasmCalls.replaceReply > before, admissions);
  assert.equal(await page.getByRole('heading', {name: 'Sequence 0'}).count(), 1);
  assert.equal(await page.getByRole('textbox', {name: 'Draft', exact: true}).inputValue(), edited);

  replySequence = 1;
  replyHasMain = false;
  const replacements = await page.evaluate(() => window.wasmCalls.replace);
  await page.getByRole('button', {name: 'Show update'}).click();
  await page.waitForFunction(before => window.wasmCalls.replace > before, replacements);
  assert.equal(await page.locator('main').count(), 1);
  await page.getByRole('heading', {name: 'Sequence 0'}).waitFor();
  assert.equal(await draft.inputValue(), edited);

  replyHasMain = true;
  await page.getByRole('button', {name: 'Show update'}).click();
  await page.getByRole('heading', {name: 'Sequence 1'}).waitFor();
  assert.equal(await page.getByRole('textbox', {name: 'Retained draft'}).inputValue(), edited);
  assert.equal(refreshes, 4);
  await page.getByRole('textbox', {name: 'Draft', exact: true}).fill('Keep editing during reconnect');
  reconnectStatus = 401;
  await channel.close({code: 4000});
  await page.getByText('Sign in again to reconnect.').waitFor();
  assert.equal(attempts, 1);
  reconnectStatus = 200;
  const nextSocket = await Promise.race([reconnected.promise, new Promise((_, reject) => {
    const timeout = setTimeout(() => reject(new Error('Missing recovered live event socket')), 8000);
    timeout.unref();
  })]);
  assert.equal(new URL(nextSocket.url()).searchParams.get('after'), '1');
  await page.getByText('Live updates connected').waitFor();
  assert.equal(await page.locator('input[name="_csrf"]').inputValue(), 'replacement');
  assert.equal(await page.getByRole('textbox', {name: 'Draft', exact: true}).inputValue(), 'Keep editing during reconnect');

  reconnectStatus = null;
  replySequence = 2;
  await page.getByRole('textbox', {name: 'Draft', exact: true}).fill('');
  await page.evaluate(() => {
    document.activeElement.blur();
    const save = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (this === sessionStorage && key === 'encounter-events:/encounter-events') {
        throw new DOMException('Session storage unavailable', 'QuotaExceededError');
      }
      return save.call(this, key, value);
    };
    const read = window.fetch;
    window.fetch = async (...args) => {
      const response = await read(...args);
      window.fetch = read;
      const text = response.text.bind(response);
      response.text = async () => {
        const html = await text();
        history.replaceState(null, '', '/?other=1');
        setTimeout(() => { window.lateBodyConsumed = true; }, 0);
        return html;
      };
      return response;
    };
  });
  nextSocket.send(JSON.stringify({sequence: 2}));
  await page.waitForFunction(() => window.lateBodyConsumed);
  assert.deepEqual(deliveryErrors, []);
  await page.getByRole('heading', {name: 'Sequence 1'}).waitFor();
  assert.equal(await page.getByRole('heading', {name: 'Sequence 2'}).count(), 0);
  await page.evaluate(() => {
    const video = document.createElement('video');
    video.dataset.encounterMediaClock = 'test-timeline';
    Object.defineProperties(video, {readyState: {value: 2}, currentTime: {value: 10}, seeking: {value: false, configurable: true}});
    const timeline = document.createElement('nav');
    timeline.id = 'test-timeline';
    for (const start of [0, 15, 5]) {
      const link = document.createElement('a');
      link.dataset.encounterMediaStart = start;
      link.href = '/';
      timeline.append(link);
    }
    document.querySelector('main').append(video, timeline);
    video.dispatchEvent(new Event('timeupdate'));
    Object.defineProperty(video, 'seeking', {value: true});
    const form = document.querySelector('[data-encounter-draft]').form;
    if (form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}))) {
      throw new Error('A seeking video allowed a draft submit');
    }
  });
  assert(Object.values(await page.evaluate(() => window.wasmCalls)).every(count => count > 0));
  console.log('PASS: live events rejected unrelated and stale-route replies, retained drafts through reconnect, and held a seeking submission through Wasm');

  for (const wasm of [true, false]) {
    const reviewOrigin = wasm ? origin : legacyOrigin;
    const review = await browser.newPage({bypassCSP: wasm && !enforceCsp, httpCredentials: {username, password}});
    try {
      if (wasm) await observeWasm(review, ['replace', 'pendingNotice', 'mediaClockReady', 'seekCue']);
      else await review.addInitScript(() => { window.WebAssembly = undefined; });
      await review.routeWebSocket('**/encounter-events?*', () => {});
      const reviewMarkup = (sequence, complete) => pageMarkup(sequence)
        .replace('<form>', '<section ' + (complete ? 'id="review" data-encounter-live-part' : '') + '><form>')
        .replace('</form>', '<button type="submit">Send feedback</button></form>')
        .replace('</main>', '<button data-encounter-decision>Review decision</button></section></main>');
      const initial = reviewMarkup(0, true).replace('</main>',
        '<video data-encounter-media-clock="review-timeline"></video>' +
        '<nav id="review-timeline"><a href="/?segment=second" data-encounter-media-start="5">Second segment</a></nav></main>');
      let complete = false;
      const policy = wasm ? policies.get('/') : undefined;
      await review.route(reviewOrigin + '/', route => fulfillHtml(route, initial, policy));
      await review.route(reviewOrigin + '/?segment=second', route => {
        const html = reviewMarkup(1, complete);
        const outside = '<aside id="review" data-encounter-live-part>Outside the workbench</aside>';
        return fulfillHtml(route, complete ? html : html.replace('</main>', '</main>' + outside), policy);
      });
      await review.goto(reviewOrigin);
      await review.evaluate(() => {
        const video = window.reviewVideo = document.querySelector('video');
        const parse = DOMParser.prototype.parseFromString;
        window.reviewReplies = 0;
        DOMParser.prototype.parseFromString = function (...args) {
          window.reviewReplies++;
          return parse.apply(this, args);
        };
        let time = 0;
        Object.defineProperties(video, {
          readyState: {value: 2},
          currentTime: {get: () => time, set: value => { time = value; }},
        });
      });
      const draft = review.getByRole('textbox', {name: 'Draft', exact: true});
      await draft.fill('Keep feedback when playback advances');
      await review.getByRole('link', {name: 'Second segment'}).click();
      await review.waitForFunction(() => window.reviewVideo.currentTime === 5);
      await review.getByText('Playback moved to another segment.', {exact: false}).waitFor();
      const apply = review.getByRole('button', {name: 'Show update'});
      const submit = review.getByRole('button', {name: 'Send feedback'});
      assert(await submit.isDisabled());
      await review.evaluate(() => {
        window.reviewVideo.currentTime = 0;
        window.reviewVideo.dispatchEvent(new Event('seeked'));
      });
      await apply.waitFor({state: 'hidden'});
      assert(await submit.isEnabled());
      await review.getByRole('link', {name: 'Second segment'}).click();
      await apply.waitFor({state: 'visible'});
      assert(await submit.isDisabled());
      await apply.click();
      await review.waitForFunction(() => window.reviewReplies === 1);
      if (wasm) await review.waitForFunction(() => window.wasmCalls.replace > 0);
      assert.equal(new URL(review.url()).search, '');
      assert.equal(await draft.inputValue(), 'Keep feedback when playback advances');

      complete = true;
      await apply.click();
      await review.waitForURL(reviewOrigin + '/?segment=second');
      assert.equal(await review.getByRole('textbox', {name: 'Retained draft'}).inputValue(), 'Keep feedback when playback advances');
      assert(await review.evaluate(() => window.reviewVideo === document.querySelector('video') &&
        document.activeElement.matches('[data-encounter-decision]')));
      if (wasm) assert(Object.values(await review.evaluate(() => window.wasmCalls)).every(count => count > 0));
    } finally {
      await review.context().close();
    }
  }
  console.log('PASS: Live Events held replies without a main surface or with a replacement part outside it and preserved drafts');

  const invalidTimeline = await browser.newPage({bypassCSP: !enforceCsp, httpCredentials: {username, password}});
  try {
    await observeWasm(invalidTimeline, ['timelineAdmission', 'playback']);
    const pageErrors = [];
    invalidTimeline.on('pageerror', error => pageErrors.push(error.message));
    await invalidTimeline.route('**/canvas?invalid-timeline=1', route => fulfillHtml(route,
      canvasMarkup.replace(/data-canvas-seconds="[^"]+"/, 'data-canvas-seconds="Infinity"'), policies.get('/canvas')));
    await invalidTimeline.goto(origin + '/canvas?invalid-timeline=1');
    await invalidTimeline.getByText('The canvas timeline is unavailable.', {exact: true}).waitFor();
    assert(await invalidTimeline.getByRole('button', {name: 'Play shot', exact: true}).isDisabled());
    assert.deepEqual(await invalidTimeline.evaluate(() => window.wasmCalls), {timelineAdmission: 1, playback: 0});
    assert.deepEqual(pageErrors, []);
  } finally {
    await invalidTimeline.context().close();
  }
  console.log('PASS: pinned Canvas refused a non-finite timeline before playback');

  const canvas = await browser.newPage({bypassCSP: !enforceCsp, httpCredentials: {username, password}});
  const playbackExports = ['playback', 'frameTime', 'clockDisplay', 'timelineAdmission', 'cueSelection', 'confirmLeave', 'scrub', 'settingChanged',
    'surfaceProfile', 'seaLayout', 'settingsAction', 'settingsText', 'settingsSurface',
    'camera', 'routePoint', 'palette', 'waterStyle', 'warmth', 'cueTime', 'sceneFrame', 'sceneCamera', 'seaWave', 'beaconGlow', 'beaconReflection',
    'beaconLayout', 'beaconStripes', 'placeVertex', 'boatBob', 'boatWake', 'routeDistance', 'routeSegment', 'drawingVertex', 'plateGeometry', 'arrivalPhase', 'lightAlpha'];
  const sceneExports = {
    flight: ['flightStar', 'flightPosition', 'flightTrail', 'flightPlate', 'flightBeacon', 'drawingVertex'],
    collision: ['collisionSlip', 'collisionRoute'],
    launch: ['launchPhase', 'launchSlip', 'bookDetails', 'bookGeometry', 'bookDetailGeometry', 'drawingVertex'],
    arrival: ['drawingVertex'],
    branches: ['drawingVertex'],
    intent: ['intentSlip', 'intentBook', 'bookDetails'],
    strata: ['strataPlate', 'strataRoute', 'strataStar'],
    gate: ['gateArms', 'drawingVertex'],
    rebuild: ['rebuildPhase', 'rebuildPlate', 'drawingVertex'],
    refactor: ['rebuildPhase', 'rebuildPlate', 'drawingVertex'],
    network: ['networkNode', 'networkMark', 'networkProgress', 'drawingVertex'],
    signals: ['signalPhase', 'signalsBook', 'bookDetails', 'bookGeometry', 'drawingVertex'],
    harbours: ['harboursProgress', 'harbourLayout', 'drawingVertex'],
    home: ['homePhase', 'drawingVertex'],
    closing: ['homePhase', 'drawingVertex'],
  };
  await observeWasm(canvas, [...playbackExports, 'branchPhase', 'gatePhase', 'closingFade', 'pulseRing',
    ...new Set(Object.values(sceneExports).flat())]);
  const canvasErrors = [];
  canvas.on('pageerror', error => canvasErrors.push(error.message));
  const canvasPolicy = policies.get('/canvas');
  await canvas.route('**/canvas?shared=1', route => fulfillHtml(route, canvasMarkup.replace(
    '<script src="/encounter-canvas.js"', '<script src="/encounter-events.js" defer></script><script src="/encounter-canvas.js"'), canvasPolicy));
  await canvas.goto(origin + '/canvas?shared=1');
  await canvas.getByRole('button', {name: 'Play shot', exact: true}).click();
  await canvas.getByRole('button', {name: 'Replay shot', exact: true}).waitFor();
  assert.equal(await canvas.locator('[data-canvas-scrub]').inputValue(), '0.5');
  const scrub = canvas.locator('[data-canvas-scrub]');
  await scrub.evaluate(control => { control.max = '1'; });
  await scrub.fill('1');
  assert.equal(await scrub.inputValue(), '0.5');
  assert.deepEqual(canvasErrors, [], 'Canvas and Live Events must load on the same document');
  assert(await canvas.locator('canvas').evaluate(node => node.getContext('2d').getImageData(20, 20, 1, 1).data.slice(0, 3).some(Boolean)));
  const pixel = () => canvas.locator('canvas').evaluate(node => [...node.getContext('2d').getImageData(20, 20, 1, 1).data]);
  const warmth = canvas.locator('[data-canvas-setting="warmth"]');
  await warmth.fill('70');
  const warm = await pixel();
  await warmth.fill('-70');
  assert.notDeepEqual(await pixel(), warm);
  const motion = canvas.locator('[data-canvas-setting="motion"]');
  const canvasDraft = canvas.locator('#canvas-settings [data-encounter-draft]');
  await motion.fill('100.0');
  assert((await canvasDraft.inputValue()).split('\n').includes('motion = 100.0'));
  await motion.fill('100');
  assert(!(await canvasDraft.inputValue()).split('\n').some(line => line.startsWith('motion = ')));
  await motion.fill('80');
  const warnsOnLeave = () => canvas.evaluate(() => {
    const event = new Event('beforeunload', {cancelable: true});
    return !window.dispatchEvent(event);
  });
  assert(await warnsOnLeave());
  const submitSettings = prevented => canvas.locator('#canvas-settings').evaluate((form, prevented) => {
    if (prevented) document.addEventListener('submit', event => event.preventDefault(), {once: true});
    form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
  }, prevented);
  await submitSettings(true);
  assert(await warnsOnLeave());
  await submitSettings(false);
  assert.equal(await warnsOnLeave(), false);
  await canvas.evaluate(() => document.dispatchEvent(new Event('encounter:live-refresh')));
  assert.equal(await canvasDraft.inputValue(), 'motion = 80\nwarmth = -70');
  assert.equal(await warnsOnLeave(), false);
  await motion.fill('81');
  assert(await warnsOnLeave());
  assert.deepEqual(await canvas.locator('canvas').evaluate(node => [node.width, node.height]), [1280, 720]);
  await canvas.getByRole('button', {name: 'Reset preview'}).click();
  assert.equal(await motion.inputValue(), '100');
  assert.equal(await warmth.inputValue(), '0');
  assert.equal(await canvasDraft.inputValue(), '');
  assert.equal(await warnsOnLeave(), false);
  await canvas.evaluate(() => {
    document.querySelector('[data-canvas-setting="motion"]').value = '78';
    document.dispatchEvent(new Event('encounter:live-refresh'));
  });
  assert.equal(await canvasDraft.inputValue(), 'motion = 78');
  assert(await warnsOnLeave());
  const playbackCalls = await canvas.evaluate(() => window.wasmCalls);
  assert(playbackExports.every(name => playbackCalls[name] > 0));
  console.log('PASS: canvas drew the declared cue, reached its playback limit, and protected draft settings through Wasm');

  const sceneNames = ['flight', 'launch', 'arrival', 'still', 'collision', 'intent', 'intent-shift',
    'intent-close', 'strata', 'strata-close', 'branches', 'gate', 'rebuild', 'refactor', 'network',
    'signals', 'harbours', 'home', 'closing', 'constructor'];
  const scenePhases = new Map([
    ['flight', {positions: [2, 3.79, 4.5]}],
    ['launch', {positions: [0.4, 1.2, 3.1]}],
    ['arrival', {positions: [1, 3, 5.5]}],
    ['rebuild', {positions: [0.5, 2, 5]}],
    ['refactor', {positions: [0.5, 3, 8]}],
    ['signals', {positions: [0.9, 1.8, 4]}],
    ['harbours', {positions: [1.4, 3, 6]}],
    ['collision', {positions: [2, 5, 6.5]}],
    ['intent', {positions: [0.9, 2, 5]}],
    ['strata', {positions: [2.9, 3.1, 6]}],
    ['network', {positions: [2, 7, 12]}],
    ['branches', {positions: [3.79, 3.8], exportName: 'branchPhase'}],
    ['gate', {positions: [5, 8, 9.5, 14], exportName: 'gatePhase'}],
    ['closing', {positions: [6, 8, 10], exportName: 'closingFade'}],
  ]);
  const previousCanvas = await browser.newPage({httpCredentials: {username, password}});
  try {
    await previousCanvas.addInitScript(() => { window.WebAssembly = undefined; });
    for (const [browserPage, policy] of [[canvas, canvasPolicy], [previousCanvas, undefined]]) {
      await browserPage.route(url => url.pathname === '/canvas' && sceneNames.includes(url.searchParams.get('scene')), route => {
        const scene = new URL(route.request().url()).searchParams.get('scene');
        const markup = canvasMarkup.replace('data-canvas-effect="still"', 'data-canvas-effect="' + scene + '"')
          .replace('data-canvas-seconds="0.5"', 'data-canvas-seconds="16"')
          .replace('data-canvas-to="10.5"', 'data-canvas-to="26"').replace('max="0.5"', 'max="16"');
        return fulfillHtml(route, markup, policy);
      });
      await browserPage.route('**/canvas?overlap=1', route => fulfillHtml(route, canvasMarkup
        .replace('data-canvas-seconds="0.5"', 'data-canvas-seconds="1"').replace('max="0.5"', 'max="1"')
        .replace('<i data-canvas-effect="still"', '<i data-canvas-effect="launch" data-canvas-from="bad" data-canvas-to="11"></i>' +
          '<i data-canvas-effect="arrival" data-canvas-from="10" data-canvas-to="10.5"></i><i data-canvas-effect="still"')
        .replace('data-canvas-effect="still" data-canvas-from="10" data-canvas-to="10.5"',
          'data-canvas-effect="still" data-canvas-from="10.25" data-canvas-to="11"'), policy));
      await browserPage.route('**/canvas?clock=1', route => fulfillHtml(route, canvasMarkup
        .replace('data-canvas-seconds="0.5"', 'data-canvas-seconds="120"').replace('max="0.5"', 'max="120"'), policy));
    }
    const frameDigest = (browserPage, position) => browserPage.evaluate(async position => {
      const scrub = document.querySelector('[data-canvas-scrub]');
      scrub.value = position;
      scrub.dispatchEvent(new Event('input', {bubbles: true}));
      const node = document.querySelector('canvas');
      const context = node.getContext('2d');
      const pixels = context.getImageData(0, 0, node.width, node.height).data;
      const digest = await crypto.subtle.digest('SHA-256', pixels);
      return Array.from(new Uint8Array(digest));
    }, position);
    for (const scene of sceneNames) {
      await Promise.all([canvas.goto(origin + '/canvas?scene=' + scene),
        previousCanvas.goto(legacyOrigin + '/canvas?scene=' + scene)]);
      const {positions, exportName} = scenePhases.get(scene) ?? {positions: [5]};
      let previous;
      for (const position of positions) {
        const [actual, legacy] = await Promise.all([frameDigest(canvas, position), frameDigest(previousCanvas, position)]);
        assert.deepEqual(actual, legacy, scene + ' at ' + position);
        if (previous) assert.notDeepEqual(actual, previous, scene + ' did not advance');
        previous = actual;
      }
      if (scene === 'arrival') {
        for (const tint of ['-70', '70']) {
          await Promise.all([canvas, previousCanvas].map(page => page.locator('[data-canvas-setting="warmth"]').fill(tint)));
          const [actual, legacy] = await Promise.all([frameDigest(canvas, 3), frameDigest(previousCanvas, 3)]);
          assert.deepEqual(actual, legacy, 'arrival with warmth ' + tint);
        }
      }
      const calls = await canvas.evaluate(() => window.wasmCalls);
      assert(calls.sceneFrame > 0);
      if (scene !== 'constructor') assert(calls.sceneCamera > 0);
      if (exportName) assert(calls[exportName] > 0);
      if (Object.hasOwn(sceneExports, scene)) {
        for (const name of sceneExports[scene]) assert(calls[name] > 0);
      }
      if (scene === 'gate') assert(calls.pulseRing > 0);
    }
    await Promise.all([canvas.goto(origin + '/canvas?overlap=1'), previousCanvas.goto(legacyOrigin + '/canvas?overlap=1')]);
    for (const position of [0.25, 0.49, 0.5, 1]) {
      const [actual, legacy] = await Promise.all([frameDigest(canvas, position), frameDigest(previousCanvas, position)]);
      assert.deepEqual(actual, legacy, 'overlapping cues at ' + position);
    }
    assert.notDeepEqual(await frameDigest(canvas, 0.49), await frameDigest(canvas, 0.5));
    assert((await canvas.evaluate(() => window.wasmCalls)).cueSelection > 4);
    for (const [page, base] of [[canvas, origin], [previousCanvas, legacyOrigin]]) {
      await page.goto(base + '/canvas?clock=1');
      for (const [position, expected] of [[59.99, '0:59'], [60, '1:00'], [61.01, '1:01']]) {
        await page.locator('[data-canvas-scrub]').fill(String(position));
        assert.equal(await page.locator('[data-canvas-time]').evaluate(output => output.value), expected);
      }
    }
    assert((await canvas.evaluate(() => window.wasmCalls)).clockDisplay >= 4);
  } finally {
    await previousCanvas.context().close();
  }
  console.log('PASS: Canvas cue variants, overlap boundaries, branch switch, gate opening, and closing fade matched legacy JavaScript pixels through Wasm');

  for (const wasm of [true, false]) {
    const narration = await browser.newPage({bypassCSP: wasm && !enforceCsp, httpCredentials: {username, password}});
    try {
      if (wasm) await observeWasm(narration, ['playToggle', 'soundChange', 'narrationResult', 'narrationFault', 'clockAnchor', 'audioPosition', 'playback']);
      else await narration.addInitScript(() => { window.WebAssembly = undefined; });
      await narration.addInitScript(() => {
        const times = new WeakMap();
        const fixture = window.narrationFixture = {requests: [], pauses: 0};
        Object.defineProperties(HTMLMediaElement.prototype, {
          currentTime: {
            get() { return times.get(this) ?? 0; },
            set(value) { times.set(this, value); },
          },
          play: {value() { return new Promise((resolve, reject) => fixture.requests.push({resolve, reject})); }},
          pause: {value() { fixture.pauses++; }},
        });
      });
      const canvasOrigin = wasm ? origin : legacyOrigin;
      await narration.route(canvasOrigin + '/canvas?narration=1', route => fulfillHtml(route, canvasMarkup
        .replace('data-canvas-seconds="0.5"', 'data-canvas-seconds="5"').replace('max="0.5"', 'max="5"'),
      wasm ? canvasPolicy : undefined));
      await narration.goto(canvasOrigin + '/canvas?narration=1');
      const sound = narration.locator('[data-canvas-sound]');
      const play = narration.locator('[data-canvas-play]');
      const waitForRequest = count => narration.waitForFunction(count => window.narrationFixture.requests.length === count, count);
      const audio = narration.locator('[data-canvas-audio]');
      const unavailable = narration.getByText('Narration is unavailable. The animation is playing silently.', {exact: true});
      await audio.dispatchEvent('error');
      assert.equal(await unavailable.count(), 0);
      await sound.check();
      await play.click();
      await waitForRequest(1);
      await sound.uncheck();
      const pauses = await narration.evaluate(() => window.narrationFixture.pauses);
      await narration.evaluate(() => window.narrationFixture.requests[0].resolve());
      await narration.waitForFunction(pauses => window.narrationFixture.pauses === pauses + 1, pauses);
      await audio.dispatchEvent('error');
      await unavailable.waitFor();
      await narration.getByRole('button', {name: 'Pause shot', exact: true}).click();

      await sound.check();
      await play.click();
      await waitForRequest(2);
      await narration.evaluate(() => window.narrationFixture.requests[1].reject(new Error('Narration refused in fixture')));
      await narration.getByText('Narration could not start. The animation is playing silently.', {exact: true}).waitFor();
      await narration.getByRole('button', {name: 'Pause shot', exact: true}).click();

      await play.click();
      await waitForRequest(3);
      await narration.evaluate(async () => {
        window.narrationFixture.requests[2].resolve();
        await Promise.resolve();
        document.querySelector('[data-canvas-audio]').currentTime = 15;
      });
      await narration.getByRole('button', {name: 'Replay shot', exact: true}).waitFor({timeout: 2000});
      assert.equal(await narration.locator('[data-canvas-scrub]').inputValue(), '5');
      if (wasm) assert(Object.values(await narration.evaluate(() => window.wasmCalls)).every(count => count > 0));
    } finally {
      await narration.context().close();
    }
  }
  console.log('PASS: canvas paused obsolete narration, recovered from a refusal, and reached the end on the audio clock');

  await writeFile(join(app, 'gateway.rel'), [
    '("application", "stateProfile", "encounter/preview-wasm-test/1")',
    '("application", "module", "gateway.encounter")',
    '("application", "entry", "gateway.route")',
    '("application", "entry", "gateway.page")',
    '("application", "entry", "gateway.styles")',
  ].join('\n'));
  await writeFile(join(app, 'gateway.encounter'), [
    'process-module "temple/surface-process-module/1"',
    'process gateway.route:',
    '  let script = and(eq($eventInput.path, "/preview-context.js"), eq($eventInput.method, "GET"), not($eventInput.upgrade))',
    '  let result = { status = if($script, 200, 404); previewContextScript = $script }',
    'process gateway.page:', '  let result = ""',
    'process gateway.styles:', '  let result = ""',
  ].join('\n'));
  const gatewayConfig = join(stage, 'gateway.rel');
  const previewDirectory = join(stage, 'preview');
  const previewPin = await copyClientBundle(sources, 'preview', previewDirectory);
  const previewModule = await readFile(join(previewDirectory, 'browser.wasm'));
  const gatewayLaunch = [
    ['gateway', 'version', 'encounter/gateway/1'], ['gateway', 'port', '0'],
    ['gateway', 'prefix', '/pilot'], ['gateway', 'broker', 'https://broker.example.test'],
    ['gateway', 'owner', 'fixture@example.test'], ['gateway', 'identityPort', '1'], ['gateway', 'identityPath', '/me'],
    ['gateway', 'root', app], ['gateway', 'declaration', 'gateway.rel'], ['gateway', 'target', 'preview'],
    ['preview', 'origin', origin], ['preview', 'port', '1'], ['preview', 'authorization', 'Basic Zml4dHVyZQ=='],
    ['preview-client', 'directory', 'preview'], ['preview-client', 'receiptSha256', previewPin],
  ].map(row => '(' + row.map(value => JSON.stringify(value)).join(', ') + ')').join('\n');
  await writeFile(gatewayConfig, gatewayLaunch.replace(previewPin, '0'.repeat(64)), {mode: 0o600});
  const rejectedGateway = spawnSync(encounter, ['gateway', gatewayConfig], {encoding: 'utf8', timeout: 5000});
  assert.ifError(rejectedGateway.error);
  assert.notEqual(rejectedGateway.status, 0);
  assert.match(rejectedGateway.stderr, /browser Wasm receipt hash differs/);
  await writeFile(gatewayConfig, gatewayLaunch, {mode: 0o600});
  async function startPreviewGateway(runtime = encounter) {
    gateway = spawn(runtime, ['gateway', gatewayConfig], {stdio: ['ignore', 'pipe', 'inherit']});
    const [line] = await once(createInterface({input: gateway.stdout}), 'line', {signal: AbortSignal.timeout(8000)});
    const gatewayOrigin = line.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    assert(gatewayOrigin, line);
    return gatewayOrigin;
  }
  async function fetchPreviewScript(gatewayOrigin) {
    const result = await gatewayResponse(gatewayOrigin, new URL('/pilot/preview-context.js', origin));
    return {status:result.status, receipt:result.headers['x-encounter-browser-wasm'], body:result.body};
  }
  async function restartPreviewGateway(config, runtime = encounter) {
    const stopped = once(gateway, 'exit');
    gateway.kill('SIGTERM');
    await stopped;
    await writeFile(gatewayConfig, config, {mode: 0o600});
    return fetchPreviewScript(await startPreviewGateway(runtime));
  }
  const gatewayOrigin = await startPreviewGateway();
  await writeFile(join(previewDirectory, 'browser.wasm'), 'changed after startup');
  const asset = await fetchPreviewScript(gatewayOrigin);
  assert.equal(asset.status, 200);
  assert.equal(asset.receipt, previewPin);
  assert(asset.body.includes(`const encounterPreviewWasm = '${previewModule.toString('base64')}';`));
  assert(!asset.body.includes('encounterLegacyPreview'));
  const preview = await browser.newPage({bypassCSP: !enforceCsp});
  const longContext = 'x'.repeat(4095) + '🙂';
  await observeWasm(preview, ['formContext', 'approvedContext', 'pickKey', 'selectionView', 'optionDisabled',
    'selectValue', 'commentVisible', 'returnVisible', 'targetFamily', 'pickClick', 'pickAlias', 'pickerStarts', 'pickerView', 'menuChoice',
    'selectionFollowup', 'commentSummary', 'commentBadge', 'contextLabel', 'contextLabelSource',
    'targetSelectors', 'reportTarget',
    'paneAdmission', 'leaveCard', 'leaveStep', 'supportCoordinates', 'panePlan', 'targetAdmission'],
    ['commonTargets', 'menuTarget', 'sameContext']);
  let previewScript = asset.body;
  await preview.route(origin + '/pilot/preview-context.js', route => route.fulfill({contentType: 'text/javascript', body: previewScript}));
  const previewPolicies = policies.get('preview');
  await preview.route(url => url.origin === origin && /^\/pilot\/(?:long-\w+\/)?step-(?:[367]|07)\/sick-leave$/.test(url.pathname), route => fulfillHtml(route,
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Preview fixture</title><script src="/pilot/preview-context.js" defer></script></head><body>' +
    '<button id="pilot-context-picker" hidden>Pick on preview</button><p id="pilot-context-status"></p>' +
    '<div class="pilot-preview-surface"><div class="pilot-app-scope">Whole app</div><main><ul>' +
    '<li id="increase"><form><input type="hidden" name="action" value="adjust-sick"><button id="increase-control" type="button">Increase leave</button></form>' +
    '<form><input type="hidden" name="action" value="approve-sick"></form></li>' +
    '<li id="hidden-increase" hidden><form><input type="hidden" name="action" value="adjust-sick"></form></li>' +
    '<li id="proposal"><p>' + '🙂'.repeat(100) + ' approved minutes</p><p>Reduction to 90 minutes</p></li>' +
    '<li id="later-proposal"><p>Proposal</p><p>Reduction to 60 minutes</p></li>' +
    '</ul></main></div><aside class="pilot-preview-comments" tabindex="-1">' +
    '<a class="pilot-aster-support" href="/aster">Ask Aster</a><iframe title="Comments" src="/pilot/comments"></iframe></aside></body></html>',
    previewPolicies?.document));
  await preview.route(url => url.origin === origin && ['/pilot/timesheet', '/pilot/report'].includes(url.pathname), route => {
    const timesheet = new URL(route.request().url()).pathname === '/pilot/timesheet';
    const content = timesheet
      ? '<section aria-label="Your entries"><ul><li id="entry" aria-label="Entry from its target"><a href="?entry=item">Entry link</a></li></ul></section>'
      : '<section aria-label="Report filters" id="report-filters">Filters</section>' +
        '<table aria-label="Employee totals" id="report-totals"><tbody><tr><td>Totals</td></tr></tbody></table>' +
        '<section aria-label="Minutes by employee" id="report-minutes">Minutes</section>';
    return fulfillHtml(route, '<!doctype html><html><head><meta charset="utf-8"><script src="/pilot/preview-context.js" defer></script></head><body>' +
      '<button id="pilot-context-picker"></button><p id="pilot-context-status"></p>' +
      '<div class="pilot-preview-surface"><div class="pilot-app-scope"></div><main>' + content + '</main></div>' +
      '<aside class="pilot-preview-comments"><iframe title="Comments" src="/pilot/comments"></iframe></aside></body></html>',
    previewPolicies?.document);
  });
  await preview.route(origin + '/pilot/comments', route => fulfillHtml(route,
    '<!doctype html><section class="nr-preview-comments"><label>Context <select aria-label="Context">' +
    '<option value="">Screen</option><option value="increase">Increase</option><option value="propose">Proposal</option><option value="approve">Approval</option><option value="confirm">Confirmation</option><option value="missing">Missing</option><option value="item"></option><option value="filters">Report filters</option><option value="employee-totals">Employee totals</option><option value="minutes-by-employee">Minutes by employee</option></select></label>' +
    '<textarea name="review-note"></textarea>' +
    '<ol aria-label="Preview comments"><li data-preview-comment-context="increase">Increase comment</li>' +
    '<li data-preview-comment-context="increase">Another note about increasing leave</li>' +
    '<li data-preview-comment-context="screen">Screen comment</li>' +
    '<li data-preview-comment-context="item"><small>Entry from its comment</small></li>' +
    '<li data-preview-comment-context="orphan"><small>Area from its comment</small></li>' +
    '<li data-preview-comment-context="' + longContext + '">Long matching comment</li>' +
    '<li data-preview-comment-context="' + longContext.slice(0, -2) + '🙃">Long different comment</li></ol></section>',
    previewPolicies?.comments));
  await preview.goto(origin + '/pilot/step-7/sick-leave?context=missing&entry=item&entry=discard&ignored=discard&review-task=fixture');
  const picker = preview.locator('#pilot-context-picker');
  const comments = preview.frameLocator('iframe[title="Comments"]');
  const supportContext = async () => {
    const support = new URL(await preview.getByRole('link', {name: 'Ask Aster'}).getAttribute('href'), origin);
    return Object.fromEntries(new URL(support.searchParams.get('source')).searchParams);
  };
  await preview.getByText('This area is unavailable in the current preview.').waitFor();
  assert(await comments.locator('option[value="missing"]').evaluate(option => option.disabled));
  assert.deepEqual(await supportContext(), {'review-task': 'fixture', entry: 'item'});
  assert.deepEqual(Object.keys(await supportContext()), ['review-task', 'entry']);
  assert.equal(await comments.locator('option[value="propose"]').isEnabled(), true);
  await preview.locator('iframe[title="Comments"]').dispatchEvent('load');
  const screenBadge = preview.getByRole('button', {name: 'This screen: 1 comment', exact: true});
  const increaseBadge = preview.getByRole('button', {name: 'Increase: 2 comments', exact: true});
  assert.equal(await screenBadge.innerText(), 'This screen · 1 comment');
  assert.equal(await increaseBadge.innerText(), '2 comments');
  assert.equal(await comments.getByRole('button', {name: 'Show all comments'}).count(), 1);
  await picker.click();
  await preview.getByText('Pick an area, this screen, or Whole app. Press Escape to cancel.').waitFor();
  await preview.locator('#increase').press('Enter');
  await preview.getByText('Highlighted: Increase', {exact: true}).waitFor();
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'increase');
  assert.equal(await preview.locator('#increase[data-pilot-context-active]').count(), 1);
  assert.equal(await preview.locator('#increase').getAttribute('tabindex'), null);
  assert.deepEqual(await supportContext(), {'review-task': 'fixture', entry: 'item', context: 'increase'});
  assert.equal(await comments.getByText('Increase comment').isVisible(), true);
  assert.equal(await comments.getByRole('status').innerText(), 'Increase · 2 comments');
  assert.equal(await comments.getByText('Screen comment').isVisible(), false);
  const composer = comments.locator('textarea[name="review-note"]');
  assert(await composer.evaluate(element => element.ownerDocument.activeElement === element));
  const increaseControl = preview.locator('#increase-control');
  await increaseControl.evaluate(element => {
    window.previewControlClicks = 0;
    element.addEventListener('click', () => { window.previewControlClicks++; });
  });
  await picker.click();
  await increaseControl.dispatchEvent('keydown', {key: 'Enter', bubbles: true});
  assert.equal(await picker.getAttribute('aria-pressed'), 'true');
  await increaseControl.click();
  assert.equal(await picker.getAttribute('aria-pressed'), 'false');
  assert.equal(await preview.evaluate(() => window.previewControlClicks), 0);
  assert(await composer.evaluate(element => element.ownerDocument.activeElement === element));
  await increaseControl.click();
  assert.equal(await preview.evaluate(() => window.previewControlClicks), 1);
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'increase');

  await comments.getByRole('combobox', {name: 'Context'}).selectOption('approve');
  await picker.click();
  await preview.locator('#increase').press('Enter');
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'approve');
  await picker.click();
  await increaseControl.click();
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'approve');
  assert.equal(await preview.locator('#increase').getAttribute('tabindex'), null);

  await preview.locator('[data-comment-target="screen"]').click();
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'screen');
  const summary = comments.getByRole('status');
  assert.equal(await summary.innerText(), 'This screen · 1 comment');
  assert(await summary.evaluate(element => element.ownerDocument.activeElement === element));
  assert.equal(await comments.getByText('Increase comment').isVisible(), false);
  const back = preview.locator('a[href="#preview-comments"]');
  assert.equal(await back.textContent(), 'Back to comments');
  await back.dispatchEvent('click');
  assert(await composer.evaluate(element => element.ownerDocument.activeElement === element));
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'screen');

  await picker.click();
  await preview.locator('#increase').press('Escape');
  assert.equal(await preview.locator('#increase').getAttribute('tabindex'), null);
  assert.equal(await picker.getAttribute('aria-pressed'), 'false');
  assert(await picker.evaluate(element => document.activeElement === element));
  await comments.getByRole('button', {name: 'Show all comments'}).click();
  assert.equal(await comments.getByText('Screen comment').isVisible(), true);
  await comments.getByRole('combobox', {name: 'Context'}).selectOption('increase');
  await comments.getByRole('combobox', {name: 'Context'}).evaluate(menu => {
    menu.value = 'missing';
    menu.dispatchEvent(new Event('change'));
  });
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'increase');
  assert.equal(await comments.getByRole('combobox', {name: 'Context'}).inputValue(), 'increase');
  assert(await comments.getByText('Increase comment').isVisible());
  await comments.getByRole('combobox', {name: 'Context'}).selectOption('');
  assert.equal(new URL(preview.url()).searchParams.get('context'), 'screen');
  assert.equal(await comments.getByText('Increase comment').isVisible(), false);
  const leaveCalls = await preview.evaluate(() => window.wasmCalls);
  assert(Object.entries(leaveCalls).every(([name, count]) => name === 'reportTarget' || count > 0));
  console.log('PASS: preview handled unavailable and selected targets, updated the support link, and filtered comments through Wasm');
  await preview.goto(origin + '/pilot/timesheet?context=item');
  await preview.locator('#entry[data-pilot-context-active]').waitFor();
  await preview.getByRole('button', {name: 'Entry from its target: 1 comment', exact: true}).waitFor();
  await preview.goto(origin + '/pilot/report?context=orphan');
  await comments.getByRole('status').filter({hasText: /^Area from its comment · 1 comment$/}).waitFor();
  const reportMenu = comments.getByRole('combobox', {name: 'Context'});
  for (const [id, selector] of [['filters', '#report-filters'], ['employee-totals', '#report-totals'], ['minutes-by-employee', '#report-minutes']]) {
    await reportMenu.selectOption(id);
    await preview.locator(selector + '[data-pilot-context-active]').waitFor();
  }
  assert((await preview.evaluate(() => window.wasmCalls.reportTarget)) >= 4);
  console.log('PASS: Preview resolved timesheet and report targets and chose accessible labels through Wasm');
  await preview.goto(origin + '/pilot/step-7/sick-leave?context=propose');
  await preview.locator('#proposal[data-pilot-context-active]').waitFor();
  assert.equal(await preview.locator('#later-proposal[data-pilot-context-active]').count(), 0);
  await preview.goto(origin + '/pilot/step-7/sick-leave?context=' + encodeURIComponent(longContext));
  await comments.getByText('Long matching comment').waitFor();
  assert.equal(await comments.getByText('Long different comment').isVisible(), false);
  await preview.goto(origin + '/pilot/step-3/sick-leave?context=approve');
  await preview.locator('#proposal[data-pilot-context-active]').waitFor();
  assert.equal(await comments.getByRole('combobox', {name: 'Context'}).inputValue(), 'approve');
  await preview.goto(origin + '/pilot/long-' + 'x'.repeat(140) + '/step-6/sick-leave?context=confirm');
  await preview.locator('#proposal[data-pilot-context-active]').waitFor();
  assert.equal(await comments.getByRole('combobox', {name: 'Context'}).inputValue(), 'confirm');
  await preview.goto(origin + '/pilot/step-07/sick-leave?context=increase');
  await preview.getByText('This area is unavailable in the current preview.').waitFor();
  assert.equal(await preview.locator('#increase[data-pilot-context-active]').count(), 0);
  await preview.goto(origin + '/pilot/step-3/sick-leave?context=approve');
  await preview.locator('#proposal[data-pilot-context-active]').waitFor();
  await preview.addInitScript(() => {
    if (sessionStorage.getItem('encounter-preview-rollback') === '1') window.WebAssembly = undefined;
  });
  await preview.evaluate(() => sessionStorage.setItem('encounter-preview-rollback', '1'));
  await preview.reload();
  await preview.getByText('This release requires WebAssembly to select preview areas.', {exact: true}).waitFor();
  assert.equal(await picker.isHidden(), true);

  const compatibilityConfig = gatewayLaunch.split('\n').filter(line => !line.startsWith('("preview-client",')).join('\n');
  const compatibilityAsset = await restartPreviewGateway(compatibilityConfig, previousRuntime);
  assert.equal(compatibilityAsset.status, 200);
  assert.equal(compatibilityAsset.receipt, undefined);
  assert(compatibilityAsset.body.includes('const encounterLegacyPreview ='));
  previewScript = compatibilityAsset.body;
  await preview.reload();
  await preview.locator('#proposal[data-pilot-context-active]').waitFor();
  assert.equal(await comments.getByRole('combobox', {name: 'Context'}).inputValue(), 'approve');
  if (previousPackage) {
    const previousDirectory = join(stage, 'previous-preview');
    const previousPin = await copyClientBundle(sources, 'preview', previousDirectory, previousPackage);
    const previousModule = await readFile(join(previousDirectory, 'browser.wasm'));
    const previousConfig = gatewayLaunch.replace('"directory", "preview"', '"directory", "previous-preview"')
      .replace(previewPin, previousPin);
    const previous = await restartPreviewGateway(previousConfig, previousRuntime);
    assert.equal(previous.status, 200);
    assert.equal(previous.receipt, previousPin);
    assert(previous.body.includes(`const encounterPreviewWasm = '${previousModule.toString('base64')}';`));
    assert(!previous.body.includes('encounterLegacyPreview'));
    previewScript = previous.body;
    await preview.evaluate(() => sessionStorage.removeItem('encounter-preview-rollback'));
    await preview.reload();
    await preview.locator('#proposal[data-pilot-context-active]').waitFor();
    assert.equal(await comments.getByRole('combobox', {name: 'Context'}).inputValue(), 'approve');
    assert((await preview.evaluate(() => window.wasmCalls.selectionView)) > 0);
    console.log('PASS: Preview kept the selected context with the retained Wasm package');
  }
  await writeFile(join(previewDirectory, 'browser.wasm'), previewModule);
  const restored = await restartPreviewGateway(gatewayLaunch);
  assert.deepEqual(restored, asset);
  previewScript = restored.body;
  await preview.evaluate(() => sessionStorage.removeItem('encounter-preview-rollback'));
  await preview.reload();
  await preview.locator('#proposal[data-pilot-context-active]').waitFor();
  assert.equal(await comments.getByRole('combobox', {name: 'Context'}).inputValue(), 'approve');
  assert((await preview.evaluate(() => window.wasmCalls.selectionView)) > 0);
  console.log('PASS: Preview selected the same context during rollback and after restoring its pinned Wasm');
}

try {
  verifyCompilationPolicyCheck();
  await exerciseClients();
  await checkPackagedRuntime(packagePath, encounter, candidateReceipt);
  await checkPackagedRuntime(previousPackage, previousRuntime, previousReceipt);
  if (!cspPreflight && candidateReceipt && previousReceipt) {
    console.log('PASS: Standalone rollback package receipts candidate=' + candidateReceipt + ' previous=' + previousReceipt);
  }
} finally {
  await browser?.close();
  for (const process of [gateway, previousHost, legacyHost, host]) {
    if (!process || process.exitCode !== null || process.signalCode !== null) continue;
    const stopped = once(process, 'exit');
    process.kill('SIGTERM');
    await stopped;
  }
  await rm(stage, {recursive: true, force: true});
}
