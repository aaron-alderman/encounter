import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from '../../../bin/browser-profile.mjs';

const binary = resolve(process.argv[2]);
const root = await mkdtemp(join(process.env.TMPDIR || '/tmp', 'encounter-policy-'));
const app = join(root, 'app');
const assets = join(root, 'assets');
let host;
let browser;

function invoke(...args) {
  const result = spawnSync(binary, args, { encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  return result;
}

function refuses(message, ...args) {
  const result = invoke(...args);
  assert.notEqual(result.status, 0, args.join(' '));
  assert.match(result.stderr, message);
}

function declaration(grant) {
  return [
    '("application", "stateProfile", "encounter/test-package-policy/1")',
    '("application", "module", "app.encounter")',
    '("application", "entry", "browser.boot")',
    '("application", "entry", "test.event")',
    ...['browser.request', 'browser.content', 'browser.write', ...grant]
      .map(port => '("application", "grant", "' + port + '")'),
  ].join('\n') + '\n';
}

const thread = '1'.repeat(32);
const token = 'a'.repeat(process.argv[3] === 'native' ? 64 : 43);
const route = '/workspace/aster/events?thread=' + thread;

try {
  await mkdir(app);
  await mkdir(assets);
  await writeFile(join(assets, 'index.html'), '<!doctype html><div id="aster-content"></div>' +
    '<output id="result"></output><script type="module" src="/_encounter/browser.mjs"></script>');
  await writeFile(join(app, 'application.rel'), declaration(['browser.asterStream']));
  await writeFile(join(app, 'app.encounter'), 'process-module "temple/surface-process-module/1"\n\n' +
    'process browser.boot:\n' +
    '  port browser.asterStream { query = "test.event" } → _\n' +
    '  port browser.request { path = "/identity-management/aster/"; fragment = "[data-notes-content=aster]" } → response\n' +
    '  port browser.content { ref = "#aster-content"; html = $response.body } → _\n' +
    '  let result = true\n\n' +
    'process test.event:\n' +
    '  let text = if(eq($eventInput.event.type, "stream-error"), "Stream unavailable", $eventInput.event.data.text)\n' +
    '  port browser.write { ref = "#result"; name = "textContent"; value = $text } → _\n' +
    '  let result = true\n');

  assert.equal(invoke('check-package', app).status, 0);
  const native = join(root, 'native');
  await mkdir(native);
  await writeFile(join(native, 'application.rel'),
    '("application", "stateProfile", "encounter/test-clean-package/1")\n' +
    '("application", "module", "run.encounter")\n' +
    '("application", "entry", "main")\n');
  await writeFile(join(native, 'run.encounter'),
    'process-module "temple/surface-process-module/1"\n\nprocess main:\n  let result = true\n');
  const image = join(root, 'clean.rel');
  assert.equal(invoke('build', native, 'application.rel', image).status, 0);
  await mkdir(join(native, 'nested'));
  await writeFile(join(native, 'nested', 'unreferenced.JSON'), '{}');
  refuses(/forbidden file/, 'build', native, 'application.rel', join(root, 'blocked.rel'));
  await rm(join(native, 'nested'), {recursive: true});
  await writeFile(join(root, 'extra.py'), '');
  refuses(/forbidden file/, 'serve', '--image', image, 'unverified', join(root, 'store'), '0');
  await rm(join(root, 'extra.py'));


  for (const ext of ['json', 'mjs', 'py', 'RS']) {
    const forbidden = join(app, 'unreferenced.' + ext);
    await writeFile(forbidden, '');
    refuses(/application package contains forbidden file/, 'check-package', app);
    refuses(/application package contains forbidden file/, 'build', app, 'application.rel', join(root, 'out.rel'));
    refuses(/application package contains forbidden file/, 'browser-host', app, 'application.rel', assets, '0');
    await rm(forbidden);
  }
  const symlinkPath = join(app, 'linked.rel');
  await symlink(join(app, 'application.rel'), symlinkPath);
  refuses(/must be a regular file/, 'check-package', app);
  await rm(symlinkPath);

  await writeFile(join(assets, 'shim.mjs'), '');
  refuses(/forbidden file/, 'browser-host', '--allow-aster-stream', app, 'application.rel', assets, '0');
  refuses(/forbidden file/, 'browser-host', '--release', assets, 'unverified', '0');
  refuses(/forbidden file/, 'publication', assets, '0');
  await rm(join(assets, 'shim.mjs'));

  refuses(/requires operator approval/, 'browser-host', app, 'application.rel', assets, '0');
  await writeFile(join(app, 'application.rel'), declaration([]));
  refuses(/port not granted/, 'browser-host', '--allow-aster-stream', app, 'application.rel', assets, '0');
  await writeFile(join(app, 'application.rel'), declaration(['browser.asterStream']));

  host = spawn(binary, ['browser-host', '--allow-aster-stream', app, 'application.rel', assets, '0']);
  host.stderr.pipe(process.stderr);
  const lines = createInterface({input: host.stdout});
  const origin = await Promise.race([
    once(lines, 'line').then(([line]) => line.replace(/^Encounter /, '')),
    once(host, 'exit').then(() => { throw new Error('Browser host exited before listening'); }),
  ]);
  lines.close();
  const bridge = await fetch(origin + '/_encounter/browser.mjs');
  assert.equal(bridge.status, 200);
  const bridgeSource = await bridge.text();
  assert.match(bridgeSource, /const encounterLegacyInteraction/);
  assert.doesNotMatch(bridgeSource, /const encounterLegacy(?:Countdown|Assurance)/);

  browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  for (const {wasm, exhaust} of [{wasm: false, exhaust: false}, {wasm: true, exhaust: false}, {wasm: true, exhaust: true}]) {
    const page = await browser.newPage({bypassCSP: wasm});
    try {
      if (wasm) {
        await page.addInitScript(() => {
          const names = ['asterAttempt', 'asterRetryDelay', 'asterResponse', 'asterBuffer',
            'asterFrameKind', 'asterDispatchFrame', 'asterWatchAction', 'transportLimits'];
          const calls = window.asterPolicyCalls = Object.fromEntries(names.map(name => [name, 0]));
          WebAssembly.Instance = new Proxy(WebAssembly.Instance, {
            construct(Instance, args) {
              const instance = new Instance(...args);
              if (names.every(name => typeof instance.exports[name] === 'function')) {
                const exports = instance.exports;
                Object.defineProperty(instance, 'exports', {value: {...exports, ...Object.fromEntries(names.map(name =>
                  [name, (...input) => { calls[name]++; return exports[name](...input); }]))}});
              }
              return instance;
            },
          });
        });
      } else {
        await page.addInitScript(() => { window.WebAssembly = undefined; });
      }
      let requests = 0;
      await page.route('**/identity-management/aster/', request => request.fulfill({
        contentType: 'text/html',
        body: '<div data-notes-content="aster"><div id="aster-live" data-thread="' + thread +
          '" data-stream-path="/unapproved" data-stream-bearer="' + token + '"></div></div>',
      }));
      await page.route('**/workspace/aster/events?*', async request => {
        requests++;
        assert.equal(request.request().url(), origin + route);
        assert.equal(request.request().headers().authorization, 'Bearer ' + token);
        if (requests === 1) return request.fulfill({contentType: 'text/plain', body: 'Not a stream'});
        if (requests === 2) {
          return request.fulfill({contentType: 'text/event-stream',
            body: 'event: done\ndata: ' + JSON.stringify({thread: 'b'.repeat(32), text: 'Wrong thread'}) + '\n\n'});
        }
        if (exhaust) {
          return request.fulfill({contentType: 'text/event-stream', body: 'x'.repeat(131_073)});
        }
        return request.fulfill({
          contentType: 'text/event-stream',
          body: 'event: ignored\ndata: invalid-json\n\nevent: done\ndata: ' +
            JSON.stringify({thread, text: 'Scoped Aster reply'}) + '\n\n',
        });
      });
      await page.goto(origin);
      await page.waitForFunction(expected => document.querySelector('#result').textContent === expected,
        exhaust ? 'Stream unavailable' : 'Scoped Aster reply');
      assert.equal(requests, 3);
      assert.equal(await page.locator('[data-stream-bearer], [data-stream-path]').count(), 0);
      assert.doesNotMatch(await page.content(), new RegExp(token));
      if (wasm) assert(Object.values(await page.evaluate(() => window.asterPolicyCalls)).every(count => count > 0));
    } finally {
      await page.context().close();
    }
  }
  console.log('Package refusals, fixed Aster stream route, bounded retries, thread admission, and credential isolation passed.');
} finally {
  await browser?.close();
  if (host?.exitCode === null) {
    const exited = once(host, 'exit');
    host.kill();
    await exited;
  }
  await rm(root, {recursive: true, force: true});
}
