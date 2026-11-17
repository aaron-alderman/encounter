import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { appendFile, cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '../../../bin/browser-profile.mjs';

const executable = resolve(process.argv[2]);
const example = fileURLToPath(new URL('../examples/browser/', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'encounter-browser-'));
const app = join(temp, 'application');
const source = 'process-module "temple/surface-process-module/1"\n\nprocess run:\n  let result = concat("Replayed ", $eventInput)\n';
let host;
let browser;

async function start(port) {
  host = spawn(executable, ['browser-host', '--allow-aster-stream', app, 'application.rel', join(app, 'assets'), String(port)]);
  host.stderr.pipe(process.stderr);
  const lines = createInterface({input: host.stdout});
  const origin = await Promise.race([
    once(lines, 'line').then(([line]) => line.replace(/^Encounter /, '')),
    once(host, 'exit').then(() => { throw new Error('Browser host exited before listening'); }),
  ]);
  lines.close();
  return origin;
}

async function stop() {
  if (host?.exitCode === null && host.signalCode === null) {
    const stopped = once(host, 'exit');
    host.stdin.end('close\n');
    await stopped;
  }
}

async function load(page, url) {
  await page.goto(url);
  await page.waitForFunction(() => document.documentElement.dataset.encounter === 'ready');
  assert.equal(await page.locator('[data-temple-errors]').textContent(), '');
}

async function textIs(page, selector, text) {
  await page.waitForFunction(({selector, text}) => document.querySelector(selector)?.textContent === text, {selector, text});
}

try {
  await cp(example, app, {recursive: true});
  await appendFile(join(app, 'application.rel'), [
    '',
    '("application", "entry", "workspace.openPopover")',
    '("application", "entry", "workspace.openDialog")',
    '("application", "entry", "workspace.observedEvent")',
    '("application", "entry", "workspace.batchFixture")',
    '("application", "grant", "browser.batch")',
    '("application", "entry", "workspace.loadStream")',
    '("application", "entry", "workspace.streamEvent")',
    '("application", "entry", "workspace.requestFixture")',
    '("application", "grant", "browser.request")',
    '("application", "grant", "browser.content")',
    '("application", "grant", "browser.asterStream")',
    '("application", "grant", "browser.appDescriptions")',
    '("application", "grant", "browser.popover")',
    '("application", "grant", "browser.dialog")',
    '',
  ].join('\n'));
  const programme = join(app, 'workspace.encounter');
  await writeFile(programme, (await readFile(programme, 'utf8')).replace('  let result = true', [
    '  port browser.on { ref = "#popover-trigger"; event = "click"; query = "workspace.openPopover" } → _',
    '  port browser.on { ref = "#dialog-trigger"; event = "click"; query = "workspace.openDialog" } → _',
    '  port browser.on { ref = "#event-fixture"; event = "click"; delegate = "[data-test-click]"; outside = "[data-excluded]"; unmodified = true; preventDefault = true; query = "workspace.observedEvent" } → _',
    '  port browser.on { ref = "#event-fixture"; event = "keydown"; delegate = "[data-test-key]"; preventKeys = list("F10"); query = "workspace.observedEvent" } → _',
    '  port browser.on { ref = "#batch-trigger"; event = "click"; query = "workspace.batchFixture" } → _',
    '  port browser.on { ref = "#aster-trigger"; event = "click"; query = "workspace.loadStream" } → _',
    '  port browser.asterStream { query = "workspace.streamEvent" } → _',
    '  port browser.on { ref = "#request-trigger"; event = "click"; query = "workspace.requestFixture" } → _',
    '  port browser.appDescriptions { ref = "#description-fixture" } → _',
    '  let result = true',
  ].join('\n')) + [
    '',
    'process workspace.openPopover:',
    '  port browser.popover { ref = "#example-popover"; open = true; position = { anchor = "#popover-trigger" } } → result',
    '',
    'process workspace.openDialog:',
    '  port browser.dialog { ref = "#example-dialog"; open = true; position = { x = 900; y = 900 } } → result',
    '',
    'process workspace.observedEvent:',
    '  port browser.write { ref = "#event-result"; name = "textContent"; value = concat($eventInput.event.type, ":", $eventInput.event.key) } → result',
    '',
    'process workspace.batchFixture:',
    '  let target = "#batch-result"',
    '  let start = { port = "dom.exists"; args = { selector = "#batch-trigger" }; save = "present" }',
    '  let missing = { port = "dom.exists"; args = { selector = "#batch-missing" }; save = "absent" }',
    '  let skip = { port = "browser.write"; args = { ref = $target; name = "textContent"; value = "skipped write" }; unless = "present" }',
    '  let write = { port = "browser.write"; args = { ref = $target; name = "textContent"; value = "valid batch" }; unless = "absent" }',
    '  port browser.batch { steps = list($start, $missing, $write, $skip) } → observations',
    '  assert and($observations.present, not($observations.absent))',
    '    otherwise "Unexpected batch observations"',
    '  let partial = { port = "browser.write"; args = { ref = $target; name = "textContent"; value = "partial batch" } }',
    '  try:',
    '    port browser.batch { steps = list($partial, { port = "browser.dialog"; args = { ref = "#example-dialog"; open = true } }) } → _',
    '  catch fault:',
    '    port browser.write { ref = "#batch-refusal"; name = "textContent"; value = "port refused" } → _',
    '  try:',
    '    port browser.batch { steps = list($partial, $start, $start) } → _',
    '  catch fault:',
    '    port browser.write { ref = "#batch-observation"; name = "textContent"; value = "duplicate refused" } → _',
    '  let result = true',
    '',
    'process workspace.loadStream:',
    '  port browser.request { path = "/identity-management/aster/" } → page',
    '  port browser.content { ref = "#aster-content"; html = $page.body } → result',
    '',
    'process workspace.streamEvent:',
    '  port browser.write { ref = "#aster-result"; name = "textContent"; value = concat($eventInput.event.type, ":", $eventInput.event.name) } → result',
    '',
    'process workspace.requestFixture:',
    '  port browser.request { path = "/request-fixture?discard=yes"; form = "#request-form"; query = { override = "query" }; fragment = "#response-marker" } → reply',
    '  port browser.content { ref = "#request-result"; html = $reply.body } → _',
    '  try:',
    '    port browser.request { path = "/request-fixture"; method = "POST"; form = "#large-form" } → _',
    '  catch fault:',
    '    port browser.write { ref = "#form-refused"; name = "textContent"; value = "large form refused" } → _',
    '  try:',
    '    port browser.request { path = "/request-fixture"; query = { a = "1"; b = "2"; c = "3"; d = "4"; e = "5"; f = "6"; g = "7"; h = "8"; i = "9" } } → _',
    '  catch fault:',
    '    port browser.write { ref = "#query-refused"; name = "textContent"; value = "large query refused" } → _',
    '  try:',
    '    port browser.request { path = "/workspace/aster/events" } → _',
    '  catch fault:',
    '    port browser.write { ref = "#stream-refused"; name = "textContent"; value = "direct stream refused" } → _',
    '  let result = true',
    '',
  ].join('\n'));
  await appendFile(join(app, 'assets/index.html'), [
    '<button id="popover-trigger">Open anchored popover</button>',
    '<div id="example-popover" popover="auto">Popover</div>',
    '<button id="dialog-trigger">Open viewport dialog</button>',
    '<dialog id="example-dialog"><form method="dialog"><button>Close dialog</button></form></dialog>',
    '<section id="event-fixture"><button id="click-target" data-test-click>Click fixture</button>',
    '<div data-excluded><button id="excluded-target" data-test-click>Excluded click</button></div>',
    '<button id="key-target" data-test-key>Key fixture</button><output id="event-result"></output></section>',
    '<button id="batch-trigger">Run batch fixture</button><output id="batch-result"></output>',
    '<output id="batch-refusal"></output><output id="batch-observation"></output>',
    '<button id="aster-trigger">Load stream fixture</button><div id="aster-content"></div><output id="aster-result"></output>',
    '<button id="request-trigger">Run request fixture</button><div id="request-result"></div>',
    '<form id="request-form"><input name="field" value="form value"><input name="override" value="original"></form>',
    '<form id="large-form"><input name="large"></form>',
    '<output id="form-refused"></output><output id="query-refused"></output><output id="stream-refused"></output>',
    '<section id="description-fixture"><article data-app-card><a class="app-link" href="#">',
    '<span class="app-card-summary">Description with enough words to overflow a narrow summary</span></a>',
    '<button class="app-card-description-button" popovertarget="example-description" hidden>About this app</button>',
    '<div class="app-card-description-panel" id="example-description" popover="auto">App description</div>',
    '</article></section>',
  ].join('\n'));
  const origin = await start(0);
  const port = Number(new URL(origin).port);
  const wrongOrigin = await fetch(origin + '/_encounter/browser', {headers: {Origin: 'https://elsewhere.invalid'}});
  assert.equal(wrongOrigin.status, 403);
  browser = await chromium.launch({headless: true});
  for (const wasm of [true, false]) {
    const overlayPage = await browser.newPage({bypassCSP: wasm, viewport: {width: 500, height: 400}});
    const events = [];
    overlayPage.on('websocket', socket => socket.on('framesent', ({payload}) => {
      const message = JSON.parse(payload.toString());
      if (message.event) events.push(message.event);
    }));
    try {
      await overlayPage.addInitScript(wasm => {
        if (!wasm) { window.WebAssembly = undefined; return; }
        window.policyCalls = {overlayPlacement: 0, eventAdmission: 0, batchLength: 0, batchPort: 0, batchStep: 0,
          batchExecute: 0, asterCredential: 0, asterBuffer: 0, asterDispatchFrame: 0, asterQueueAction: 0,
          descriptionTransition: 0, descriptionLayout: 0, requestRoute: 0, requestForm: 0, requestQuery: 0,
          queryField: 0, requestResponse: 0, requestBearer: 0};
        WebAssembly.Instance = new Proxy(WebAssembly.Instance, {
          construct(Instance, args) {
            const instance = new Instance(...args);
            const exports = instance.exports;
            if (typeof exports.overlayPlacement === 'function') {
              const observed = Object.fromEntries(Object.keys(window.policyCalls).map(name => [name, (...input) => {
                window.policyCalls[name]++;
                return exports[name](...input);
              }]));
              Object.defineProperty(instance, 'exports', {value: {...exports, ...observed}});
            }
            return instance;
          },
        });
      }, wasm);
      await load(overlayPage, origin);
      await overlayPage.evaluate(() => {
        Object.assign(document.querySelector('#popover-trigger').style,
          {position: 'fixed', left: '420px', top: '365px', width: '72px', height: '24px', overflow: 'hidden'});
        Object.assign(document.querySelector('#example-popover').style, {width: '100px', height: '60px'});
        Object.assign(document.querySelector('#example-dialog').style, {width: '120px', height: '70px'});
      });
      const trigger = overlayPage.locator('#popover-trigger');
      const popover = overlayPage.locator('#example-popover:popover-open');
      const dialog = overlayPage.locator('#example-dialog');
      const original = await dialog.getAttribute('style');
      await trigger.click();
      await popover.waitFor();
      const anchor = await trigger.boundingBox();
      const menu = await popover.boundingBox();
      assert.equal(menu.y + menu.height, anchor.y);
      assert.equal(menu.x + menu.width, 492);
      await overlayPage.keyboard.press('Escape');
      await popover.waitFor({state: 'hidden'});
      await overlayPage.locator('#dialog-trigger').click();
      await dialog.waitFor();
      const box = await dialog.boundingBox();
      assert.equal(box.x + box.width, 492);
      assert.equal(box.y + box.height, 392);
      await dialog.getByRole('button', {name: 'Close dialog'}).click();
      await overlayPage.waitForFunction(style => document.querySelector('#example-dialog').getAttribute('style') === style, original);
      const observedBefore = events.length;
      const defaults = await overlayPage.evaluate(() => {
        const click = (id, options = {}) => {
          const event = new MouseEvent('click', {bubbles: true, cancelable: true, ...options});
          document.getElementById(id).dispatchEvent(event);
          return event.defaultPrevented;
        };
        const key = key => {
          const event = new KeyboardEvent('keydown', {key, bubbles: true, cancelable: true});
          document.getElementById('key-target').dispatchEvent(event);
          return event.defaultPrevented;
        };
        return [click('excluded-target'), click('click-target', {ctrlKey: true}), click('click-target', {button: 1}),
          click('key-target'), click('click-target'), key('F10'), key('x')];
      });
      assert.deepEqual(defaults, [false, false, false, false, true, true, false]);
      await textIs(overlayPage, '#event-result', 'keydown:x');
      assert.deepEqual(events.slice(observedBefore).map(({type, key}) => [type, key]),
        [['click', ''], ['keydown', 'F10'], ['keydown', 'x']]);
      await overlayPage.locator('#batch-trigger').click();
      await textIs(overlayPage, '#batch-observation', 'duplicate refused');
      assert.equal(await overlayPage.locator('#batch-refusal').textContent(), 'port refused');
      assert.equal(await overlayPage.locator('#batch-result').textContent(), 'valid batch');
      assert(await dialog.isHidden());
      const thread = 'a'.repeat(32);
      const bearer = 'b'.repeat(43);
      let validWatch = false;
      let attempts = 0;
      await overlayPage.route(origin + '/identity-management/aster/', route => route.fulfill({
        contentType: 'text/html',
        body: '<section data-notes-content="aster"><div id="aster-live" data-thread="' + thread +
          '" data-stream-bearer="' + (validWatch ? bearer : bearer.slice(1)) +
          '" data-stream-path="/workspace/aster/events">' + (validWatch ? 'Valid watch' : 'Invalid watch') + '</div></section>',
      }));
      await overlayPage.route(url => url.pathname === '/workspace/aster/events', async route => {
        assert.equal(new URL(route.request().url()).searchParams.get('thread'), thread);
        assert.equal((await route.request().allHeaders()).authorization, 'Bearer ' + bearer);
        attempts++;
        const bodies = [
          'event: update\ndata: ' + 'x'.repeat(131_100) + '\n\n',
          'event: update\ndata: {"thread":"different"}\n\n',
          'event: ignored\ndata: invalid json\n\nevent: done\ndata: ' + JSON.stringify({thread}) + '\n\n',
        ];
        return route.fulfill({contentType: 'text/event-stream', body: bodies[attempts - 1]});
      });
      await overlayPage.locator('#aster-trigger').click();
      await textIs(overlayPage, '#aster-live', 'Invalid watch');
      assert.equal(attempts, 0);
      validWatch = true;
      await overlayPage.locator('#aster-trigger').click();
      await textIs(overlayPage, '#aster-result', 'stream:done');
      assert.equal(attempts, 3);
      assert.equal(await overlayPage.locator('#aster-live').getAttribute('data-stream-bearer'), null);
      assert.equal(await overlayPage.locator('#aster-live').getAttribute('data-stream-path'), null);
      assert.deepEqual(events.filter(event => event.type.startsWith('stream')).map(event => event.name), ['done']);
      const summary = overlayPage.locator('#description-fixture .app-card-summary');
      const details = overlayPage.getByRole('button', {name: 'About this app'});
      const description = overlayPage.locator('#example-description');
      await summary.evaluate(element => Object.assign(element.style,
        {display: 'block', width: '60px', height: '18px', overflow: 'hidden'}));
      await details.waitFor();
      await details.dispatchEvent('pointerenter', {pointerType: 'touch'});
      await overlayPage.waitForTimeout(220);
      assert(await description.isHidden());
      await details.dispatchEvent('pointerenter', {pointerType: 'mouse'});
      await description.waitFor();
      await details.dispatchEvent('pointerleave', {pointerType: 'mouse'});
      await description.waitFor({state: 'hidden'});
      await details.dispatchEvent('pointerenter', {pointerType: 'mouse'});
      await description.waitFor();
      await details.evaluate(button => button.click());
      await details.dispatchEvent('pointerleave', {pointerType: 'mouse'});
      await overlayPage.waitForTimeout(220);
      assert(await description.isVisible());
      await details.evaluate(button => button.click());
      await description.waitFor({state: 'hidden'});
      await details.dispatchEvent('pointerenter', {pointerType: 'mouse'});
      await description.waitFor();
      await summary.evaluate(element => { element.style.height = 'auto'; });
      await details.waitFor({state: 'hidden'});
      assert(await description.isHidden());
      const requests = [];
      await overlayPage.route(url => url.pathname === '/request-fixture', route => {
        requests.push({method: route.request().method(), query: Object.fromEntries(new URL(route.request().url()).searchParams)});
        return route.fulfill({contentType: 'text/html', body: '<p>Omitted response</p><p id="response-marker">Selected response</p>'});
      });
      await overlayPage.locator('#large-form input').evaluate(input => { input.value = 'x'.repeat(16385); });
      await overlayPage.locator('#request-trigger').click();
      await textIs(overlayPage, '#stream-refused', 'direct stream refused');
      assert.equal(await overlayPage.locator('#form-refused').textContent(), 'large form refused');
      assert.equal(await overlayPage.locator('#query-refused').textContent(), 'large query refused');
      assert.equal(await overlayPage.locator('#request-result').textContent(), 'Selected response');
      assert.deepEqual(requests, [{method: 'GET', query: {field: 'form value', override: 'query'}}]);
      if (wasm) {
        const calls = await overlayPage.evaluate(() => window.policyCalls);
        assert.equal(calls.overlayPlacement, 2);
        assert(calls.eventAdmission >= defaults.length);
        assert(calls.batchLength >= 3 && calls.batchPort >= 9 && calls.batchStep >= 9 && calls.batchExecute === 4);
        assert(calls.asterCredential >= 2 && calls.asterBuffer >= 4 && calls.asterDispatchFrame === 2 && calls.asterQueueAction === 1);
        assert(calls.descriptionTransition >= 8 && calls.descriptionLayout >= 2);
        assert(calls.requestRoute >= 4 && calls.requestForm >= 2 && calls.requestQuery >= 2 &&
          calls.queryField > 0 && calls.requestResponse > 0 && calls.requestBearer > 0);
      }
    } finally {
      await overlayPage.context().close();
    }
  }
  console.log('PASS anchored popover, viewport dialog, and style restoration in Wasm and compatibility modes');
  console.log('PASS delegated event admission and keyboard default handling in Wasm and compatibility modes');
  console.log('PASS ordered browser batches evaluated guards and refused invalid steps before any writes');
  console.log('PASS Aster refused an invalid watch, retried oversized and mismatched frames, and delivered the terminal event');
  console.log('PASS app descriptions opened on mouse hover, pinned on click, and closed when the summary fit');
  console.log('PASS request admission preserved form serialization and response fragments, and refused oversized or unscoped requests');
  const context = await browser.newContext();
  const page = await context.newPage();
  await load(page, origin);
  await page.getByLabel('Encounter source').fill(source);
  await page.getByRole('button', {name: 'Save and run'}).click();
  await textIs(page, '#output', 'Replayed saved work');
  await page.waitForFunction(key => localStorage.getItem(key) !== null, 'encounter.example.source');
  assert.equal(await page.evaluate(() => localStorage.getItem('encounter.example.source')), source);
  const ticket = await page.locator('#ticket').textContent();
  assert.match(ticket, /^[a-f0-9]{48}$/);
  await page.getByRole('button', {name: 'Check admission'}).click();
  await textIs(page, '#output', 'Replayed current session');

  await page.getByRole('button', {name: 'Check raw model'}).click();
  await textIs(page, '[data-temple-errors]', 'EC-CHILD: Expected an admission ticket and optional input.');

  // The other tab shares the saved source. Its admitted child has a different ticket.
  const tab = await context.newPage();
  await load(tab, origin);
  await textIs(tab, '#output', 'Replayed saved work');
  assert.notEqual(await tab.locator('#ticket').textContent(), ticket);
  await tab.locator('#admission').fill(ticket);
  await tab.getByRole('button', {name: 'Check admission'}).click();
  await textIs(tab, '[data-temple-errors]', 'EC-CHILD: Child has no preparation admission in this browser session.');
  await tab.close();

  await page.locator('#admission').fill('fabricated');
  await page.getByRole('button', {name: 'Check admission'}).click();
  await textIs(page, '[data-temple-errors]', 'EC-CHILD: Child has no preparation admission in this browser session.');
  await page.getByLabel('Encounter source').fill(
    'process-module "temple/surface-process-module/1"\n\nprocess run:\n  port storage.read { key = "secret" } → result\n');
  await page.getByRole('button', {name: 'Save and run'}).click();
  await textIs(page, '[data-temple-errors]', 'run: port not granted: storage.read');
  assert.equal(await page.evaluate(() => localStorage.getItem('encounter.example.source')), source);
  console.log('PASS delegated DOM events, local storage, tab isolation, raw model, forged ticket and child storage refusals');

  await stop();
  await start(port);
  await load(page, origin);
  assert.equal(await page.getByLabel('Encounter source').inputValue(), source);
  await textIs(page, '#output', 'Replayed saved work');
  assert.notEqual(await page.locator('#ticket').textContent(), ticket);
  await page.locator('#admission').fill(ticket);
  await page.getByRole('button', {name: 'Check admission'}).click();
  await textIs(page, '[data-temple-errors]', 'EC-CHILD: Child has no preparation admission in this browser session.');
  console.log('PASS saved source replay after native restart and stale ticket refusal');
} finally {
  await browser?.close();
  await stop();
  await rm(temp, {recursive: true, force: true});
}
