'use strict';

const { execFileSync, spawn, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { once } = require('node:events');
const { copyFile, mkdir, mkdtemp, readFile, rm, stat } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { createInterface } = require('node:readline');
const { backup, DatabaseSync } = require('node:sqlite');
const { decode, parse } = require('../../encounter/bootstrap/rel-values.cjs');
const { createRunner, main } = require('./runner.cjs');
const { createOperators } = require('./operators.cjs');
const { imageLaunchArgs } = require('./host.cjs');
const { locate } = require('./locator.cjs');

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hashFile = async file => digest(await readFile(file));
const env = { PATH: '/nonexistent' };

async function optionalStat(file) {
  try { return await stat(file); } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function run() {
  const args = process.argv.slice(2);
  const flags = args.filter(arg => arg.startsWith('--'));
  const paths = args.filter(arg => !arg.startsWith('--'));
  const claimipediaUpdate = flags.includes('--claimipedia-update');
  const evidenceLibrary = flags.includes('--evidence-library');
  const researchReview = flags.includes('--research-review');
  const verifiedReview = flags.includes('--verified-review');
  const packetReview = flags.includes('--packet-review');
  const leaseReview = flags.includes('--lease-review');
  const reconciliationReview = flags.includes('--reconciliation-review');
  const applyReconciliation = flags.includes('--apply-reconciliation');
  const editorsFlag = flags.find(arg => arg.startsWith('--editors-baseline='));
  const editorsBaseline = editorsFlag?.slice('--editors-baseline='.length);
  const attachmentRoot = process.env.ENCOUNTER_TEST_ATTACHMENT_ROOT;
  const [oldArchive, newArchive, liveStore] = paths;
  if (!oldArchive || !newArchive || paths.length > 3 || (claimipediaUpdate && !liveStore)
      || ((evidenceLibrary || researchReview) && !claimipediaUpdate)
      || (verifiedReview && !researchReview) || (packetReview && !verifiedReview) || (reconciliationReview && !leaseReview) || (leaseReview && (!packetReview || !attachmentRoot))
      || (editorsFlag && !editorsBaseline)
      || (applyReconciliation && !reconciliationReview)
      || flags.length !== Number(claimipediaUpdate) + Number(evidenceLibrary) + Number(researchReview) + Number(verifiedReview) + Number(packetReview) + Number(leaseReview) + Number(reconciliationReview) + Number(applyReconciliation) + Number(Boolean(editorsFlag))) {
    throw Error('Usage: node test/release.cjs OLD_ARCHIVE NEW_ARCHIVE [CLAIMIPEDIA_SQLITE] [--claimipedia-update] [--evidence-library] [--research-review] [--verified-review] [--packet-review] [--lease-review] [--reconciliation-review] [--apply-reconciliation] [--editors-baseline=LAUNCH_REL]');
  }
  const { chromium } = require(process.env.ENCOUNTER_PLAYWRIGHT);
  const scratch = await mkdtemp(path.join(tmpdir(), 'encounter-release-'));
  const file = (...parts) => path.join(scratch, ...parts);
  const executable = release => file(release, 'bin/encounter');
  const command = (release, args) => execFileSync(executable(release), args, {
    cwd: file(release), env, encoding: 'utf8',
  }).trim();
  const archives = { baseline: path.resolve(oldArchive), upgrade: path.resolve(newArchive) };
  const serverArgs = (image, directory) => ['serve', '--image', file(image.file), image.pin, file(directory), '0'];
  let browser, context, operatorContext, page, host, exited, origin;
  const operators = verifiedReview ? createOperators(scratch) : null;
  async function openPage(role) {
    await page?.close();
    await operatorContext?.close();
    operatorContext = role ? await browser.newContext({ httpCredentials: operators.credentials[role] }) : null;
    page = await (operatorContext ?? context).newPage();
    page.setDefaultTimeout(5000);
  }

  async function stop() {
    if (!host) return [0, null];
    const child = host;
    host = undefined;
    if (child.exitCode === null && child.signalCode === null) {
      child.stdin.on('error', () => {});
      child.stdin.end('close\n');
    }
    const deadline = setTimeout(() => child.kill(), 5000);
    try {
      await page?.close();
      page = undefined;
      await operatorContext?.close();
      operatorContext = undefined;
      return await exited;
    } finally {
      clearTimeout(deadline);
    }
  }

  try {
    const check = createRunner('release', ['test.release'], {
      'release.catalogue': async () => ({
        text: await readFile(path.resolve(__dirname, '../release-applications.rel'), 'utf8'),
      }),
      'release.editorsConfig': () => readFile(path.resolve(editorsBaseline), 'utf8'),
      'release.copyEditorsImage': async ({ image }) => {
        const output = 'baseline-editors.rel';
        await copyFile(path.resolve(path.dirname(path.resolve(editorsBaseline)), image), file(output));
        return output;
      },
      'release.rel': ({ text }) => parse(text),
      'release.archive': async ({ release }) => {
        const archive = archives[release];
        return { checksum: (await readFile(archive + '.sha256', 'utf8')).trim(), digest: await hashFile(archive), name: path.basename(archive) };
      },
      'release.extract': async ({ release }) => {
        const directory = file(release);
        await mkdir(directory);
        execFileSync('tar', ['-xzf', archives[release], '-C', directory, '--strip-components=1']);
        return {
          manifest: await readFile(file(release, 'release.rel'), 'utf8'),
          runtimePin: await hashFile(executable(release)),
        };
      },
      'release.fileHash': ({ release, relative }) => hashFile(file(release, relative)),
      'release.version': ({ release }) => command(release, ['--version']),
      'release.buildImage': ({ release, app, project, declaration }) => {
        const output = 'baseline-' + app + '.rel';
        const sourceRoot = path.resolve(__dirname, '../..', project);
        return { file: output, pin: command(release, ['build', sourceRoot, declaration, file(output)]) };
      },
      'release.image': async ({ file: image }) => {
        const contents = await readFile(file(image));
        const { basis, runtimeSha256, programmeSha256 } = decode(contents.toString('utf8'), 'EncounterApplicationImage');
        return { digest: digest(contents), basis, runtimeSha256, programmeSha256 };
      },
      'release.cross': async ({ release, image, directory }) => {
        const result = spawnSync(executable(release), serverArgs(image, directory), { env, encoding: 'utf8', timeout: 5000 });
        return { status: result.status, error: result.stderr, exists: Boolean(await optionalStat(file(directory))) };
      },
      'release.launch': async ({ width, height }) => {
        browser = await chromium.launch();
        context = await browser.newContext({ viewport: { width, height } });
        return true;
      },
      'release.serve': async ({ release, image, directory, authenticated }) => {
        const args = authenticated ? imageLaunchArgs({ file: file(image.file), pin: image.pin }, file(directory), { operatorFile: operators.file, attachmentRoot: leaseReview ? attachmentRoot : undefined })
          : serverArgs(image, directory);
        host = spawn(executable(release), args, {
          cwd: file(release), env, stdio: ['pipe', 'pipe', 'pipe'],
        });
        let stderr = '';
        host.stderr.on('data', chunk => { stderr += chunk; });
        exited = once(host, 'close');
        const lines = createInterface({ input: host.stdout });
        try {
          const [line] = await Promise.race([
            once(lines, 'line', { signal: AbortSignal.timeout(10000) }),
            exited.then(([status]) => { throw Error('Installed server exited ' + status + ': ' + stderr); }),
          ]);
          origin = line.slice('Encounter '.length);
          await openPage(authenticated ? "proposer" : null);
          return line;
        } finally {
          lines.close();
        }
      },
      'release.stop': stop,
      'release.operator': async ({ role }) => { await openPage(role); return true; },
      'release.open': async ({ route }) => (await page.goto(origin + route)).status(),
      'release.click': async ({ locator }) => {
        const [response] = await Promise.all([page.waitForNavigation(), locate(page, locator).click()]);
        return response.status();
      },
      'release.fill': async ({ label, value }) => { await page.getByLabel(label, { exact: true }).fill(value); return true; },
      'release.observe': ({ locator, property }) => {
        const target = locate(page, locator);
        if (property === 'count') return target.count();
        if (property === 'value') return target.inputValue();
        if (property === 'text') return target.innerText();
        if (property === 'list') return target.allTextContents();
        if (property === 'visible') return target.isVisible();
        throw Error('Unknown release browser observation: ' + property);
      },
      'release.act': async ({ locator, action, value }) => {
        const target = locate(page, locator);
        if (action === 'click') await target.click();
        else if (action === 'fill') await target.fill(value);
        else if (action === 'select') await target.selectOption(value);
        else if (action === 'check') await target.setChecked(value);
        else throw Error('Unknown release browser action: ' + action);
        return true;
      },
      'release.store': ({ directory }) => {
        const db = new DatabaseSync(file(directory, 'workspace.sqlite'), { readOnly: true });
        try {
          return {
            integrity: db.prepare('PRAGMA integrity_check').get().integrity_check,
            metadata: db.prepare('SELECT * FROM metadata ORDER BY key').all(),
            revisions: db.prepare('SELECT * FROM revisions ORDER BY id').all(),
            documents: db.prepare('SELECT * FROM documents ORDER BY revision,path').all(),
          };
        } finally {
          db.close();
        }
      },
      'release.storeHash': ({ directory }) => hashFile(file(directory, 'workspace.sqlite')),
      'release.walSize': async ({ directory }) => (await optionalStat(file(directory, 'workspace.sqlite-wal')))?.size ?? 0,
      'release.copy': async ({ from, to }) => {
        await mkdir(file(to));
        await copyFile(file(from, 'workspace.sqlite'), file(to, 'workspace.sqlite'));
        return true;
      },
      'release.backup': async ({ directory }) => {
        await mkdir(file(directory));
        const original = new DatabaseSync(path.resolve(liveStore), { readOnly: true });
        try { await backup(original, file(directory, 'workspace.sqlite')); } finally { original.close(); }
        return true;
      },
      'test.report': ({ text }) => { console.log(text); return true; },
    }, ['upgrade-workflows', 'research-editors']);
    await check('test.release', { hasSnapshot: Boolean(liveStore), claimipediaUpdate, evidenceLibrary, researchReview, verifiedReview, packetReview, leaseReview, reconciliationReview, applyReconciliation, editorsBaseline: Boolean(editorsBaseline) });
  } finally {
    try {
      await stop();
    } finally {
      await browser?.close();
      await rm(scratch, { recursive: true, force: true });
    }
  }
}

main(run);
