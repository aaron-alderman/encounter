import assert from 'node:assert/strict';
import {execFile, execFileSync, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {access, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';

const encounter = resolve(process.argv[2]);
const browser = fileURLToPath(new URL('../browser/', import.meta.url));
const bootstrap = await readFile(new URL('../src/browser_wasm_bootstrap.mjs', import.meta.url), 'utf8');
const {browserWasmText, browserWasmTextMatches, browserWasmTextResult} = await import('data:text/javascript;base64,' +
  Buffer.from(bootstrap + '\nexport {browserWasmText, browserWasmTextMatches, browserWasmTextResult};').toString('base64'));
const legacyPreviewSource = await readFile(new URL('../src/preview-context-legacy.js', import.meta.url), 'utf8');
const {encounterLegacyPreview} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyPreviewSource + '\nexport {encounterLegacyPreview};').toString('base64'));
const legacyInteractionSource = await readFile(new URL('../src/browser_interaction_legacy.mjs', import.meta.url), 'utf8');
const {encounterLegacyInteraction} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyInteractionSource + '\nexport {encounterLegacyInteraction};').toString('base64'));
const legacyCountdownSource = await readFile(new URL('../src/browser_countdown_legacy.mjs', import.meta.url), 'utf8');
const {encounterLegacyCountdown} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyCountdownSource + '\nexport {encounterLegacyCountdown};').toString('base64'));
const legacyAssuranceSource = await readFile(new URL('../src/browser_assurance_legacy.mjs', import.meta.url), 'utf8');
const {encounterLegacyAssurance} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyAssuranceSource + '\nexport {encounterLegacyAssurance};').toString('base64'));
const legacyTempleSource = await readFile(new URL('../src/workspace/temple_startup_legacy.mjs', import.meta.url), 'utf8');
const {encounterLegacyTemple} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyTempleSource + '\nexport {encounterLegacyTemple};').toString('base64'));
const legacyEventsSource = await readFile(new URL('../src/events-client-legacy.js', import.meta.url), 'utf8');
const {encounterLegacyLiveEvents} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyEventsSource + '\nexport {encounterLegacyLiveEvents};').toString('base64'));
const legacyCanvasSource = await readFile(new URL('../src/canvas-controls-legacy.js', import.meta.url), 'utf8');
const {encounterLegacyCanvasControls} = await import('data:text/javascript;base64,' +
  Buffer.from(legacyCanvasSource + '\nexport {encounterLegacyCanvasControls};').toString('base64'));
const legacyMobilePolicies = {};
for (const [file, exportName, entries] of [
  ['mobile_runtime_legacy.mjs', 'encounterLegacyMobile',
    ['tripStorage', 'pairRequest', 'pairReply', 'localRemoval', 'pilotRoute', 'pilotRead', 'pilotResult', 'draftAction', 'tripItemView', 'offlineReceipt', 'claimAction', 'invitationAdmission',
      'draftBasis', 'draftSaveAdmission', 'draftSaveState', 'pilotSubmit', 'workerStartup', 'resumePairing', 'receiptReply',
      'refreshIntervals', 'removalMessages', 'snapshotInput', 'snapshotIntegrity', 'snapshotAdmission']],
  ['mobile_worker_legacy.mjs', 'encounterLegacyMobileWorker', ['shellPaths', 'offlineMarkers', 'shellUnavailable', 'shellPolicyMatches',
    'shellCacheRefresh', 'shellCacheKey', 'retiredShellCache']],
]) {
  const source = await readFile(new URL('../src/workspace/' + file, import.meta.url), 'utf8');
  const module = await import('data:text/javascript;base64,' +
    Buffer.from(source + '\nexport {' + exportName + '};').toString('base64'));
  for (const entry of entries) legacyMobilePolicies[entry] = module[exportName][entry].bind(module[exportName]);
}
const stage = await mkdtemp(join(tmpdir(), 'encounter-wasm-'));
const application = join(stage, 'native');

function run(...args) {
  return execFileSync(encounter, args, {encoding: 'utf8', timeout: 10_000}).trim();
}

const fixtures = {
  'aster-frame': {
    messageTypes: [[], [[]], ['protocol', 'request', 'snapshot', 'changed']],
    bridgeRole: [['nested', 'parentDeclared', 'hostDeclared'], [
      [false, false, false], [false, false, true], [true, false, true], [true, true, false], [true, true, true],
    ]],
    adapterAllowed: [['adapter'], ['', 'a', '0', 'a-9', 'a'.repeat(64), 'a'.repeat(65), '-demo', 'Demo', 'demo\n'].map(value => [value])],
    nonceAllowed: [['nonce'], ['a'.repeat(31), 'a'.repeat(32), 'a'.repeat(33), 'A'.repeat(32), 'a'.repeat(31) + 'ø'].map(value => [value])],
    markerPlan: [['adapterMatches', 'length', 'label', 'labelLength', 'value', 'valueLength', 'providedLength'], [
      [true, 0, 'Page', 'Work · review', 2], [true, 148, 'L'.repeat(32), 'V'.repeat(96), 2],
      [true, 149, 'L'.repeat(32), 'V'.repeat(96), 2], [true, 0, 'L'.repeat(33), 'V'.repeat(96), 9],
      [true, 0, 'L'.repeat(32), 'V'.repeat(97), 9], [true, 0, 'Bad!', 'Work · review', 9],
      [true, 0, 'Page', 'Work 🧪', 9], [true, 20, '', '', 259], [true, 20, '', '', 260],
      [true, 0, '', '', 0], [false, 0, 'Page', 'Work · review', 9],
    ].map(([matches, length, label, value, provided]) => [matches, length, label, label.length, value, value.length, provided]),
    ['length', 'labelled', 'divider', 'ending', 'separator']],
    childRequest: [['parentMatches', 'originMatches', 'protocol', 'kind', 'adapterValid', 'nonceValid'], [
      [true, true, 'sourcery/aster-frame/1', 'request', true, true],
      [false, true, 'sourcery/aster-frame/1', 'request', true, true],
      [true, false, 'sourcery/aster-frame/1', 'request', true, true],
      [true, true, 'sourcery/aster-frame/1', 'request', true, false],
      [true, true, 'sourcery/aster-frame/2', 'request', true, true],
    ]],
    childChanged: [['hasRequest', 'summaryMatches'], [[false, false], [true, false], [true, true]]],
    summarySource: [['preferLocal', 'childReadable', 'targetIsLocal', 'directoryPath', 'documentOriginMatches',
      'documentWithinTarget', 'currentBinding'], [
      [false, false, false, false, false, false, true], [false, false, false, false, false, false, false],
      [true, true, true, true, true, true, false], [true, true, true, true, true, false, false],
      [true, true, true, false, true, true, false], [true, true, true, true, false, true, false],
    ]],
    summaryChanged: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, 0, '', ''], [130, 131, 'prefix', 'prefix'], [2, 2, '🙂', '🙃'], [2, 2, '🙂', '🙂'],
    ]],
    frameAction: [['connected', 'hasAdapter', 'tracked'], [
      [false, true, false], [true, true, true], [false, true, true], [true, false, true], [true, true, false],
    ]],
    requestChild: [['adapterValid', 'targetIsLocal', 'protocol', 'hasWindow'], [
      [true, false, 'http:', true], [true, false, 'https:', true], [false, false, 'https:', true],
      [true, true, 'http:', true], [true, false, 'data:', true], [true, false, 'https:', false],
    ]],
    hostMessage: [['frameConnected', 'windowMatches', 'originMatches', 'adapterMatches', 'protocol', 'kind',
      'nonceMatches', 'summaryText', 'summaryLength', 'currentBinding'], [
      [true, true, true, true, 'sourcery/aster-frame/1', 'snapshot', true, true, 280, true],
      [true, true, true, true, 'sourcery/aster-frame/1', 'snapshot', true, true, 281, true],
      [true, true, true, true, 'sourcery/aster-frame/1', 'snapshot', false, true, 20, true],
      [true, true, true, true, 'sourcery/aster-frame/1', 'changed', false, false, 0, true],
      [true, true, false, true, 'sourcery/aster-frame/1', 'snapshot', true, true, 20, true],
      [true, false, true, true, 'sourcery/aster-frame/1', 'changed', false, false, 0, true],
      [true, true, true, false, 'sourcery/aster-frame/1', 'snapshot', true, true, 20, true],
      [true, true, true, true, 'sourcery/aster-frame/1', 'snapshot', true, true, 20, false],
      [true, true, true, true, 'sourcery/aster-frame/1', 'changed', false, false, 0, false],
    ]],
  },
  canvas: {
    surfaceProfile: [[], [[]], ['width', 'height', 'alpha']],
    seaLayout: [[], [[]], ['bands', 'waves', 'middleStop', 'glowX', 'glowY', 'glowRadius', 'glowAlpha']],
    settingsAction: [['event', 'matched'], [
      ['input', true], ['input', false], ['click', true], ['click', false],
      ['submit', true], ['submit', false], ['encounter:live-refresh', false], ['unknown', true],
    ], ['read', 'reset', 'trackSubmission', 'clearSubmission', 'notify']],
    settingsText: [[], [[]], ['assignment', 'separator']],
    settingsSurface: [[], [[]], ['form', 'field', 'reset', 'draft', 'outputAttribute']],
    playback: [['useAudio', 'audioTime', 'start', 'now', 'anchor', 'duration'], [
      [false, 0, 10, 2150, 150, 4], [true, 14.5, 10, 0, 0, 4], [true, 5, 10, 0, 0, 4],
      [false, 0, 0, 100, 200, 0.25],
    ], ['position', 'ended', 'stopLabel']],
    frameTime: [['start', 'position', 'duration'], [[10, 2, 4], [10, 4, 4]]],
    timelineAdmission: [['validNumbers'], [[true], [false]], ['admitted', 'notice']],
    cueSelection: [['absolute', 'validBounds', 'from', 'to'], [
      [9, true, 10, 12], [10, true, 10, 12], [11, true, 10, 12], [12, true, 10, 12], [11, false, 10, 12],
    ], ['selected', 'offset']],
    confirmLeave: [['sameForm', 'prevented', 'dirty'], [
      [false, false, false], [false, false, true], [true, false, true], [true, true, true], [true, true, false],
    ]],
    scrub: [['requested', 'duration', 'audioPlaying'], [
      [0, 1, false], [0.25, 1, true], [-1, 1, false], [1, 1, true], [2, 1, true],
    ], ['position', 'seekAudio']],
    playToggle: [['playing', 'position', 'duration', 'enabled'], [
      [true, 1, 2, true], [true, 2, 2, true], [false, 1, 2, false], [false, 2, 2, true],
    ], ['stop', 'position', 'startSound', 'label']],
    soundChange: [['playing', 'enabled'], [[false, false], [false, true], [true, true], [true, false]],
      ['startSound', 'useAnimationClock']],
    narrationResult: [['token', 'activeToken', 'playing', 'enabled', 'failed', 'usingAudio'], [
      [1, 1, true, true, false, false], [1, 2, true, false, false, false], [1, 2, false, true, false, false],
      [1, 2, true, true, false, false], [1, 2, true, true, false, true], [3, 3, true, true, true, false],
      [2, 3, true, true, true, true], [3, 3, false, true, true, false],
    ], ['useAudio', 'pause', 'resetClock', 'notice']],
    narrationFault: [['playing', 'usingAudio'], [[false, false], [false, true], [true, false], [true, true]],
      ['useAudio', 'resetClock', 'notice']],
    settingChanged: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, -1, '', ''], [0, 0, '', ''], [3, 3, '100', '100'], [5, 3, '100.0', '100'], [2, 2, '90', '80'],
    ]],
    clockAnchor: [['now', 'position'], [[2000, 0.25], [0, 0.5], [9000, 0]]],
    audioPosition: [['start', 'position'], [[10, 2], [0, 0.125]]],
    ease: [['position'], [[-1], [0], [0.25], [0.5], [1], [2]]],
    camera: [['width', 'height', 'dx', 'dy', 'zoom', 'zoomPercent', 'pan'], [
      [1280, 720, 0, 0, 1, 100, 0], [1280, 720, 11, -5, 1.25, 120, -10],
      [101, 51, -7, 3, 0.75, 125, 8],
    ], ['x', 'y', 'scale', 'originX', 'originY']],
    routePoint: [['fromX', 'fromY', 'toX', 'toY', 'remaining', 'length'], [
      [10, 30, 14, 10, 5, 10], [10, 30, 14, 10, 25, 10], [10, 30, 10, 30, 5, 0],
      [10, 30, 14, 10, 0, 10], [10, 30, 14, 10, -5, 10],
    ], ['draw', 'x', 'y', 'remaining']],
    sceneFrame: [['scene', 'time'], [
      ...['flight', 'launch', 'arrival', 'still', 'collision', 'intent', 'intent-shift', 'intent-close', 'strata',
        'strata-close', 'branches', 'gate', 'rebuild', 'refactor', 'network', 'signals', 'harbours', 'home', 'closing',
        'constructor', 'still-extra', 's'.repeat(129)].map(scene => [scene, 2.5]),
    ], ['code', 'time', 'offset', 'alternate']],
    sceneCamera: [['code', 'time', 'offset', 'alternate'], [
      ...Array.from({length: 13}, (_, index) => index + 1)
        .flatMap(code => [0, 5, 11, 16].map(time => [code, time, code === 5 ? 1.3 : 0, code === 13])),
      [0, 2, 0, false], [13, 5, 0, false],
    ], ['warm', 'zoom', 'x', 'y']],
    seaWave: [['time', 'row', 'column'], [[0, 0, 0], [5.25, 22, 5], [8, 23, 4], [14, 35, 5]], [
      'x', 'y', 'crestX', 'crestY', 'endX', 'ink', 'width',
    ]],
    beaconLayout: [['y', 'scale'], [[305, 1], [343, 1.23], [0, 0]],
      ['plateY', 'plateWidth', 'plateHeight', 'plateDepth']],
    placeVertex: [['x', 'y', 'scale', 'dx', 'dy'],
      [[960, 305, 1, -23, 64], [845, 343, 1.23, 13, -47], [0, 0, 0, 12, 15]], ['x', 'y']],
    beaconStripes: [['x', 'y', 'scale'], [[960, 305, 1], [845, 343, 1.23], [0, 0, 0]],
      ['left', 'right', 'top', 'bottom', 'width']],
    beaconGlow: [['time', 'y', 'scale'], [[0, 305, 1], [0.4, 343, 1.23], [14, 355, 0.84]],
      ['glowY', 'glowRadius', 'alpha', 'lampY', 'lampRadius']],
    beaconReflection: [['time', 'row', 'scale', 'baseY', 'baseX'],
      [[0, 0, 1, 345, 960], [5, 5, 1.23, 343, 845], [14, 10, 0.84, 355, 0]],
      ['y', 'left', 'right', 'strokeWidth', 'ink']],
    boatBob: [['time', 'y'], [[0, 180], [1.5, 345], [14, 490]]],
    boatWake: [['time', 'ring'], [[0, 0], [5.25, 1], [14, 2]], ['alpha', 'radiusX', 'radiusY']],
    pulseRing: [['time', 'ring'], [[0, 0], [5.25, 1], [14, 2]], ['alpha', 'radiusX', 'radiusY']],
    routeDistance: [['length', 'progress'], [[185.25, -1], [185.25, 0], [185.25, 0.4], [185.25, 2]]],
    drawingVertex: [['drawing', 'index'], [
      ...['launch', 'arrival', 'collision-west', 'collision-east', 'branch-first', 'branch-second', 'gate',
        'rebuild', 'network', 'signal-west', 'signal-east', 'signal-south', 'home',
        'beacon-tower', 'beacon-shadow', 'beacon-window', 'beacon-roof', 'slip-paper', 'slip-fold',
        'slip-line-top', 'slip-line-middle', 'slip-line-bottom',
        'boat-hull', 'boat-mast', 'boat-main-sail', 'boat-small-sail', 'flight-craft']
        .flatMap(drawing => [0, 1, 2, 3, 4, 5].map(index => [drawing, index])),
      ['gate', -1], ['gate', 1.5], ['unknown', 0],
    ], ['exists', 'x', 'y']],
    routeSegment: [['fromX', 'fromY', 'toX', 'toY', 'total'], [
      [0, 0, 3, 4, 0], [230, 537, 420, 462, 21], [320, 510, 490, 530, 250], [12, 18, 12, 18, 30],
    ], ['length', 'total']],
    plateGeometry: [['x', 'y', 'rx', 'ry', 'depth'], [
      [830, 434, 258, 81, 23], [0, 0, 10.75, 5.5, 3.25], [10, 20, 0, 0, 0],
    ], ['left', 'right', 'top', 'bottom', 'edge', 'face']],
    flightStar: [['time', 'index'], [[0, 0], [3.8, 18], [11, 46]], ['x', 'y', 'radius']],
    flightPosition: [['time'], [[0], [3.8], [11]], ['x', 'y']],
    flightTrail: [['time', 'index', 'x', 'y'], [[0, 0, 320, 324], [5, 5, 670, 340]], ['x', 'y', 'radius']],
    flightPlate: [['time', 'index'], [[0, 0], [3.8, 1], [11, 5]], ['x', 'y', 'slate', 'width', 'height', 'depth']],
    flightBeacon: [['time'], [[3.79], [3.8], [3.81], [6]], ['visible', 'alpha', 'x', 'y', 'glowRadius', 'lampRadius']],
    collisionSlip: [['time', 'index'], [[0, 0], [0.9, 5], [1.2, 5], [6, 19]],
      ['visible', 'x', 'y', 'scale', 'rotation', 'teal']],
    collisionRoute: [['time'], [[4.99], [5], [5.01], [8]], ['visible', 'progress']],
    intentSlip: [['time', 'index'], [[1, 0], [5, 0], [5, 1], [5, 2], [5, 3], [5, -1], [5, 4], [5, 1.5]],
      ['visible', 'x', 'y', 'elbow', 'progress', 'scale', 'rotation']],
    strataPlate: [['time', 'index'], [[0, 0], [3, 1], [3.1, 2], [8, 3]],
      ['x', 'y', 'rx', 'ry', 'depth', 'ink']],
    strataRoute: [['time', 'index', 'x', 'y'], [[0, 0, 640, 510], [3, 1, 645, 400], [8, 3, 638, 300]],
      ['edge', 'routeX', 'endY', 'showRoute', 'progress', 'width']],
    strataStar: [['time', 'index'], [[0, 0], [3, 7], [8, 11]], ['x', 'y']],
    networkNode: [['index'], [[0], [7], [28], [48]], ['x', 'y', 'peer']],
    networkMark: [['time', 'progress', 'index'], [[0, 0, 0], [5, 0.45, 1], [10, 0.87, 4], [12, 1, 4]],
      ['visible', 'pulseTime', 'card', 'angle']],
    launchPhase: [['time'], [[0], [0.4], [1.2], [2.8], [3.1]], ['opening', 'route']],
    launchSlip: [['time', 'index'], [[0, 0], [0.8, 1], [2.6, 2], [4, 3]], ['x', 'y', 'rotation', 'coral']],
    arrivalPhase: [['time', 'still'], [[0, false], [2.75, false], [5.5, true]], ['route', 'boatTime']],
    intentBook: [['time'], [[0], [1], [3]]],
    gateArms: [['open'], [[0], [0.64], [1]], ['left', 'right', 'y', 'leftBase', 'rightBase', 'baseY', 'width']],
    rebuildPhase: [['time', 'refactor'], [[0, false], [3, false], [0, true], [5, true], [9, true]], ['progress', 'route']],
    rebuildPlate: [['time', 'progress', 'index', 'baseX', 'baseY', 'refactor'], [
      [0, 0, 0, 398, 413, false], [2, 0.5, 1, 638, 426, false],
      [3, 0.5, 0, 398, 413, true], [6, 0.75, 2, 847, 413, true],
    ], ['x', 'y']],
    networkProgress: [['time'], [[0], [0.6], [6], [11.8]]],
    signalPhase: [['time', 'index'], [[0, 0], [1, 1], [2, 2], [5, 2], [5, 3]], ['route', 'pulseTime', 'amber', 'x', 'y']],
    signalsBook: [['time'], [[0], [1.1], [3.8]]],
    harboursProgress: [['time'], [[0], [1.4], [3], [5.4]]],
    harbourLayout: [['index'], [[0], [1], [2], [-1], [0.5]],
      ['x', 'scale', 'plateY', 'beaconY', 'routeX', 'routeStart', 'routeElbow', 'routeEnd']],
    homePhase: [['time'], [[0], [5], [10.5], [14]], ['beam', 'route']],
    lightAlpha: [['alpha', 'light'], [[0.21, 100], [0.21, 0], [0.7, 190], [0.5, -10]]],
    bookDetails: [['x', 'scale', 'opening'], [[640, 0.98, 0], [826, 1.12, 0.22], [826, 1.12, 0.2201], [640, 1.07, 1]],
      ['visible', 'left', 'lineWidth', 'markWidth', 'markRadius']],
    bookDetailGeometry: [['x', 'y', 'scale', 'opening', 'index'], [
      ...[0, 1, 2, 3].map(index => [826, 321, 1.12, 0.85, index]), [640, 265, 1.07, 1, 3],
    ], ['lineX', 'fromY', 'toY', 'markX', 'markY', 'accent']],
    clockDisplay: [['position'], [[-1], [0], [9.99], [10], [59.999], [60], [61.1], [6000.5]], ['minutes', 'seconds', 'separator', 'padding']],
    bookGeometry: [['x', 'y', 'scale', 'opening'], [[640, 365, 0.98, 0], [826, 321, 1.12, 0.85], [640, 265, 1.07, 1]],
      ['left', 'right', 'foot', 'outerBottom', 'outerTop', 'spineTop', 'spineLineTop', 'spineLineBottom']],
    cueTime: [['offset', 'motion'], [[0, 80], [1.25, 80], [1.25, 0]]],
    branchPhase: [['time'], [[0], [2.7], [3.79], [3.8], [5.2], [10]], ['firstRoute', 'secondRoute', 'firstBranch', 'boatRoute']],
    gatePhase: [['time'], [[0], [4.2], [8.2], [9.14], [9.16], [9.8], [13.8]], ['open', 'lamp', 'beacons', 'route']],
    closingFade: [['time'], [[0], [6.8], [7.9], [9], [12]], ['title', 'background', 'caption', 'ink', 'font']],
    palette: [[], [[]], ['teal', 'foam', 'paper', 'coral', 'amber', 'slate']],
    waterStyle: [['warm'], [[false], [true]], ['surface', 'middle', 'depth', 'glow']],
    warmth: [['setting'], [[-100], [0], [50], [100]], ['alpha', 'color']],
  },
  preview: {
    leaveCard: [['statusTail', 'reductionHead', 'proposalFound'], [
      ['120 approved minutes', 'Reduction to 90 minutes', false], ['120 approved minutes', 'Reduction to 90 minutes', true],
      ['120 approved minutes later', 'Not Reduction to 90 minutes', false], ['', 'Reduction to ', false],
      ['🙂 approved minutes', 'reduction to 90 minutes', false], ['x'.repeat(111) + ' approved minutes', '', true],
    ], ['approved', 'proposalContext']],
    supportCoordinates: [[], [[]], ['task', 'entry', 'context', 'source']],
    commonTargets: [[], [[]], ['screen', 'app']],
    menuTarget: [['emptyValue'], [[false], [true]]],
    leaveStep: [['path'], ['/pilot/step-3/sick-leave', '/pilot/step-6/sick-leave',
      '/pilot/step-7/sick-leave', '/pilot/step-07/sick-leave', '/pilot/step-17/sick-leave',
      '/pilot/step-7/sick-leave/', '/pilot/step-7/timesheet', 'sick-leave', ''].map(path => [path])],
    panePlan: [['hasSelection', 'hasMenu', 'hasTargets', 'jumpOnLoad'], [
      [false, true, true, false], [true, true, false, true], [false, false, true, true],
    ], ['useDefault', 'showPicker', 'showPanePicker', 'scroll']],
    formContext: [['action', 'step', 'hasListItem'], [
      ['notify-sick', '1', true], ['approve-sick', '2', false], ['adjust-sick', '7', true], ['adjust-sick', '07', true],
      ['approve-reduction', '8', true], ['approve-reduction\u0000', '8', true], ['approve-reduction🙂', '8', false],
    ], ['context', 'useListItem']],
    approvedContext: [['approvedCount', 'step'], [[1, '3'], [1, '6'], [0, '3'], [2, '3'], [1, '7']]],
    targetAdmission: [['hasId', 'visible'], [[false, true], [true, false], [true, true]]],
    pickKey: [['picking', 'key', 'hasTarget'], [
      [true, 'Enter', true], [true, 'Enter', false], [true, ' ', true],
      [true, 'Escape', false], [false, 'Escape', true], [true, 'x', true],
    ]],
    targetFamily: [['route'], [['sick-leave'], ['timesheet'], ['report'], ['reports'], ['']]],
    targetSelectors: [['family'], [[0], [1], [2], [3], [4]], ['primary', 'secondary', 'coordinate', 'forms', 'links', 'report']],
    reportTarget: [['index'], [[-1], [0], [1], [2], [3]], ['id', 'selector']],
    contextLabelSource: [['option', 'element', 'comment'], [
      [true, true, true], [false, true, true], [false, false, true], [false, false, false],
    ], ['source', 'fallback']],
    pickClick: [['picking', 'hasTarget'], [[false, true], [true, false], [true, true]]],
    sameContext: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, -1, '', ''], [0, 0, '', ''], [6, 6, 'screen', 'screen'], [6, 6, 'screen', 'screan'],
    ]],
    pickAlias: [['hasAlias', 'selected'], [[false, false], [true, false], [false, true], [true, true]],
      ['bind', 'initialise']],
    pickerStarts: [['picking', 'hasTargets'], [[false, true], [true, true], [false, false], [true, false]]],
    menuChoice: [['emptyValue', 'screenAvailable', 'targetAvailable'], [
      [true, true, false], [true, false, true], [false, true, true], [false, true, false], [false, false, true],
    ]],
    selectionFollowup: [['source'], [['picker'], ['badge'], ['menu'], ['return']],
      ['scroll', 'syncSelect', 'focusSidebar', 'focusComposer', 'focusFilter', 'sidebarBlock', 'filterBlock']],
    commentControls: [[], [[]], ['back', 'clear']],
    commentSummary: [['filtered', 'count'], [
      [false, 0], [false, 2], [true, 0], [true, 1], [true, 2],
    ], ['showList', 'showCaption', 'separator', 'suffix']],
    commentBadge: [['context', 'count', 'hasTarget', 'onApp', 'onScreen', 'inList'], [
      ['app', 2, true, true, false, false], ['screen', 1, true, false, true, false],
      ['entry', 1, true, false, false, true], ['report', 2, true, false, false, false],
      ['missing', 1, false, false, false, false],
    ], ['placement', 'prefix', 'suffix', 'labelSeparator']],
    contextLabel: [['context'], [['screen'], ['app'], ['entry'], ['']]],
    pickerView: [['active'], [[false], [true]], ['button', 'notice']],
    paneAdmission: [['hasPane', 'alreadyBound'], [[false, false], [true, false], [true, true]]],
    selectionView: [['value', 'hasTarget', 'scroll', 'picking', 'updateUrl'], [
      ['', false, false, false, true], ['screen', true, true, false, true], ['app', true, true, false, true],
      ['increase', true, false, false, false], ['increase', true, true, true, true], ['missing', false, true, true, true],
    ], ['url', 'linkContext', 'scrollApp', 'scrollBlock', 'updateStatus', 'label', 'message', 'fallback']],
    optionDisabled: [['value', 'available'], [['', false], ['increase', true], ['missing', false]]],
    selectValue: [['value', 'available'], [['screen', true], ['increase', true], ['missing', false]]],
    commentVisible: [['filterLength', 'contextLength', 'filter', 'context'],
      [['', 'screen'], ['screen', 'screen'], ['screen', 'app'], ['target🙂', 'target🙃']]
        .map(([filter, context]) => [filter.length, context.length, filter, context])],
    returnVisible: [['offered', 'top', 'bottom', 'viewport'], [
      [false, 999, 1200, 800], [true, 680, 1200, 800], [true, 679, 1200, 800], [true, -200, 0, 800], [true, -200, 1, 800],
    ]],
  },
  countdown: {
    bindingAllowed: [['ref', 'duplicate', 'used', 'storage', 'array', 'count'], [
      ['#a', false, 15, 'x', true, 1], ['#' + 'a'.repeat(80), false, 16, 'x'.repeat(120), true, 1],
      ['#' + 'a'.repeat(80), false, 1, 'x'.repeat(120), true, 12],
      ['#' + 'a'.repeat(81), false, 1, 'x', true, 12], ['#', false, 1, 'x', true, 12],
      ['#a', false, 1, 'x'.repeat(121), true, 1], ['#a', false, 1, '', true, 1],
      ['#a', false, 1, 'x', true, 0], ['#a', false, 1, 'x', true, 13], ['#a', true, 1, 'x', true, 1],
      ['.a', false, 1, 'x', true, 1], ['#a', false, 1, 'X', true, 1], ['#a', false, 1, 'x', false, 1],
    ]],
    choiceAllowed: [['name', 'duplicate', 'whole', 'milliseconds', 'defaultConflict'], [
      ...[-1, 0, 999, 1000, 3600000, 3600001].map(interval => ['x', false, true, interval, false]),
      ...[0, 32, 33].map(length => ['x'.repeat(length), false, true, 15000, false]),
      ['x', true, true, 15000, false], ['x', false, true, 15000, true], ['X', false, true, 15000, false],
      ['x', false, false, 0, false],
    ]],
    optionsReady: [['hasDefault', 'optionsPresent'], [[true, true], [true, false], [false, true], [false, false]]],
    controlsAllowed: [['captionInPanel', 'preferenceInPanel', 'panelInDesktop', 'correctTypes'], [
      [true, true, true, true], [false, true, true, true], [true, false, true, true],
      [true, true, false, true], [true, true, true, false],
    ]],
    tickVisible: [['bound', 'panelHidden', 'desktopHidden'], [
      [true, false, false], [true, true, false], [true, false, true], [false, false, false],
    ]],
    selectedInterval: [['known', 'selected', 'defaultInterval'], [[true, 0, 10000], [true, 5000, 10000], [false, 0, 10000]]],
    preferenceChoice: [['known', 'candidateSelected', 'defaultSelected'], [
      [true, true, false], [true, false, true], [false, false, true], [false, false, false],
    ], ['useCandidate', 'update']],
    refreshAnchor: [['bound', 'scheduled'], [[true, false], [true, true], [false, false], [false, true]]],
    tick: [['hasAnchor', 'anchor', 'interval', 'now', 'requests', 'scheduled', 'idle'], [
      [false, 0, 0, 10000, 0, false, true], [false, 0, 15000, 10000, 0, false, true],
      [true, 1000, 15000, 1999, 0, false, true], [true, 1000, 15000, 16000, 0, false, true],
      [true, 1000, 15000, 16999, 0, false, true], [true, 1000, 15000, 17000, 0, false, true],
      [true, 1000, 15000, 16000, 0, false, false], [true, 1000, 15000, 16000, 1, false, true],
      [true, 1000, 15000, 16000, 2, false, true], [true, 1000, 15000, 16000, 0, true, true],
      [true, 1000, 0, 16000, 1, true, true],
    ], ['caption', 'dispatch', 'anchor', 'delay', 'label', 'suffix', 'showSeconds']],
    caption: [['interval', 'remaining', 'refreshing'], [[0, 0, false], [15_000, 14_001, false], [15_000, 0, false], [15_000, 2_000, true]]],
    dispatch: [['interval', 'remaining', 'refreshing', 'idle'], [[0, 0, false, true], [15_000, 0, false, true], [15_000, 0, true, true], [15_000, 0, false, false]]],
    deadline: [['hasAnchor', 'anchor', 'interval', 'now'], [[true, 1000, 15_000, 1100], [false, 0, 15_000, 1100]]],
    anchor: [['now', 'deadline'], [[1100, 1000], [1999, 1000], [2000, 1000]]],
    delay: [['remaining', 'refreshing'], [[0, false], [-1, false], [500, true], [1000, false], [12_345.25, false]]],
  },
  assurance: {
    response: [['status', 'warnings'], [
      [200, false], [204, true], [403, false], [403, true], [503, true],
    ], ['action', 'dropUnread']],
    rowLimit: [['warnings'], [[true], [false]]],
    presentation: [['open', 'warnings', 'hasRows'], [
      [false, false, true], [false, false, false], [true, true, false], [true, false, false], [true, true, true],
    ], ['visible', 'showEmptyHistory', 'refreshAges']],
    updateEnvelope: [['warnings', 'length', 'rowsObject', 'unread', 'openLimit', 'exchangeLimit'], [
      [false, 40, true, -1, -1, -1], [false, 41, true, 0, 0, 0], [false, -1, true, 0, 0, 0],
      [true, 4, true, 1, 100, 2], [true, 5, true, 1, 100, 2], [true, 4, false, 1, 100, 2],
      [true, 4, true, -1, 100, 2], [true, 4, true, 1, -1, 2], [true, 4, true, 1, 100, -1],
      [true, 0, true, 0, 100, 2], [true, 2, true, 2, 100, 2],
    ]],
    warningHeader: [['unread'], [[0], [1], [2]], ['unreadSuffix', 'budgetPrefix', 'budgetDivider', 'budgetSuffix']],
    rowAction: [['key', 'unique', 'retained', 'hasMarkup'], [
      ['a'.repeat(20), true, true, false], ['a'.repeat(20), true, false, true],
      ['a'.repeat(20), true, false, false], ['a'.repeat(20), false, true, true],
      ...['A'.repeat(20), '0'.repeat(19) + '\n', 'a'.repeat(19), 'a'.repeat(21), 'a'.repeat(129), ''].map(
        key => [key, true, true, true]),
    ]],
    warningAge: [['now', 'timestamp'], [[0, 60_000], [0, 0], [60_000, 0], [3_600_000, 0], [3_660_000, 0], [7_140_000, 0], [7_200_000, 0]],
      ['hours', 'minutes', 'hourSuffix', 'minuteSuffix', 'separator', 'prefix', 'ending']],
  },
  mobile: {
    tripStorage: [[], [[]], ['scope', 'worker', 'tripCache', 'session', 'package', 'receipt', 'draftCache', 'draftPrefix']],
    shellPaths: [[], [[]], ['prefix', 'phone', 'runtime']],
    offlineMarkers: [[], [[]], ['online', 'offline', 'removeHeader']],
    shellUnavailable: [[], [[]], ['message', 'status']],
    shellRoute: [['sameOrigin', 'method', 'path'], [
      [true, 'GET', '/workspace/mobile/phone'], [true, 'GET', '/workspace/mobile/runtime.mjs'],
      [true, 'GET', '/workspace/mobile/pair/a'], [true, 'POST', '/workspace/mobile/phone'],
      [false, 'GET', '/workspace/mobile/phone'], [true, 'GET', '/workspace/mobile/phone/'],
    ]],
    shellReply: [['route', 'networkOk', 'hasCache'], [
      [1, true, false], [1, false, true], [2, false, true], [1, false, false], [2, false, false],
    ]],
    shellCacheKey: [['route'], [[0], [1], [2], [3]]],
    shellCacheRefresh: [['route', 'hasQuery', 'redirected', 'sameUrl', 'status', 'contentType', 'hasPolicy', 'request', 'latest'], [
      [1, false, false, true, 200, 'text/html', true, 2, 1], [1, true, false, true, 200, 'text/html', true, 2, 1],
      [1, false, true, true, 200, 'text/html', true, 2, 1], [1, false, false, false, 200, 'text/html', true, 2, 1],
      [1, false, false, true, 204, 'text/html', true, 2, 1], [1, false, false, true, 200, 'text/plain', true, 2, 1],
      [1, false, false, true, 200, 'text/html', false, 2, 1], [2, false, false, true, 200, 'text/html', true, 2, 1],
      [2, false, false, true, 200, 'text/javascript', true, 2, 1], [1, false, false, true, 200, 'text/html', true, 1, 2],
      [1, false, false, true, 200, 'text/html', true, 2, 2],
    ], ['refresh', 'latest']],
    shellPolicyMatches: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, -1, '', ''], [4, 4, 'same', 'same'], [4, 5, 'same', 'same'],
      [400, 400, 'same chunk', 'same chunk'], [400, 400, 'abc🙂', 'abc🙃'],
    ]],
    retiredShellCache: [['prefix', 'key', 'current'], [
      ['sourcery-mobile-shell-', 'sourcery-mobile-shell-current', 'sourcery-mobile-shell-current'],
      ['sourcery-mobile-shell-', 'sourcery-mobile-shell-old', 'sourcery-mobile-shell-current'],
      ['sourcery-mobile-trip-1', 'sourcery-mobile-trip-1', 'sourcery-mobile-shell-current'],
    ]],
    pairRequest: [['action'], ['read', 'claim', 'disconnect', 'invalidate', 'receipt', 'unknown'].map(action => [action]),
      ['prefix', 'suffix', 'method', 'authorization', 'digest', 'challenge']],
    pairReply: [['status', 'ok'], [[200, true], [201, true], [204, true], [404, false], [409, false]], ['action', 'message']],
    claimAction: [['phone', 'code', 'previous', 'next', 'hasPrevious'], [
      ...[
        ['A_-09z'.padEnd(43, 'a'), '001234'], ['a'.repeat(42) + '=', '001234'], ['a'.repeat(42), '001234'],
        ['a'.repeat(44), '001234'], ['a'.repeat(43), '01234!'], ['a'.repeat(43), '12345'],
        ['a'.repeat(43), '1234567'], ['a'.repeat(43), '123456\n'], ['a'.repeat(43), '12345８'], ['', ''],
      ].map(fields => [...fields, 'previous', 'next', true]),
      ['a'.repeat(43), '001234', 'same', 'same', true],
      ['a'.repeat(43), '001234', '', 'next', false],
    ], ['action', 'message']],
    invitationAdmission: [['id', 'bearer', 'pair'], [
      ['x'.repeat(16), 'y'.repeat(43), true], ['x'.repeat(16), 'y'.repeat(43), false],
      ['x'.repeat(15) + '.', 'y'.repeat(43), true], ['x'.repeat(16), 'y'.repeat(42) + 'ø', true],
    ]],
    draftBasis: [['task', 'pin', 'id', 'base'], [
      ['a', 'b'.repeat(64), 'draft_1', 'new'], ['a'.repeat(80), 'b'.repeat(64), 'c'.repeat(80), '0'.repeat(64)],
      ['a'.repeat(81), 'b'.repeat(64), 'draft', 'new'], ['a', 'B'.repeat(64), 'draft', 'new'],
      ['a', 'b'.repeat(64), '', 'new'], ['a', 'b'.repeat(64), 'draft', 'new\n'],
      ['a', 'b'.repeat(64), 'draft', 'c'.repeat(129)],
    ]],
    snapshotDigest: [['actual', 'claimed'], [['a'.repeat(64), 'a'.repeat(64)], ['a'.repeat(64), 'b'.repeat(64)], ['', '']]],
    snapshotInput: [['hasText'], [[false], [true]], ['hash', 'message']],
    snapshotIntegrity: [['actual', 'claimed'], [['a'.repeat(64), 'a'.repeat(64)], ['a'.repeat(64), 'b'.repeat(64)], ['', '']],
      ['parse', 'message']],
    refreshIntervals: [[], [[]], ['trip', 'drafts']],
    snapshotAdmission: [['hasExpiry', 'expires', 'now', 'count', 'expected', 'sameRevision', 'unique', 'validItems'], [
      [true, 200, 100, 2, 2, true, true, true], [true, 100, 100, 2, 2, true, true, true],
      [false, 0, 100, 2, 2, true, true, true], [true, 200, 100, 0, 0, true, true, true],
      [true, 200, 100, 2, 1, true, true, true], [true, 200, 100, 2, 2, false, true, true],
      [true, 200, 100, 2, 2, true, false, true], [true, 200, 100, 2, 2, true, true, false],
      [true, 100, 100, 2, 1, false, false, false],
    ], ['admit', 'message']],
    referenceOffset: [['id', 'length'], [['pilot-ref-', 10], ['pilot-ref-', 11], ['pilot-ref-', 270], ['pilot-refs', 15]]],
    referenceDigits: [['digits'], ['', '0', '08', '1'.repeat(128), '123x', '１２', '1\n'].map(text => [text])],
    itemAdmission: [['id', 'text', 'nonempty', 'reference', 'title', 'hasDraft', 'validDraft'], [
      ['note', true, true, false, false, false, false], ['project', true, false, false, false, false, false],
      ['pilot-review', true, false, false, true, false, false], ['pilot-review', true, false, false, true, true, false],
      ['pilot-ref-8', true, false, true, true, false, false], ['pilot-unknown', true, true, false, true, false, false],
      ['pilot-draft', true, true, false, true, true, false], ['pilot-draft', true, true, false, true, true, true],
      ['pilot-draft', false, false, false, true, true, true],
    ]],
    tripItemView: [['id', 'count'], ['note', 'project', 'pilot-ref-8', 'pilot-diff', 'pilot-draft', 'pilot-ref', 'note-extra']
      .map((id, count) => [id, count]), ['fallbackTitle', 'element', 'draft', 'position']],
    offlineReceipt: [['offline', 'reopened', 'receipt'], [
      [false, false, 0], [false, true, 2], [true, false, 0], [true, true, 0], [true, true, 1], [true, true, 2],
    ], ['action', 'message', 'detail']],
    tripAction: [['installed', 'dirty', 'confirmed'], [
      [true, true, true], [true, false, false], [false, true, true], [false, false, false], [false, false, true],
    ], ['action', 'message']],
    workerStartup: [['active', 'online'], [[false, false], [false, true], [true, false], [true, true]], ['register', 'refresh']],
    resumePairing: [['paired', 'pendingRemoval'], [[false, false], [false, true], [true, false], [true, true]], ['action', 'message']],
    canSynchronise: [['running', 'stopped', 'booted', 'paired', 'online'], [
      [false, false, true, true, true], [true, false, true, true, true], [false, true, true, true, true],
      [false, false, false, true, true], [false, false, true, false, true], [false, false, true, true, false],
    ]],
    roomAction: [['status', 'hasTrip'], [['waiting', false], ['connected', false], ['connected', true], ['connected-extra', true]],
      ['action', 'message']],
    receiptAction: [['hasReceipt', 'digest', 'tripDigest', 'challenge', 'tripChallenge'], [
      [false, 'digest', 'digest', 'challenge', 'challenge'],
      [true, 'old', 'new', 'challenge', 'challenge'],
      [true, 'digest', 'digest', 'old', 'new'],
      [true, 'digest', 'digest', 'longer', 'long'],
      [true, 'digest', 'digest', '', ''],
      [true, 'digest', 'digest', 'offline🙂', 'offline🙂'],
      [true, 'digest', 'digest', 'offline🙂', 'offline🙃'],
      [true, 'd'.repeat(128), 'd'.repeat(128), 'c\u0000', 'c\u0000'],
      [true, 'd'.repeat(128), 'd'.repeat(127) + 'e', 'c\u0000', 'c\u0000'],
    ]],
    receiptReply: [['accepted', 'status'], [[true, 0], [true, 409], [false, 409], [false, 503], [false, 0]],
      ['retry', 'confirm', 'clear', 'message']],
    localRemoval: [['running', 'stopped', 'dirty'], [
      [true, false, true], [true, false, false], [false, true, false], [false, false, true], [false, false, false],
    ], ['action', 'message']],
    canFinishRemoval: [['pending', 'online', 'removing', 'removingLocally'], [
      [false, true, false, false], [true, false, false, false], [true, true, true, false],
      [true, true, false, true], [true, true, false, false],
    ]],
    removalFinished: [['status'], [[404], [409]]],
    removalMessages: [[], [[]], ['finished', 'failed']],
    draftRecordAdmission: [['basis', 'text', 'sameKey', 'state'], [
      [true, true, true, 'pending'], [true, true, true, 'saved'], [true, true, true, 'conflict'], [true, true, true, 'sign-in'],
      [false, true, true, 'pending'], [true, false, true, 'pending'], [true, true, false, 'pending'], [true, true, true, ''],
    ]],
    draftView: [['state', 'hasCurrent', 'active'], [
      ['saved', false, false], ['conflict', false, false], ['conflict', true, false],
      ['conflict', true, true], ['sign-in', false, false], ['pending', false, true], ['', false, false],
    ], ['message', 'showInList', 'removeWithTrip', 'appendCurrent']],
    draftSaveAdmission: [['hasText'], [[false], [true]]],
    draftSaveState: [['state'], [['conflict'], ['pending'], ['saved'], ['sign-in'], ['']]],
    draftTextChanged: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, 0, '', ''], [2, 2, '🙂', '🙂'], [2, 2, '🙂', '🙃'], [130, 131, 'prefix', 'prefix'],
    ]],
    canSyncDrafts: [['syncing', 'online', 'hasList'], [
      [false, true, true], [true, true, true], [false, false, true], [false, true, false],
    ]],
    draftPending: [['state'], [['pending'], ['sign-in'], ['saved'], ['conflict'], ['']]],
    pilotRoute: [['syncing'], [[false], [true]], ['path', 'work', 'view', 'travel', 'sync']],
    pilotRead: [['redirected', 'status', 'ok'], [[true, 0, false], [false, 401, false], [false, 403, false], [false, 200, true], [false, 503, false]], ['readBody', 'status']],
    pilotSubmit: [['status', 'hasCsrf'], [['open', false], ['open', true], ['conflict', true], ['', true]],
      ['send', 'task', 'travel', 'comment', 'base', 'pin', 'note', 'csrf']],
    pilotResult: [['ok', 'status'], [[true, 200], [false, 401], [false, 403], [false, 409]], ['readBody', 'status']],
    draftAction: [['currentBase', 'submittedBase', 'state', 'reply', 'sameText', 'replyBase'], [
      [false, 'pending', 'saved', true, 'a'.repeat(64)],
      [true, 'saved', 'saved', true, 'a'.repeat(64)],
      [true, 'pending', 'saved', true, 'a'.repeat(64)],
      [true, 'pending', 'saved', false, 'a'.repeat(64)],
      [true, 'pending', 'saved', true, ''],
      [true, 'pending', 'saved', false, 'x'.repeat(64)],
      [true, 'pending', 'saved', true, 'a'.repeat(65)],
      [true, 'pending', 'conflict', false, ''],
      [true, 'pending', 'unavailable', false, ''],
      [true, 'pending', 'sign-in', false, ''],
      [true, 'sign-in', 'sign-in', false, ''],
      [true, 'pending', 'saved🔒', false, 'a'.repeat(64)],
      [true, 'pending', 'x'.repeat(129), false, 'a'.repeat(64)],
    ].map(([sameBase, ...fields]) => [
      '0'.repeat(64), sameBase ? '0'.repeat(64) : '0'.repeat(63) + '1', ...fields,
    ]), ['state', 'updateBase', 'updateCurrent']],
  },
  temple: {
    timing: [[], [[]], ['initialRetry', 'connectionDeadline', 'workspaceDeadline', 'assurancePoll']],
    connectionTimedOut: [['active', 'greeted'], [[false, false], [false, true], [true, false], [true, true]]],
    messageBody: [['text', 'length'], [[false, 0], [true, 0], [true, 4096], [true, 4097]]],
    subscriptionRequest: [['previous'], [[0], [1], [42]], ['type', 'id']],
    subscriptionReply: [['pendingId', 'observedId', 'pendingWorkspace', 'observedWorkspace'], [
      [2, 2, 'home', 'home'], [0, 0, '', ''], [2, 1, 'home', 'home'], [2, 2, 'home', 'work'],
    ]],
    subscriptionTimedOut: [['pendingId', 'observedId', 'pendingWorkspace', 'observedWorkspace'], [
      [2, 2, 'home', 'home'], [0, 0, '', ''], [2, 1, 'home', 'home'], [2, 2, 'home', 'work'],
    ], ['expire', 'suffix']],
    retryConnection: [['greeted', 'reconnecting', 'delay'], [
      [false, false, 1000], [true, false, 1000], [false, true, 16_000], [true, true, 30_000],
    ], ['retry', 'wait', 'nextDelay', 'notice']],
    platformAppCount: [['array', 'count', 'distinct'], [
      [true, 0, 0], [true, 2, 2], [true, 2, 1], [true, 3, 3], [false, 0, 0],
    ]],
    platformApp: [['view', 'titleText', 'titleLength', 'detailText', 'detailLength'], [
      ['platform-inbox', true, 80, true, 160], ['work-items', true, 81, true, 160],
      ['work-items', true, 80, true, 161], ['unknown', true, 1, true, 1],
      ['work-items', false, 0, true, 0], ['work-items', true, 0, false, 0],
    ]],
    originInput: [['text', 'length'], [[false, 0], [true, 0], [true, 240], [true, 241]]],
    connectionCoordinates: [['secure'], [[true], [false]], ['path', 'protocol']],
    originAllowed: [['protocol', 'loopbackHost', 'explicitPort', 'rootPath', 'credentials', 'decorated'], [
      ['https:', false, false, true, false, false], ['http:', true, true, true, false, false],
      ['http:', true, false, true, false, false], ['http:', false, true, true, false, false],
      ['https:', false, false, false, false, false], ['https:', false, false, true, true, false],
      ['https:', false, false, true, false, true],
    ]],
    workspaceLocation: [['path', 'view', 'uniqueView'], [
      ['/', 'platform', true], ['/workspace/home', 'work-items', true], ['/workspace/home', 'platform', false],
      ['/workspace/work', 'platform', true], ['/workspace/platform', '', false], ['/workspace/mobile', '', false],
      ['/workspace/home/extra', 'platform-inbox', true],
    ]],
    workspaceName: [['workspace'], [['home'], ['work'], ['platform'], ['mobile'], ['unknown'], ['']]],
    workspacePath: [['workspace'], [['home'], ['work'], ['platform'], ['mobile'], ['unknown'], ['']]],
    historyRestore: [['path', 'view', 'uniqueView'], [
      ['/workspace/work', '', false], ['/workspace/mobile', '', false], ['/', 'platform', true],
      ['/workspace/home', 'work-items', true], ['/workspace/home', 'platform', false], ['/other', 'platform', true],
    ], ['workspace', 'mode']],
    navigationItem: [['workspace', 'selected'], [
      ['home', 'home'], ['work', 'home'], ['platform', ''], ['mobile', 'mobile'], ['unknown', 'unknown'], ['', ''],
    ], ['label', 'current']],
    workspaceNotice: [['phase'], [['opening'], ['subscription-timeout'], ['unavailable'], ['slow'], ['empty'], ['unknown']],
      ['prefix', 'suffix']],
    launchFields: [['workspace', 'local'], [['home', true], ['platform', true], ['platform', false], ['home', false]],
      ['open', 'view', 'item', 'setup', 'play', 'pilot', 'comment', 'signIn']],
    launchValueAllowed: [['workspace', 'name', 'value', 'count', 'local'], [
      ['home', 'open', '', 0, true], ['home', 'open', '', 1, true], ['home', 'open', 'front-gate', 2, true],
      ['work', 'open', 'front-gate', 1, false], ['platform', 'view', 'platform-inbox', 1, false],
      ['platform', 'view', 'platform', 1, false], ['platform', 'view', 'work-items', 2, false],
      ['platform', 'item', 'coordinate', 1, false], ['home', 'view', 'work-items', 1, false],
    ]],
    platformTarget: [['workspace', 'view', 'item'], [
      ...[['', ''], ['', 'a'.repeat(32)], ['platform', 'a'.repeat(32)], ['unknown', 'a'.repeat(32)],
        ['platform-inbox', 'A'.repeat(32)], ['work-items', '0'.repeat(32)], ['work-items', '0'.repeat(33)]]
        .map(fields => ['platform', ...fields]),
      ['home', 'work-items', 'a'.repeat(32)], ['mobile', '', 'a'.repeat(32)],
    ], ['project', 'view', 'includeItem']],
    catalogueLimit: [[], [[]]],
    savedTempleAdmission: [['validIdentity', 'canonicalOrigin'], [[false, false], [true, false], [false, true], [true, true]]],
    savedOriginMatch: [['currentLength', 'savedLength', 'current', 'saved'], [
      [22, 22, 'https://temple.example', 'https://temple.example'], [22, -1, 'https://temple.example', ''],
      [180, 181, 'same', 'same'], [180, 180, 'example', 'invalid'], [180, 180, 'example', 'example'],
    ]],
    retainSavedTemple: [['count', 'sameOrigin'], [[1, true], [1, false], [19, false], [20, false], [20, true]]],
    savedCatalogue: [['version', 'hasList'], [[0, false], [0, true], [1, false], [1, true], [2, true]]],
    identityAdmission: [['id'], ['', 'a', 'a-._1Z', 'a'.repeat(80), 'a'.repeat(81), 'a\n', '🌐'].map(id => [id])],
    greetingWorkspaceCount: [['hasList', 'count'], [[false, 0], [true, 0], [true, 4], [true, 5]]],
    greetingPlan: [['subscriptionVersion', 'reconnecting', 'selected', 'path'], [
      [0, false, '', '/'], [1, true, 'home', '/workspace/home'], [1, false, 'work', '/workspace/work'],
      [1, true, '', ''], [1, true, 'platform', '/workspace/home'], [2, true, 'mobile', '/workspace/mobile'],
    ], ['subscriptions', 'refreshLaunch']],
    greetingAccepted: [['protocol', 'savedTemple', 'observedTemple', 'knownTemple', 'validTemple', 'validWorkspaces'], [
      ['sourcery/temple-connection/1', '', 'fixture', false, true, true],
      ['sourcery/temple-connection/1', 'fixture', 'fixture', true, true, true],
      ['sourcery/temple-connection/1', 'saved', 'different', true, true, true],
      ['sourcery/temple-connection/2', 'fixture', 'fixture', true, true, true],
      ['sourcery/temple-connection/1', '', '', false, false, true],
      ['sourcery/temple-connection/1', '', 'fixture', false, true, false],
    ]],
    selection: [['selected', 'available', 'preferred', 'preferredAvailable', 'first'], [
      ['', false, '', false, ''], ['', false, 'mobile', true, 'home'], ['', false, 'mobile', false, 'home'],
      ['work', false, 'mobile', true, 'home'], ['work', true, 'mobile', true, 'home'],
    ], ['action', 'workspace']],
    subscription: [['resubscribe', 'mounted', 'pending', 'subscriptions'], [
      [false, true, false, true], [false, false, true, true], [true, true, false, true], [false, false, false, false],
    ]],
    followWorkspaceLink: [['hasLink', 'primary', 'prevented', 'modified', 'target'], [
      [true, true, false, false, ''], [true, true, false, false, '_self'],
      [true, true, false, false, '_blank'], [true, true, false, true, ''],
      [true, false, false, false, ''], [true, true, true, false, ''], [false, true, false, false, ''],
    ]],
    workspaceDestination: [['sameOrigin', 'available'], [[true, true], [true, false], [false, true]]],
    workspaceOpen: [['connected', 'available'], [[true, true], [true, false], [false, true]]],
    workspaceHistory: [['mode', 'samePath', 'sameQuery'], [
      ['none', false, false], ['push', true, true], ['push', true, false],
      ['push', false, true], ['replace', true, false], ['replace', true, true], ['unknown', false, false],
    ]],
    surfacePlan: [['mounted', 'hasFrame', 'frameReady', 'launcher'], [
      [true, true, true, false], [true, true, false, false], [true, false, false, true],
      [false, false, false, true], [false, false, false, false],
    ], ['action', 'loadingHidden', 'frameHidden']],
    preferenceReply: [['ok', 'current', 'connected', 'available'], [
      [false, true, true, true], [true, true, true, true], [true, false, true, true],
      [true, true, false, true], [true, true, true, false],
    ], ['action', 'message']],
    connectionNotice: [['reconnecting'], [[false], [true]]],
    frameLoadAction: [['active', 'targetDocument', 'local', 'workspace', 'connected'], [
      [false, true, true, 'work', true], [true, true, true, 'work', true],
      [true, false, true, 'work', true], [true, false, false, 'work', true],
      [true, false, true, 'work', false], [true, false, true, 'home', true],
    ]],
    frameMount: [['workspace', 'local'], [['home', true], ['home', false], ['work', true], ['work', false], ['mobile', true]],
      ['sandbox', 'homeConnection', 'preferenceForm', 'referrer']],
    frameObservation: [['hasHomeConnection'], [[true], [false]], ['attribute', 'bridge']],
    frameSignIn: [[], [[]], ['path', 'message', 'label']],
    frameReady: [['hasHomeConnection', 'homeReady', 'bridgeReady', 'waitForBridge'], [
      [true, false, true, true], [true, true, false, true], [false, false, true, true],
      [false, false, false, true], [false, false, false, false],
    ]],
    showFrame: [['connected', 'pending', 'ready'], [
      [false, false, true], [true, true, true], [true, false, false], [true, false, true],
    ]],
    frameTimedOut: [['active', 'connected'], [[false, true], [true, false], [true, true]]],
    workspaceReply: [['type', 'workspace', 'kind', 'hasView', 'validApps', 'entryMatches'], [
      ['workspace.ready', 'platform', 'platform-launcher', false, true, false],
      ['workspace.ready', 'platform', 'platform-launcher', false, false, false],
      ['workspace.ready', 'platform', 'frame', true, false, true],
      ['workspace.ready', 'platform', 'frame', false, false, true],
      ['workspace.ready', 'work', 'frame', false, false, false],
      ['workspace.ready', 'work', 'frame', false, false, true],
      ['workspace.unavailable', 'work', 'frame', false, false, true],
    ]],
  },
  'live-events': {
    sameCoordinate: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, -1, '', ''], [4, 4, '/one', '/two'], [4, 4, '/one', '/one'], [5, 4, '/one', '/one'],
    ]],
    draftChanged: [['currentLength', 'savedLength', 'current', 'saved'], [
      [0, 0, '', ''], [2, 2, '🙂', '🙂'], [2, 2, '🙂', '🙃'], [129, 130, 'prefix', 'prefix'],
    ]],
    editorActive: [['editable', 'canvasControl'], [[false, false], [true, false], [true, true]]],
    updatePlan: [['surfacePresent', 'updating', 'force'], [
      [false, false, false], [false, true, true], [true, false, false], [true, false, true],
      [true, true, false], [true, true, true],
    ]],
    applyQueued: [['force', 'queued', 'sameRoute'], [
      [false, false, false], [true, false, false], [false, true, true],
      [false, true, false], [true, true, false], [true, true, true],
    ], ['force', 'consume']],
    queuedApplied: [['replaced', 'consume'], [[false, false], [false, true], [true, false], [true, true]]],
    inspectQueuedRoute: [['queued', 'applied'], [[false, false], [false, true], [true, false], [true, true]]],
    finishQueued: [['queued', 'sameRoute', 'applied'], [
      [false, false, false], [false, false, true], [true, true, true],
      [true, true, false], [true, false, false], [true, false, true],
    ], ['clear', 'retry']],
    refresh: [['moved', 'validRendered', 'rendered', 'wanted', 'force', 'dirty', 'editing', 'media'], [
      [false, true, 2, 2, false, true, true, false], [false, true, 2, 2, false, true, true, true],
      [true, true, 3, 2, false, true, false, true], [false, true, 1, 2, false, false, true, false],
      [false, false, 0, 0, false, false, false, false], [false, true, 1, 2, true, true, true, false],
      [true, true, 1, 2, false, false, true, true],
    ], ['fetch', 'pending']],
    replace: [['dirty', 'force', 'media', 'partCount', 'matchedParts', 'moved', 'surfacesPresent',
      'markerInside', 'incomingMarkerInside'], [
      [true, false, false, 0, 0, false, true, false, false], [true, true, true, 2, 2, true, true, true, true],
      [false, false, false, 0, 0, true, true, false, false], [false, false, false, 0, 0, true, true, true, true],
      [true, true, true, 2, 1, true, true, true, true], [true, true, true, 0, 0, true, true, true, true],
      [false, false, true, 1, 1, false, true, false, false], [false, true, true, 1, 1, true, true, true, true],
      [true, true, false, 0, 0, false, false, false, false], [true, true, false, 0, 0, false, true, true, false],
      [true, true, true, 2, 2, true, false, true, true], [true, true, true, 2, 2, true, true, false, true],
    ], ['action', 'retainDraft', 'changeRoute', 'focus', 'updateMarker']],
    pendingNotice: [['show', 'moved', 'hasConnection'], [
      [false, true, true], [true, false, true], [true, false, false], [true, true, false],
    ], ['message', 'hideApply', 'disableSubmit']],
    mediaClockReady: [['hasCurrentData', 'seeking'], [[false, false], [true, true], [true, false]]],
    seekCue: [['hasCue', 'hasCurrentData', 'primaryButton', 'modified'], [
      [false, true, true, false], [true, false, true, false], [true, true, false, false],
      [true, true, true, true], [true, true, true, false],
    ]],
    replaceToken: [['hasToken', 'sameStream'], [[true, false], [false, true], [true, true]]],
    resumeCursor: [['safeInteger', 'saved'], [[true, 0], [true, 7], [true, -1], [true, 9007199254740991], [false, 0]]],
    socketCoordinates: [['secure'], [[false], [true]], ['protocol', 'cursorParameter', 'storagePrefix']],
    socketDelivery: [['opening', 'validSequence', 'after', 'wanted', 'sequence'], [
      [false, true, 0, 0, 1], [false, true, 1, 1, 1], [false, true, 2, 2, 1],
      [false, false, 2, 2, 10], [false, true, 2, 8, 3], [true, false, 7, 0, 0],
      [true, true, 7, 10, 12],
    ], ['accept', 'after', 'wanted']],
    refreshReply: [['ok', 'currentRoute'], [[true, true], [true, false], [false, true]]],
    replaceReply: [['currentRoute', 'sameStream', 'moved', 'validSequences', 'shown', 'incoming'], [
      [true, true, false, true, 0, 1], [true, false, false, true, 0, 1], [true, true, false, true, 1, 1],
      [true, true, false, true, 2, 1], [true, true, true, true, 2, 1], [true, false, true, true, 2, 1],
      [false, true, false, true, 0, 1], [false, true, true, true, 0, 1], [true, true, true, false, 0, 0],
    ]],
    reconnectRequest: [['hasConnection'], [[false], [true]], ['refresh', 'cache', 'redirect']],
    reconnectAction: [['status', 'opaqueRedirect', 'ok'], [
      [0, true, false], [401, false, false], [403, false, false], [503, false, false], [200, false, true],
    ], ['read', 'retryEvent']],
    socketSchedule: [['event', 'delay', 'hasConnection'], [
      ['start', 0, true], ['open', 5000, true], ['close', 500, true], ['close', 500, false],
      ['failed', 4000, true], ['sign-in', 1000, true], ['poll', 500, true], ['focus-out', 500, true],
    ], ['delay', 'wait', 'notice', 'publish']],
    cueCandidate: [['validTimes', 'start', 'now', 'previous', 'hasCue'], [
      [true, 0, 10, 0, false], [true, 15, 10, 0, true], [true, 5, 10, 0, true],
      [true, 4, 10, 5, true], [true, 5, 10, 5, true], [false, 0, 0, 0, false],
    ]],
    holdSubmit: [['hasDraft', 'seeking', 'moved'], [
      [true, false, false], [true, true, false], [true, false, true], [false, true, true],
    ]],
  },
  interaction: {
    fileSizeBatch: [['array', 'count'], [[false, 0], [true, 0], [true, 8192], [true, 8193]]],
    fileSize: [['safeInteger', 'bytes'], [
      [false, 0], [true, -1], [true, 0], [true, 999], [true, 1000], [true, 12_345_678],
      ...[999_950, 999_950_000, 999_950_000_000, 999_950_000_000_000]
        .flatMap(boundary => [boundary - 1, boundary, boundary + 1].map(bytes => [true, bytes])),
      [true, Number.MAX_SAFE_INTEGER],
    ], ['valid', 'scaled', 'unit']],
    connectionView: [['state', 'now', 'retryAt', 'manualRetry'], [
      ['connecting', 100, 0, false], ['ready', 100, 0, false], ['disconnected', 0, 10_000, true],
      ['disconnected', 1, 10_000, false], ['disconnected', 9001, 10_000, true],
      ['disconnected', 10_001, 10_000, true], ['reconnecting', 100, 0, false],
    ], ['label', 'prefix', 'countdown', 'suffix', 'showRetry', 'retryTitle']],
    disconnectPlan: [['leaving', 'storedReason', 'socketReason', 'code', 'hasPanel', 'reconnect'], [
      [false, true, true, 1006, true, true], [false, false, true, 4000, false, true],
      [false, false, false, 1006, false, false], [false, false, false, 1000, false, true],
      [true, false, true, 4000, false, true],
    ], ['publish', 'preserveReason', 'includeCode', 'includeSocketReason', 'prefix', 'suffix', 'notice', 'logNotice']],
    startupFailureNotice: [['hasPanel'], [[false], [true]], ['prefix', 'report']],
    holdStartupSubmit: [['reconnect', 'booting'], [[false, false], [false, true], [true, false], [true, true]]],
    connectionOpen: [['leaving', 'hasSocket'], [[false, false], [false, true], [true, false], [true, true]],
      ['open', 'status']],
    historyResume: [['persisted', 'leaving', 'hasSocket'], [
      [false, false, false], [false, true, true], [true, false, true], [true, true, false], [true, true, true],
    ], ['resume', 'waitForClose']],
    connectionProfile: [['hasPanel', 'homeAster', 'requestedReconnect'], [
      [true, false, false], [false, true, false], [false, false, true], [false, false, false],
    ], ['reconnect', 'firstDelay', 'startupTimeout']],
    socketReplyAllowed: [['sameSocket', 'socketOpen'], [[true, true], [false, true], [true, false]]],
    agentInvocationAllowed: [['sameSocket', 'socketOpen', 'queued'], [
      [true, true, 0], [true, true, 63], [true, true, 64], [false, true, 1], [true, false, 1],
    ]],
    activate: [['sameMember', 'hasPrevious'], [[false, false], [false, true], [true, true]]],
    activeGroupAdmission: [['text', 'duplicate', 'used', 'array', 'count'], [
      [true, false, 15, true, 1], [true, false, 15, true, 64], [true, false, 16, true, 1],
      [true, false, 0, true, 0], [true, false, 0, true, 65], [true, true, 0, true, 1],
      [false, false, 0, true, 1], [true, false, 0, false, 1],
    ]],
    activeMemberId: [['id'], ['#a', '#a9-', '#9a', '#A', '#', '#' + 'a'.repeat(101), '#' + 'a'.repeat(102)].map(id => [id])],
    activeMemberAdmission: [['html', 'directChild', 'duplicate'], [
      [true, true, false], [false, true, false], [true, false, false], [true, true, true],
    ]],
    activeMemberInitial: [['active', 'hasPrevious'], [[false, false], [false, true], [true, false], [true, true]]],
    observationHandle: [['known', 'count'], [[true, 2048], [false, 2047], [false, 2048]], ['allocate', 'evict']],
    descriptionCards: [['count'], [[0], [128], [129]]],
    descriptionBinding: [['summary', 'button', 'panelMatches'], [
      [true, true, true], [false, true, true], [true, false, true], [true, true, false],
    ]],
    timingIntervals: [['started', 'enqueued', 'ended', 'hasDispatch', 'dispatched', 'revealed'], [
      [100, 101.25, 120.5, true, 103, 108], [100, 100, 100.5, false, 0, 0],
    ], ['input', 'dispatch', 'total', 'queue', 'reveal']],
    timingAge: [['now', 'recordedAt'], [[0, 1000], [1000, 1000], [1999, 1000], [2000, 1000], [3200, 1000]]],
    timingHost: [['host', 'exchange'], [[10, 9.5], [9, 10], [10, 10]]],
    timingBlocker: [['enqueued', 'dispatched', 'ended', 'started', 'count'], [
      [105, 101, 113.25, 104, 11], [105, 108, 113.25, 104, 12], [117, 108, 113.25, 104, 0],
    ], ['overlap', 'offset', 'keep']],
    timingEffectRequest: [['port'], [['browser.request'], ['browser.frontGateStatus'], ['browser.content'], ['']]],
    timingEffectSample: [['started', 'effectStarted', 'ended', 'count', 'previousReveal', 'hasReveal'], [
      [1, 10, 20.5, 47, false, true], [1, 10, 20.5, 48, true, true], [1, 10, 10, 0, false, false],
    ], ['elapsed', 'offset', 'keep', 'revealed']],
    timingResponse: [['ended', 'requestStarted', 'status'], [
      [20.5, 19, 200], [20.5, 19, 499], [20.5, 19, 500], [20.5, 19, 503],
    ], ['elapsed', 'failed']],
    timingFailure: [['request'], [[true], [false]]],
    timingEvict: [['count'], [[29], [30], [31]]],
    retryAt: [['enabled', 'now', 'delay'], [[false, 100_000, 250], [true, 100_000, 250]]],
    backoff: [['delay', 'hasPanel'], [[250, false], [4000, false], [30_000, true], [60_000, true]]],
    retryPlan: [['enabled', 'now', 'delay', 'hasPanel'], [
      [false, 100_000, 250, false], [false, 100_000, 10_000, true], [true, 100_000, 250, false],
      [true, 100_000, 4000, false], [true, 100_000, 10_000, true], [true, 100_000, 60_000, true],
    ], ['at', 'schedule', 'nextDelay', 'state', 'countdownInterval', 'panelState', 'wait']],
    delayAllowed: [['integer', 'milliseconds'], [[true, 0], [true, 5000], [true, 5001], [true, -1], [false, 0]]],
    fileReadAction: [['fileInput', 'integer', 'maxBytes', 'hasFile', 'size'], [
      [true, true, 3_000_000, true, 3_000_000], [true, true, 3_000_000, true, 3_000_001],
      [true, true, 3_000_001, true, 0], [true, true, 1, true, 0], [true, true, 0, true, 0],
      [false, true, 1, false, 0], [true, false, 0, true, 0], [true, true, 1, false, 0],
    ]],
    retryAllowed: [['now', 'lastAttempt', 'hasAttempt', 'hasSocket'], [
      [50_000, 0, false, false], [50_000, 0, false, true], [50_000, 40_001, true, false], [50_000, 40_000, true, false],
    ]],
    startupReceiver: [['receiver', 'arrays', 'paths', 'hashes', 'encoded', 'seen', 'used'], [
      ['home', true, 8, 8, 8, false, 15], ['home', true, 8, 8, 8, false, 16],
      ['a'.repeat(32), true, 8, 8, 8, true, 16], ['a'.repeat(33), true, 0, 0, 0, false, 0],
      ['9home', true, 0, 0, 0, false, 0], ['home', false, 0, 0, 0, false, 0], ['home', true, 9, 0, 0, false, 0],
      ['home', true, 0, 9, 0, false, 0], ['home', true, 0, 0, 9, true, 0],
    ]],
    startupRoute: [['pathAllowed', 'hashAllowed', 'hasSearch', 'hasHash'], [
      [true, true, true, true], [true, false, false, true], [false, true, true, true], [true, false, false, false],
    ], ['hadInput', 'launchHash']],
    startupField: [['key', 'encoded'], [['x', true], ['x-0', false], ['9x', true], ['xX', false], ['', false]]],
    startupFields: [['length', 'count', 'unique'], [[4096, 16, true], [4097, 16, true], [4, 17, true], [4, 2, false]]],
    startupCleanup: [['consume', 'samePath', 'hasSearch', 'sameLaunchHash'], [
      [false, true, true, true], [true, false, true, true], [true, true, true, false],
      [true, true, false, true], [true, true, false, false],
    ]],
    batchLength: [['array', 'count'], [[false, 1], [true, 0], [true, 1], [true, 64], [true, 65]]],
    batchPort: [['port'], [
      ...['dom.exists', 'browser.property', 'browser.write', 'browser.attribute', 'browser.focus', 'browser.activate',
        'browser.dialog', 'browser.batch', 'constructor', ''].map(port => [port]),
    ]],
    batchStep: [['port', 'record', 'conditional', 'guardPort', 'save', 'key', 'duplicate'], [
      [1, true, false, 0, true, 'result2', false], [3, true, true, 1, false, '', false],
      [3, true, true, 0, false, '', false], [3, true, true, 2, false, '', false],
      [0, true, false, 0, false, '', false], [1, false, false, 0, false, '', false],
      [1, true, false, 0, true, 'bad-key', false], [1, true, false, 0, true, 'result2', true],
      [1, true, true, 1, true, 'result2', false], [1, true, false, 0, true, 'a'.repeat(40), false],
      [1, true, false, 0, true, 'a'.repeat(41), false], [1, true, false, 0, true, 'Bad', false],
    ]],
    batchExecute: [['conditional', 'observed'], [[true, true], [true, false], [false, true], [false, false]]],
    markReveal: [['port', 'matchingTarget', 'open', 'unhide'], [
      ['browser.dialog', true, true, false], ['browser.dialog', true, false, false],
      ['browser.write', true, false, true], ['browser.write', true, false, false],
      ['browser.write', false, false, true], ['browser.content', true, true, true],
    ]],
    bootBatchAllowed: [['booting', 'array', 'count'], [
      [false, true, 1], [true, false, 1], [true, true, 0], [true, true, 1], [true, true, 64], [true, true, 65],
    ]],
    preflightPlain: [['hasSearch', 'hasHash', 'sameLocation'], [
      [false, false, true], [true, false, true], [false, true, true], [false, false, false],
    ]],
    preflightRead: [['port', 'plain'], [
      ['browser.startup', true], ['browser.startup', false], ['browser.location', true], ['browser.location', false],
      ...['dom.exists', 'browser.property', 'storage.read', 'state.get', 'browser.write', 'constructor'].map(port => [port, false]),
    ]],
    deferredBootEffect: [['port'], [
      ...['browser.startup', 'browser.asterStream', 'browser.countdown', 'browser.on', 'browser.onMany',
        'browser.activeGroup', 'browser.appDescriptions', 'browser.copyText', 'browser.guard',
        'browser.write', 'browser.attribute', 'browser.content', 'state.set', 'state.get', 'browser.preflight',
        'browser.bootEffects', 'constructor'].map(port => [port]),
    ]],
    bootStartupMatches: [['sameFirst', 'samePath', 'hadInput', 'hasHash', 'hasFields'], [
      [true, true, false, false, false], [false, true, false, false, false], [true, false, false, false, false],
      [true, true, true, false, false], [true, true, false, true, false], [true, true, false, false, true],
    ]],
    followupBootEffect: [['port', 'present', 'known'], [
      ['', false, false], ['browser.bootEffects', true, true], ['browser.preflight', true, true],
      ['browser.request', true, true], ['constructor', true, false],
    ]],
    storageInTab: [['scope'], [['tab'], ['local'], ['Tab'], ['']]],
    storageReadAllowed: [['present', 'length', 'limit'], [
      [false, 0, -1], [true, 0, -1], [true, 2, 1], [true, 2, 2], [true, 2, 2.5], [true, 65537, 65536],
    ]],
    documentStateKey: [['text', 'length'], [[false, 0], [true, 0], [true, 512], [true, 513]]],
    documentStateAdmission: [['used', 'previousSize', 'keyLength', 'valueLength', 'remove', 'count', 'existing'], [
      [3_999_999, 0, 0, 1, false, 63, false], [3_999_999, 0, 1, 1, false, 63, false],
      [1, 0, 0, 1, false, 64, false], [10, 2, 1, 2, false, 64, true],
      [10, 2, 1, 0, true, 64, true], [10, 0, 1, 0, true, 64, false],
    ], ['total', 'allowed', 'size']],
    formField: [['name', 'nameLength', 'text', 'valueLength', 'repeated', 'count', 'used'], [
      ['a', true, 0, false, 0, 0], ['a'.repeat(80), true, 16304, false, 63, 0],
      ['a'.repeat(80), true, 16305, false, 63, 0], ['name', true, 8, false, 5, 16373],
      ['', true, 1, false, 0, 0], ['a'.repeat(81), true, 0, false, 0, 0],
      ['a?!b', true, 2, false, 0, 0], ['name', false, 0, false, 0, 0],
      ['name', true, 2, true, 1, 7], ['name', true, 2, false, 64, 16380],
    ].map(([name, ...fields]) => [name, name.length, ...fields]), ['action', 'size']],
    sessionRequestAllowed: [['inFlight', 'pending'], [[false, false], [true, false], [false, true], [true, true]]],
    sessionRetry: [['received', 'status', 'aborted'], [
      [false, 0, false], [true, 200, false], [true, 500, false], [true, 502, false],
      [true, 503, false], [true, 504, false], [true, 505, false], [false, 0, true], [true, 503, true],
    ]],
    sessionFields: [['identityText', 'usernameText', 'xAvailable'], [
      [true, true, true], [true, false, false], [false, true, false], [false, false, true],
    ], ['identityLimit', 'usernameLimit', 'xAvailable']],
    queueHasRoom: [['queued'], [[0], [63], [64], [65]]],
    canDispatch: [['busy', 'hasQueued', 'socketOpen'], [
      [false, true, true], [true, true, true], [false, false, true], [false, true, false],
    ]],
    canDeliverObservation: [['aborted', 'sameSocket', 'socketOpen', 'queued'], [
      [false, true, true, 0], [false, true, true, 63], [false, true, true, 64],
      [true, true, true, 0], [false, false, true, 0], [false, true, false, 0],
    ]],
    domWriteProperty: [['name'], [
      ...['value', 'checked', 'disabled', 'hidden', 'readOnly', 'tabIndex', 'textContent', 'className',
        'open', 'max', 'min', 'title', 'innerHTML', 'src', 'onclick', ''].map(name => [name]),
    ]],
    domAttribute: [['name', 'anchor', 'image', 'page', 'nullValue', 'boolean', 'valueTrue'], [
      ['aria-current', true, false, true, false, false, false],
      ['aria-current', true, false, false, true, false, false],
      ['aria-current', false, false, true, false, false, false],
      ['aria-pressed', false, false, false, false, true, false],
      ['aria-pressed', false, false, false, false, false, false],
      ['data-test', false, false, false, false, true, true],
      ['data-test', false, false, false, false, true, false],
      ['data-test', false, false, false, false, false, false],
      ...['data-7test', 'data-Test', 'data-' + 'a'.repeat(64), 'data-' + 'a'.repeat(65)].map(name =>
        [name, false, false, false, false, true, true]),
      ['src', false, true, false, true, false, false],
      ['src', false, true, false, false, false, false],
      ['src', true, false, false, false, false, false],
      ['onclick', false, false, false, false, false, false],
    ]],
    pngPayloadOffset: [['head', 'length'], [
      ['data:image/png;base64,', 22], ['data:image/png;base64,A', 23],
      ['data:image/png;base64,', 131072], ['data:image/png;base64,', 131073],
      ['data:image/gif;base64,A', 23], ['DATA:image/png;base64,A', 23], ['', 0],
    ]],
    pngPayloadChunk: [['chunk'], [
      [''], ['AZaz09+/='], ['a'.repeat(128)], ['a-'], ['a\n'], ['a🙂'], ['a_'],
    ]],
    clipboardControl: [['id'], ['#a', '#9', '#' + 'a'.repeat(101), '#' + 'a'.repeat(102), 'a'].map(id => [id])],
    timingLabelAllowed: [['click', 'text', 'length'], [
      [true, true, 0], [true, true, 1], [true, true, 80], [true, true, 81], [false, true, 1], [true, false, 1],
    ]],
    timingTarget: [['id'], ['#0', '#--', '#A', '#', '#' + '0'.repeat(100), '#' + '0'.repeat(101)].map(id => [id])],
    launchId: [['id'], ['0', '123', '', '１２', '0'.repeat(16), '0'.repeat(17), '12\n'].map(id => [id])],
    clipboardTrigger: [['trusted', 'matches'], [[true, true], [false, true], [true, false]]],
    clipboardSelection: [['readOnly', 'feedback', 'length'], [
      [true, true, 0], [true, true, 1], [true, true, 96000], [true, true, 96001],
      [false, true, 20], [true, false, 20],
    ]],
    clipboardNotice: [['copied'], [[true], [false]]],
    observationReply: [['status'], [[0], [200], [204], [401], [503]]],
    bootCompletion: [['booting', 'reconnect', 'failed'], [
      [true, true, false], [true, true, true], [true, false, true], [false, true, true], [false, false, false],
    ], ['close', 'ready', 'status']],
    startupTimedOut: [['sameSocket', 'booting'], [[true, true], [false, true], [true, false], [false, false]],
      ['close', 'reason']],
    asterAttempt: [['attempt', 'aborted'], [[0, false], [2, false], [3, false], [1, true]]],
    asterRetryDelay: [['attempt', 'aborted'], [[0, false], [1, false], [2, false], [2, true]]],
    asterCredential: [['capture', 'thread', 'bearer'], [
      [false, 'a'.repeat(32), 'x'.repeat(43)], [true, 'a'.repeat(32), 'x'.repeat(43)],
      [true, 'a'.repeat(32), 'b'.repeat(64)], [true, 'a'.repeat(32), 'B'.repeat(64)],
      [true, 'a'.repeat(31), 'b'.repeat(43)], [true, 'A'.repeat(32), 'b'.repeat(43)],
      [true, 'a'.repeat(32), 'x'.repeat(42) + '='], [true, 'a'.repeat(32), 'x'.repeat(129)],
    ]],
    asterChunkBoundary: [['previousCR', 'leadingLF', 'trailingCR'], [
      [false, false, false], [false, true, false], [true, false, true], [true, true, false], [true, true, true],
    ], ['skip', 'carryCR']],
    asterBuffer: [['boundary', 'pending'], [
      [-1, 0], [-1, 5], [-1, 131071], [-1, 131072], [-1, 131073],
      [0, 3], [131071, 150000], [131072, 150000], [131073, 150000],
    ]],
    asterDispatchFrame: [['action', 'expected', 'observed'], [
      [1, 'fixture', 'fixture'], [2, 'fixture', 'fixture'], [2, 'fixture', 'other'], [1, '', ''],
    ]],
    asterQueueAction: [['pending', 'room'], [[true, false], [true, true], [false, true], [false, false]]],
    asterResponse: [['ok', 'mediaType', 'hasBody'], [
      [true, 'text/event-stream', true], [false, 'text/event-stream', true],
      [true, 'text/event-stream-unsupported', true], [true, 'text/event-stream', false],
    ]],
    asterField: [['field', 'hasColon', 'space', 'eventPresent'], [
      ['event', true, true, false], ['event', true, false, false], ['event', true, false, true],
      ['data', true, true, true], ['data', false, false, true], ['data', true, false, true], ['', true, true, false],
    ], ['kind', 'skip']],
    asterFrameKind: [['name'], [['update'], ['done'], ['unknown'], ['done '], ['']]],
    asterWatchAction: [['sameMarker', 'hasWatch', 'expected', 'observed'], [
      [true, true, 'a'.repeat(32), 'a'.repeat(32)], [true, true, 'a'.repeat(32), 'b'.repeat(32)],
      [false, false, '', ''], [false, true, '', ''],
      [false, true, 'a'.repeat(32), 'b'.repeat(32)], [false, true, 'a'.repeat(32), 'a'.repeat(32)],
    ]],
    transportLimits: [[], [[]], ['requestDeadline', 'asterDeadline', 'delayLimit', 'fileLimit']],
    overlayPlacement: [['anchored', 'pointX', 'pointY', 'anchorTop', 'anchorBottom', 'width', 'height', 'viewportWidth', 'viewportHeight'], [
      [false, 10, 20, 0, 0, 100, 50, 500, 400],
      [false, 900, 900, 0, 0, 100, 50, 500, 400],
      [false, -10, -20, 0, 0, 100, 50, 500, 400],
      [true, 450, 0, 360, 390, 100, 50, 500, 400],
      [true, 40, 0, 310, 342, 100, 50, 500, 400],
      [true, 40, 0, 20, 50, 100, 50, 500, 400],
      [true, 40, 0, 20, 50, 600, 500, 500, 400],
    ], ['left', 'top']],
    eventAdmission: [['excluded', 'delegated', 'withinScope', 'unmodified', 'primary', 'modified', 'alreadyPrevented',
      'preventDefault', 'preventKey', 'waitingForBoot'], [
      [false, true, true, true, true, false, false, true, false, false],
      [true, true, true, true, true, false, false, true, false, false],
      [false, true, false, true, true, false, false, true, false, false],
      [false, true, true, true, false, false, false, true, false, false],
      [false, true, true, true, true, true, false, true, false, false],
      [false, true, true, true, true, false, true, true, false, false],
      [false, false, false, false, false, false, false, false, true, false],
      [false, false, false, false, false, false, false, false, true, true],
      [false, false, false, false, false, false, false, false, false, true],
    ], ['prevent', 'dispatch']],
    canPoll: [['busy', 'queued', 'socketOpen'], [[false, false, true], [true, false, true], [false, true, true], [false, false, false]]],
    intervalSelector: [['ref', 'nullRef'], [['window', false], ['document', false], ['#status', false],
      ['', false], ['', true], ['Window', false]]],
    intervalDispatch: [['scoped', 'visible'], [[false, false], [false, true], [true, false], [true, true]]],
    intervalAllowed: [['whole', 'milliseconds'], [[true, 499], [true, 500], [false, 500.5], [true, 60000], [true, 60001]]],
    requestRoute: [['method', 'path'], [
      ['GET', '/workspace/session'], ['POST', '/workspace/sign-out'], ['GET', '/workspace/aster/events'],
      ['GET', '/workspace/mobile'], ['POST', '/workspace/mobile'], ['PUT', '/workspace/session'],
    ]],
    requestForm: [['path', 'mobileOffer', 'length'], [
      ['/workspace/formation/records', false, 32768], ['/workspace/formation/records', false, 32769],
      ['/workspace/mobile/pair/test/offer', true, 65536], ['/workspace/mobile/pair/test/offer', true, 65537],
      ['/workspace/default', false, 16384], ['/workspace/default', false, 16385],
    ]],
    requestQuery: [['count'], [[0], [8], [9]]],
    queryField: [['key', 'text', 'length'], [
      ['a'.repeat(64), true, 1024], ['name', true, 1025], ['name[]', true, 0],
      ['a'.repeat(65), true, 0], ['name', false, 0], ['', true, 0],
    ]],
    requestResponse: [['path', 'asterView', 'ok', 'subscription', 'fragment'], [
      ['/identity-management/aster/', false, true, true, true], ['/identity-management/aster/', false, false, true, true],
      ['/identity-management/aster/', false, true, false, false], ['/identity-management/', true, true, true, true],
      ['/workspace/home', false, true, true, false], ['/workspace/home', false, true, true, true],
    ]],
    requestBearer: [['present', 'bearer'], [
      [false, ''], [true, ''], [true, 'A_-0'], [true, 'a'.repeat(128)], [true, 'a'.repeat(129)], [true, 'a='],
    ]],
    asterStartupCoordinates: [[], [[]], ['bridge', 'panel', 'view', 'openKey', 'openValue', 'stateAttribute', 'ready']],
    asterStartupPlan: [['connected', 'view', 'restored', 'ready', 'deadline', 'idle'], [
      [false, '', false, false, false, true], [true, 'aster', false, false, false, true],
      [true, '', true, false, false, false], [true, '', false, false, false, true],
      [true, '', false, true, false, true], [true, '', false, false, true, false],
    ], ['action', 'delay']],
    frontGatePort: [['integer', 'canonical', 'port'], [
      [true, true, 1023], [true, true, 1024], [true, true, 65535], [true, true, 65536],
      [true, false, 24220], [false, false, 0],
    ]],
    descriptionTransition: [['event', 'preview', 'mouse', 'open', 'hidden'], [
      ['enter', false, true, false, false], ['enter', false, false, false, false],
      ['enter', true, true, true, false], ['leave', true, false, true, false],
      ['leave', false, false, true, false], ['show', false, false, false, true],
      ['show', false, false, false, false], ['hide', true, false, true, false],
      ['click', true, false, true, false], ['click', false, false, true, false],
      ['closed', true, false, false, false], ['other', true, true, true, false],
    ], ['action', 'delay', 'preview']],
    descriptionLayout: [['height', 'scrollHeight', 'open'], [
      [0, 200, false], [20, 21, false], [20, 22, false], [20, 20, true], [20, 22, true],
    ]],
    workspaceObservationTrigger: [['ref', 'event', 'booting', 'backgroundSession'], [
      ['window', 'workspace-access', true, false], ['window', 'workspace-access', false, true],
      ['document', 'workspace-access', true, false], ['window', 'focus', true, true],
      ['window', 'pageshow', false, true], ['document', 'pageshow', true, true],
      ['window', 'click', false, true], ['document', 'click', true, false],
    ]],
    sessionObservation: [['initial', 'booting', 'leaving', 'socketOpen'], [
      [true, true, false, true], [true, true, true, true], [true, false, false, true],
      [false, false, false, true], [false, true, false, true], [false, false, false, false],
    ]],
  },
};

try {
  await mkdir(application);
  for (const [name, exports] of Object.entries(fixtures)) {
    const output = join(stage, name);
    const duplicate = output + '-duplicate';
    const build = directory => run('build', '--browser', browser, name + '.rel', browser, directory);
    assert.equal(build(output), build(duplicate));
    const bytes = await readFile(join(output, 'browser.wasm'));
    assert.deepEqual(bytes, await readFile(join(duplicate, 'browser.wasm')));
    if (name === 'canvas') {
      const map = await readFile(join(output, 'browser.wasm.map.rel'), 'utf8');
      assert.match(map, /\("camera", "result", "x:Number"\)\n\("camera", "result", "y:Number"\)\n\("camera", "result", "scale:Number"\)/);
    }
    const wasm = new WebAssembly.Module(bytes);
    if (name === 'temple') {
      assert(!WebAssembly.Module.exports(wasm).some(entry => entry.name === 'platformViewCode'));
      assert.doesNotMatch(await readFile(join(output, 'browser.wasm.map.rel'), 'utf8'), /platformViewCode/);
    }
    const math = name === 'canvas' ? ['cos', 'hypot', 'remainder', 'sin'] : [];
    assert.deepEqual(WebAssembly.Module.imports(wasm),
      math.map(name => ({module: 'encounter.math', name, kind: 'function'})));
    const instance = new WebAssembly.Instance(wasm, {
      'encounter.math': {sin: Math.sin, cos: Math.cos, hypot: Math.hypot, remainder: (value, divisor) => value % divisor},
    }).exports;
    if (name === 'mobile') {
      const helpers = ['shellPrefix', 'phonePath', 'runtimePath', 'shellPathCode'];
      const map = await readFile(join(output, 'browser.wasm.map.rel'), 'utf8');
      assert(helpers.every(helper => !Object.hasOwn(instance, helper) && !map.includes(helper)));
      const overlong = 'x'.repeat(129);
      assert.equal(instance.receiptAction(true, ...browserWasmText(instance.memory, 'digest', 'digest', overlong, overlong)), 1);
      const oddLength = 1n << 32n;
      assert.equal(instance.receiptAction(true, ...browserWasmText(instance.memory, 'digest', 'digest'), oddLength, oddLength), 1);
      const outsidePage = (2n << 32n) | 65535n;
      assert.throws(() => instance.receiptAction(true, outsidePage, outsidePage, 0n, 0n), WebAssembly.RuntimeError);
    }
    if (name === 'preview') {
      const limit = instance.textEqualityUnits.value;
      assert.equal(limit, 4096);
      const long = 'x'.repeat(limit - 1) + '🙂' + 'tail';
      for (const [filter, context, expected] of [
        ['', long, true], [long, long, true], [long, long.replace('🙂', '🙃'), false], [long, long + 'x', false],
      ]) {
        assert.equal(browserWasmTextMatches(instance.memory, instance.commentVisible, filter, context, limit), expected);
      }
      const [status, reduction] = browserWasmText(instance.memory, '120 approved minutes', 'Reduction to 90');
      const oddStatus = (39n << 32n) | (status & 0xffff_ffffn);
      const [approved, proposal] = instance.leaveCard(oddStatus, reduction, false);
      assert.equal(approved, 0);
      assert.equal(browserWasmTextResult(instance.memory, proposal), 'propose');
      const overlong = browserWasmText(instance.memory, 'x'.repeat(129))[0];
      const [overlongApproved, overlongProposal] = instance.leaveCard(overlong, overlong, false);
      assert.equal(overlongApproved, 0);
      assert.equal(browserWasmTextResult(instance.memory, overlongProposal), '');
    }
    await copyFile(join(browser, name + '.encounter'), join(application, 'policy.encounter'));
    await writeFile(join(application, 'application.rel'), [
      '("application", "stateProfile", "encounter/browser-wasm-test/1")',
      '("application", "module", "policy.encounter")',
      '("application", "module", "test.encounter")',
      '("application", "entry", "cli.main")',
      ...['number.calculate', 'json.parse', 'json.stringify', 'text.startsWith', 'text.endsWith', 'text.matches']
        .map(grant => '("application", "grant", "' + grant + '")'),
    ].join('\n'));
    for (const [entry, [parameters, cases, fields]] of Object.entries(exports)) {
      await writeFile(join(application, 'test.encounter'), [
        'process-module "temple/surface-process-module/1"',
        'process cli.main:',
        '  port json.parse { text = at($eventInput, 0) } → cases',
        '  fold $cases as args; results starts list():',
        ...parameters.map((parameter, index) => '    let ' + parameter + ' = at($args, ' + index + ')'),
        '    call ' + (name === 'live-events' ? 'liveEvents' : name === 'aster-frame' ? 'asterFrame' : name) + '.' + entry,
        '    yield append($results, list($result)) → outputs',
        '  port json.stringify { value = $outputs } → result',
      ].join('\n'));
      const expected = JSON.parse(run('run', '--declaration', application, 'application.rel', JSON.stringify(cases)));
      const actual = cases.map(input => {
        const texts = input.filter(value => typeof value === 'string');
        const packed = texts.length ? browserWasmText(instance.memory, ...texts) : [];
        const result = instance[entry](...input.map(value => typeof value === 'string' ? packed.shift() : value));
        const decode = value => typeof value === 'bigint' ? browserWasmTextResult(instance.memory, value) : value;
        return Array.isArray(result) ? result.map(decode) : decode(result);
      });
      const scalar = value => typeof value === 'boolean' ? Number(value) : value;
      const reference = expected.map(value => fields ? fields.map(field => scalar(value[field])) : scalar(value));
      if (name === 'canvas' && [
        'sceneCamera', 'beaconGlow', 'beaconReflection', 'boatBob', 'flightPosition', 'flightTrail',
        'collisionSlip', 'intentSlip', 'strataPlate', 'strataStar', 'networkNode', 'rebuildPlate', 'homePhase', 'routeSegment',
      ].includes(entry)) {
        // The browser and native trigonometric implementations can differ by a few ulps.
        const expectedFields = reference.flat();
        actual.flat().forEach((value, index) => {
          const expectedValue = expectedFields[index];
          if (typeof expectedValue === 'number') {
            assert.equal(typeof value, 'number', name + '.' + entry);
            assert(Math.abs(value - expectedValue) <= 4 * Number.EPSILON * Math.max(1, Math.abs(expectedValue)), name + '.' + entry);
          } else {
            assert.equal(value, expectedValue, name + '.' + entry);
          }
        });
      } else {
        assert.deepEqual(actual, reference, name + '.' + entry);
      }
      if (name === 'mobile' && Object.hasOwn(legacyMobilePolicies, entry)) {
        const legacy = cases.map(input => legacyMobilePolicies[entry](...input));
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy Mobile ' + entry);
      } else if (name === 'preview') {
        const legacy = cases.map(input => {
          if (entry === 'sameContext') return encounterLegacyPreview.sameContext(input[2], input[1] < 0 ? null : input[3]);
          return encounterLegacyPreview[entry](...(entry === 'commentVisible' ? input.slice(2) : input));
        });
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy Preview ' + entry);
      } else if (name === 'assurance') {
        const legacy = cases.map(input => encounterLegacyAssurance[entry](...input));
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy Assurance ' + entry);
      } else if (name === 'temple' && ['retryConnection', 'connectionTimedOut', 'subscriptionRequest',
        'subscriptionReply', 'subscriptionTimedOut', 'workspaceHistory', 'workspacePath', 'historyRestore', 'greetingPlan',
        'frameMount', 'frameObservation', 'frameSignIn', 'platformTarget', 'identityAdmission',
        'savedTempleAdmission', 'retainSavedTemple', 'launchFields', 'launchValueAllowed', 'originInput', 'connectionCoordinates'].includes(entry)) {
        const legacy = cases.map(input => encounterLegacyTemple[entry](...input));
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy Temple ' + entry);
      } else if (name === 'live-events' && ['replace', 'queuedApplied', 'inspectQueuedRoute', 'finishQueued', 'socketCoordinates',
        'reconnectRequest', 'reconnectAction', 'sameCoordinate'].includes(entry)) {
        const legacy = cases.map(input => encounterLegacyLiveEvents[entry](...input));
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy Live Events ' + entry);
      } else if (name === 'canvas' && ['surfaceProfile', 'seaLayout', 'settingsAction', 'settingsText',
        'settingsSurface', 'narrationResult', 'narrationFault', 'camera', 'beaconLayout', 'beaconStripes',
        'placeVertex', 'routePoint'].includes(entry)) {
        const legacy = cases.map(input => encounterLegacyCanvasControls[entry](...input));
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy Canvas ' + entry);
      } else if (name === 'countdown' && ['bindingAllowed', 'choiceAllowed', 'selectedInterval'].includes(entry)) {
        assert.deepEqual(actual, cases.map(input => scalar(encounterLegacyCountdown[entry](...input))), 'legacy countdown ' + entry);
      } else if (name === 'interaction' && ['activeGroupAdmission', 'activeMemberId', 'activeMemberAdmission', 'activeMemberInitial',
        'observationHandle', 'descriptionCards', 'descriptionBinding', 'timingIntervals', 'timingHost', 'timingAge', 'timingBlocker',
        'timingEffectRequest', 'timingEffectSample', 'timingResponse', 'timingFailure', 'timingEvict', 'fileSizeBatch', 'fileSize', 'connectionView', 'disconnectPlan', 'connectionOpen',
        'startupFailureNotice', 'holdStartupSubmit', 'workspaceObservationTrigger', 'intervalSelector', 'intervalDispatch', 'storageInTab', 'storageReadAllowed',
        'retryPlan', 'bootCompletion', 'historyResume', 'delayAllowed', 'fileReadAction',
        'startupReceiver', 'startupRoute', 'startupField', 'batchStep', 'connectionProfile', 'socketReplyAllowed',
        'agentInvocationAllowed', 'sessionRequestAllowed', 'sessionRetry', 'sessionFields', 'canDeliverObservation',
        'formField', 'asterCredential', 'queryField', 'requestBearer', 'asterChunkBoundary', 'asterBuffer', 'asterWatchAction', 'transportLimits', 'clipboardControl', 'clipboardTrigger',
        'clipboardSelection', 'clipboardNotice', 'timingLabelAllowed', 'timingTarget', 'launchId', 'startupTimedOut', 'domWriteProperty',
        'domAttribute', 'pngPayloadOffset', 'pngPayloadChunk', 'asterResponse', 'asterField'].includes(entry)) {
        const legacy = cases.map(input => encounterLegacyInteraction[entry](...input));
        assert.deepEqual(actual, legacy.map(value => fields ? value.map(scalar) : scalar(value)), 'legacy browser interaction ' + entry);
      }
    }
  }
  const catalogs = [
    ['appdev', 'encounter/appdev-browser-wasm/3', ['assurance', 'aster-frame', 'countdown', 'interaction', 'mobile', 'temple']],
    ['work', 'encounter/appdev-work-browser-wasm/1', ['interaction']],
    ['standalone', 'encounter/standalone-browser-wasm/1', ['canvas', 'live-events', 'preview']],
  ];
  const bundles = new Map();
  for (const [name, contract, modules] of catalogs) {
    const output = join(stage, name + '-catalog');
    const build = directory => run('build', '--browser', browser, name + '.rel', browser, directory);
    const pin = build(output);
    assert.equal(build(output + '-duplicate'), pin);
    const catalog = await readFile(join(output, 'browser-wasm.rel'), 'utf8');
    assert.equal(createHash('sha256').update(catalog).digest('hex'), pin);
    const lines = ['("wasm", "contract", "' + contract + '")'];
    assert.deepEqual((await readdir(join(output, 'browser-wasm'))).sort(), modules);
    for (const module of modules) {
      const packaged = join(output, 'browser-wasm', module);
      const receipt = await readFile(join(packaged, 'build-receipt.rel'));
      lines.push('("' + module + '", "receiptSha256", "' + createHash('sha256').update(receipt).digest('hex') + '")');
      for (const file of ['browser.wasm', 'browser.wasm.map.rel', 'build-receipt.rel']) {
        assert.deepEqual(await readFile(join(packaged, file)), await readFile(join(stage, module, file)));
        assert.deepEqual(await readFile(join(output + '-duplicate', 'browser-wasm', module, file)),
          await readFile(join(packaged, file)));
      }
    }
    assert.equal(catalog, lines.join('\n') + '\n');
    bundles.set(name, {output, pin, catalog});
  }
  for (const name of ['work', 'standalone']) {
    const sources = join(stage, name + '-partial');
    await mkdir(sources);
    const declaration = await readFile(join(browser, name + '.rel'), 'utf8');
    await writeFile(join(sources, name + '.rel'), declaration.trimEnd().split('\n').slice(0, -1).join('\n') + '\n');
    const output = sources + '-output';
    const rejected = spawnSync(encounter, ['build', '--browser', sources, name + '.rel', sources, output],
      {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /invalid AppDev browser Wasm build declaration/);
    await assert.rejects(access(output), {code: 'ENOENT'});
  }
  const {output: home, pin: catalogPin, catalog} = bundles.get('appdev');
  const concurrent = join(stage, 'home-concurrent');
  const buildConcurrently = () => new Promise(resolve => {
    execFile(encounter, ['build', '--browser', browser, 'appdev.rel', browser, concurrent],
      {encoding: 'utf8', timeout: 10_000}, (error, stdout) => resolve({error, stdout: stdout.trim()}));
  });
  const builds = Promise.all([buildConcurrently(), buildConcurrently()]);
  const deadline = Date.now() + 10_000;
  while (true) {
    try {
      await access(concurrent);
      break;
    } catch (error) {
      assert.equal(error.code, 'ENOENT');
      assert(Date.now() < deadline, 'The concurrent Wasm builds did not publish');
      await delay(5);
    }
  }
  assert.equal(await readFile(join(concurrent, 'browser-wasm.rel'), 'utf8'), catalog);
  for (const name of catalogs[0][2]) {
    for (const file of ['browser.wasm', 'browser.wasm.map.rel', 'build-receipt.rel']) {
      assert.deepEqual(await readFile(join(concurrent, 'browser-wasm', name, file)),
        await readFile(join(home, 'browser-wasm', name, file)));
    }
  }
  const results = await builds;
  assert.equal(results.filter(result => !result.error).length, 1);
  assert.equal(results.find(result => !result.error).stdout, catalogPin);
  assert.equal(results.find(result => result.error).stdout, '');
  assert(!(await readdir(stage)).some(name => name.startsWith('.encounter-wasm-')));
  for (const version of [1, 2]) {
    const sources = join(stage, 'retired-home-build-' + version);
    await mkdir(sources);
    await writeFile(join(sources, 'appdev.rel'), '("wasm", "contract", "encounter/appdev-browser-wasm-build/' + version + '")\n');
    const retired = join(stage, 'retired-home-output-' + version);
    const rejected = spawnSync(encounter, ['build', '--browser', sources, 'appdev.rel', sources, retired], {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /partial Home browser Wasm builds are retired/);
    await assert.rejects(access(retired), {code: 'ENOENT'});
  }
  const work = join(stage, 'work');
  const workPin = run('build', '--browser', browser, 'work.rel', browser, work);
  const workCatalog = await readFile(join(work, 'browser-wasm.rel'), 'utf8');
  assert.equal(createHash('sha256').update(workCatalog).digest('hex'), workPin);
  assert.match(workCatalog, /encounter\/appdev-work-browser-wasm\/1/);
  const workModule = join(work, 'browser-wasm', 'interaction');
  const workReceipt = await readFile(join(workModule, 'build-receipt.rel'));
  assert(workCatalog.includes(createHash('sha256').update(workReceipt).digest('hex')));
  for (const file of ['browser.wasm', 'browser.wasm.map.rel', 'build-receipt.rel']) {
    assert.deepEqual(await readFile(join(workModule, file)), await readFile(join(stage, 'interaction', file)));
  }
  const invalid = join(stage, 'invalid');
  await mkdir(invalid);
  const recursive = [
    '("wasm", "contract", "encounter/browser-wasm/1")',
    '("wasm", "source", "invalid.encounter")',
    '("entry", "entry", "demo.entry")',
    '("entry", "result", "Number")',
    '("helper", "entry", "demo.helper")',
    '("helper", "result", "Number")',
  ].join('\n');
  await writeFile(join(invalid, 'wasm.rel'), recursive);
  await writeFile(join(invalid, 'invalid.encounter'), [
    'process-module "temple/surface-process-module/1"',
    'process demo.entry:',
    '  call demo.helper',
    '  let result = $result',
    'process demo.helper:',
    '  call demo.entry',
    '  let result = $result',
  ].join('\n'));
  const refused = join(stage, 'refused-output');
  const failure = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
    {encoding: 'utf8', timeout: 10_000});
  assert.ifError(failure.error);
  assert.notEqual(failure.status, 0);
  assert.match(failure.stderr, /invalid\.encounter:2: demo\.entry: recursive browser Wasm helper call/);
  await assert.rejects(access(refused), {code: 'ENOENT'});
  for (const [declaration, error] of [
    [recursive.replace('("helper", "entry"', '("helper", "helper"'),
      /recursive browser Wasm helper call/],
    [recursive + '\n("helper", "helper", "demo.helper")',
      /cannot be both an entry and a helper/],
  ]) {
    await writeFile(join(invalid, 'wasm.rel'), declaration);
    const rejected = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
      {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, error);
    await assert.rejects(access(refused), {code: 'ENOENT'});
  }
  for (const [helperBody, error] of [
    [['  call demo.helper', '  let result = $result'], /demo\.helper: recursive browser Wasm helper call/],
    [['  let result = 0', '  when true:', '    let result = 1'], /expected a straight-line scalar browser Wasm helper/],
  ]) {
    await writeFile(join(invalid, 'wasm.rel'), recursive.replace('("helper", "entry"', '("helper", "helper"'));
    await writeFile(join(invalid, 'invalid.encounter'), [
      'process-module "temple/surface-process-module/1"',
      'process demo.entry:',
      '  call demo.helper',
      '  let result = $result',
      'process demo.helper:',
      ...helperBody,
    ].join('\n'));
    const rejected = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
      {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, error);
    await assert.rejects(access(refused), {code: 'ENOENT'});
  }
  const repeatedHelpers = Array.from({length: 15}, (_, index) => 'repeat' + index);
  await writeFile(join(invalid, 'wasm.rel'), [
    ...recursive.split('\n').slice(0, 4),
    ...repeatedHelpers.flatMap(name => [
      '("' + name + '", "helper", "demo.' + name + '")',
      '("' + name + '", "result", "Number")',
    ]),
  ].join('\n'));
  await writeFile(join(invalid, 'invalid.encounter'), [
    'process-module "temple/surface-process-module/1"',
    'process demo.entry:', '  call demo.repeat14', '  let result = $result',
    ...repeatedHelpers.flatMap((name, index) => [
      'process demo.' + name + ':',
      ...(index === 0 ? ['  let result = 1'] : [
        '  call demo.' + repeatedHelpers[index - 1],
        '  call demo.' + repeatedHelpers[index - 1],
        '  let result = $result',
      ]),
    ]),
  ].join('\n'));
  const repeated = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
    {encoding: 'utf8', timeout: 10_000});
  assert.ifError(repeated.error);
  assert.notEqual(repeated.status, 0);
  assert.match(repeated.stderr, /browser Wasm expanded helper call budget exceeded/);
  await assert.rejects(access(refused), {code: 'ENOENT'});
  const invalidRecord = [
    '("wasm", "contract", "encounter/browser-wasm/1")',
    '("wasm", "source", "invalid.encounter")',
    '("entry", "entry", "demo.entry")',
    '("entry", "result", "x:Number")',
    '("entry", "result", "y:Boolean")',
  ];
  await writeFile(join(invalid, 'invalid.encounter'), [
    'process-module "temple/surface-process-module/1"',
    'process demo.entry:',
    '  let result = { x = 1; y = 2 }',
  ].join('\n'));
  await writeFile(join(invalid, 'wasm.rel'), invalidRecord.join('\n'));
  const mismatched = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
    {encoding: 'utf8', timeout: 10_000});
  assert.ifError(mismatched.error);
  assert.notEqual(mismatched.status, 0);
  assert.match(mismatched.stderr, /browser Wasm operand type mismatch/);
  await assert.rejects(access(refused), {code: 'ENOENT'});
  const mathDeclaration = [...invalidRecord.slice(0, 3), '("entry", "result", "Number")'];
  await writeFile(join(invalid, 'invalid.encounter'), [
    'process-module "temple/surface-process-module/1"',
    'process demo.entry:',
    '  port number.calculate { operation = "sin"; values = list(0) } → wave',
    '  let result = $wave',
  ].join('\n'));
  for (const [declarations, error] of [
    [mathDeclaration, /unsupported browser Wasm calculation/],
    [[...mathDeclaration, '("wasm", "math", "sqrt")'], /unsupported browser Wasm math import sqrt/],
  ]) {
    await writeFile(join(invalid, 'wasm.rel'), declarations.join('\n'));
    const rejected = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
      {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, error);
    await assert.rejects(access(refused), {code: 'ENOENT'});
  }
  const lookupDeclaration = [
    ...mathDeclaration.slice(0, 3),
    '("entry", "parameter", "index:Number")',
    '("entry", "result", "Number")',
    '("flag", "entry", "demo.flag")',
    '("flag", "parameter", "index:Number")',
    '("flag", "result", "Boolean")',
    '("caption", "entry", "demo.caption")',
    '("caption", "parameter", "index:Number")',
    '("caption", "result", "Text")',
  ].join('\n');
  const lookupSource = [
    'process-module "temple/surface-process-module/1"',
    'process demo.entry:',
    '  let result = at(list(-3, 0, 2.5), $index)',
    'process demo.flag:',
    '  let result = at(list(false, true), $index)',
    'process demo.caption:',
    '  let result = at(list("", "This screen", "東京 🙂"), $index)',
  ].join('\n');
  await writeFile(join(invalid, 'wasm.rel'), lookupDeclaration);
  await writeFile(join(invalid, 'invalid.encounter'), lookupSource);
  const lookup = join(stage, 'literal-lookup');
  run('build', '--browser', invalid, 'wasm.rel', invalid, lookup);
  const lookupModule = new WebAssembly.Module(await readFile(join(lookup, 'browser.wasm')));
  const indexed = new WebAssembly.Instance(lookupModule).exports;
  assert.deepEqual([0, 1, 2].map(index => indexed.entry(index)), [-3, 0, 2.5]);
  assert.deepEqual([0, 1].map(index => indexed.flag(index)), [0, 1]);
  assert.deepEqual([0, 1, 2].map(index => browserWasmTextResult(indexed.memory, indexed.caption(index))), ['', 'This screen', '東京 🙂']);
  for (const index of [-1, 0.5, 3]) {
    assert.throws(() => indexed.entry(index), WebAssembly.RuntimeError);
    assert.throws(() => indexed.caption(index), WebAssembly.RuntimeError);
  }
  for (const [list, message] of [
    ['list()', /expected 1 to 32 literals/],
    ['list(' + Array(33).fill(1).join(', ') + ')', /expected 1 to 32 literals/],
    ['list(-3, true)', /expected homogeneous Number, Boolean, or Text literals/],
    ['list(-3, "label")', /expected homogeneous Number, Boolean, or Text literals/],
    ['list($index, 0)', /expected homogeneous Number, Boolean, or Text literals/],
  ]) {
    await writeFile(join(invalid, 'invalid.encounter'), lookupSource.replace('list(-3, 0, 2.5)', list));
    const rejected = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
      {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, message);
    await assert.rejects(access(refused), {code: 'ENOENT'});
  }
  const entryNames = Array.from({length: 129}, (_, index) => 'entry' + index.toString().padStart(3, '0'));
  await writeFile(join(invalid, 'invalid.encounter'), [
    'process-module "temple/surface-process-module/1"',
    ...entryNames.flatMap((name, index) => ['process demo.' + name + ':', '  let result = ' + index]),
  ].join('\n'));
  const exportDeclaration = names => [
    '("wasm", "contract", "encounter/browser-wasm/1")',
    '("wasm", "source", "invalid.encounter")',
    ...names.flatMap(name => [`("${name}", "entry", "demo.${name}")`, `("${name}", "result", "Number")`]),
  ].join('\n');
  await writeFile(join(invalid, 'wasm.rel'), exportDeclaration(entryNames.slice(0, 128)));
  const manyExports = join(stage, 'many-exports');
  run('build', '--browser', invalid, 'wasm.rel', invalid, manyExports);
  const module = new WebAssembly.Module(await readFile(join(manyExports, 'browser.wasm')));
  const exported = new WebAssembly.Instance(module).exports;
  assert.deepEqual(Object.keys(exported), entryNames.slice(0, 128));
  assert.deepEqual(Object.values(exported).map(entry => entry()), Array.from({length: 128}, (_, index) => index));
  await writeFile(join(invalid, 'wasm.rel'), exportDeclaration(entryNames));
  const tooMany = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
    {encoding: 'utf8', timeout: 10_000});
  assert.ifError(tooMany.error);
  assert.notEqual(tooMany.status, 0);
  assert.match(tooMany.stderr, /expected 1 to 128 browser Wasm exports/);
  await assert.rejects(access(refused), {code: 'ENOENT'});
  const textDeclaration = [
    '("wasm", "contract", "encounter/browser-wasm/1")',
    '("wasm", "source", "invalid.encounter")',
    '("message", "entry", "demo.message")',
    '("message", "parameter", "enabled:Boolean")',
    '("message", "result", "Text")',
    '("echo", "entry", "demo.echo")',
    '("echo", "parameter", "value:Text")',
    '("echo", "result", "Text")',
    '("record", "entry", "demo.record")',
    '("record", "result", "ready:Boolean")',
    '("record", "result", "title:Text")',
  ].join('\n');
  const message = 'Pairing ready · 東京 · 🙂';
  const textSource = [
    'process-module "temple/surface-process-module/1"',
    'process demo.message:',
    '  let result = if($enabled, ' + JSON.stringify(message) + ', "")',
    'process demo.echo:',
    '  let result = $value',
    'process demo.record:',
    '  let result = { title = ' + JSON.stringify(message) + '; ready = true }',
  ].join('\n');
  await writeFile(join(invalid, 'wasm.rel'), textDeclaration);
  await writeFile(join(invalid, 'invalid.encounter'), textSource);
  const textOutput = join(stage, 'text-results');
  run('build', '--browser', invalid, 'wasm.rel', invalid, textOutput);
  const textModule = new WebAssembly.Module(await readFile(join(textOutput, 'browser.wasm')));
  const text = new WebAssembly.Instance(textModule).exports;
  assert.equal(text.memory.buffer.byteLength, 131_072);
  assert.throws(() => text.memory.grow(1), RangeError);
  const initial = text.message(true);
  assert.equal(browserWasmTextResult(text.memory, initial), message);
  assert.equal(browserWasmTextResult(text.memory, text.message(false)), '');
  assert.deepEqual(text.record(), [1, initial]);
  const boundary = '🙂'.repeat(64);
  const [packed] = browserWasmText(text.memory, boundary);
  assert.equal(browserWasmTextResult(text.memory, text.echo(packed)), boundary);
  assert.equal(browserWasmTextResult(text.memory, initial), message);
  const [overlong] = browserWasmText(text.memory, boundary + '!');
  const odd = 1n << 32n;
  const acrossPages = (2n << 32n) | 65_535n;
  const outside = (2n << 32n) | 131_071n;
  for (const malformed of [overlong, odd, acrossPages, outside]) {
    assert.throws(() => text.echo(malformed), WebAssembly.RuntimeError);
    assert.throws(() => browserWasmTextResult(text.memory, malformed), RangeError);
  }
  await writeFile(join(invalid, 'invalid.encounter'),
    textSource.replace(JSON.stringify(message), JSON.stringify(boundary + '!')));
  const longLiteral = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
    {encoding: 'utf8', timeout: 10_000});
  assert.ifError(longLiteral.error);
  assert.notEqual(longLiteral.status, 0);
  assert.match(longLiteral.stderr, /browser Wasm text literal exceeds 128 code units/);
  await assert.rejects(access(refused), {code: 'ENOENT'});
  await writeFile(join(invalid, 'wasm.rel'), [
    '("wasm", "contract", "encounter/browser-wasm/1")',
    '("wasm", "source", "invalid.encounter")',
    '("matches", "entry", "demo.matches")',
    '("matches", "parameter", "value:Text")',
    '("matches", "result", "Boolean")',
  ].join('\n'));
  const patternSource = (pattern, fields = '') => [
    'process-module "temple/surface-process-module/1"',
    'process demo.matches:',
    '  let matched = false',
    '  when true:',
    '    port text.matches { value = $value; pattern = ' + JSON.stringify(pattern) + fields + ' } → matched',
    '  let result = $matched',
  ].join('\n');
  await writeFile(join(invalid, 'invalid.encounter'), patternSource('\\A[!-~·]{0,128}\\z'));
  const patternOutput = join(stage, 'ascii-pattern');
  run('build', '--browser', invalid, 'wasm.rel', invalid, patternOutput);
  const patterns = new WebAssembly.Instance(new WebAssembly.Module(await readFile(join(patternOutput, 'browser.wasm')))).exports;
  for (const [value, expected] of [
    ['', 1], ['!~·', 1], ['z'.repeat(128), 1], ['z'.repeat(129), 0], ['a b', 0], ['aé', 0], ['a🙂', 0],
  ]) {
    assert.equal(patterns.matches(...browserWasmText(patterns.memory, value)), expected);
  }
  assert.equal(patterns.matches(1n << 32n), 0);
  for (const [pattern, fields] of [
    ['\\A[a-z]*\\z', ''], ['\\A[a-z]{0,129}\\z', ''], ['\\A[^a]{1}\\z', ''],
    ['\\A[z-a]{1}\\z', ''], ['\\A[a-z]{+1}\\z', ''], ['\\A[a-z]{1}\\z', '; flags = "i"'],
    ['\\A[🙂]{1}\\z', ''], ['\\A[à-ö]{1}\\z', ''],
  ]) {
    await writeFile(join(invalid, 'invalid.encounter'), patternSource(pattern, fields));
    const rejected = spawnSync(encounter, ['build', '--browser', invalid, 'wasm.rel', invalid, refused],
      {encoding: 'utf8', timeout: 10_000});
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /expected (?:a browser Wasm pattern|browser Wasm text value and pattern literal)/);
    await assert.rejects(access(refused), {code: 'ENOENT'});
  }
  console.log('PASS: browser Wasm returned scalar and record Text with bounded UTF-16 storage');
  console.log('PASS: browser Wasm builds are deterministic and agree with native Encounter');
} finally {
  await rm(stage, {recursive: true, force: true});
}
