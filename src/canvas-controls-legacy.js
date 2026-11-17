const encounterLegacyCanvasDrawings = new Map([
  ['launch', [[230,537],[420,462],[612,425],[825,432]]],
  ['arrival', [[101,598],[320,510],[490,530],[693,453],[904,427]]],
  ['collision-west', [[367,328],[473,419],[626,443]]],
  ['collision-east', [[922,324],[801,417],[626,443]]],
  ['branch-first', [[187,512],[463,476],[632,256],[982,239]]],
  ['branch-second', [[187,512],[463,476],[694,526],[1067,449]]],
  ['gate', [[83,562],[320,474],[624,410],[978,302],[1190,226]]],
  ['rebuild', [[185,496],[398,413],[638,426],[847,413],[1100,496]]],
  ['network', [[144,437],[384,286],[625,410],[841,248],[1104,354]]],
  ['signal-west', [[202,305],[416,305],[640,455]]],
  ['signal-east', [[1080,307],[859,308],[640,455]]],
  ['signal-south', [[640,455],[640,566]]],
  ['home', [[52,595],[246,525],[494,546],[714,455],[930,422]]],
  ['beacon-tower', [[-23,64],[-13,-47],[13,-47],[23,64]]],
  ['beacon-shadow', [[0,-47],[13,-47],[23,64],[0,64]]],
  ['beacon-window', [[-21,-43],[21,-43],[17,-71],[-17,-71]]],
  ['beacon-roof', [[-27,-70],[0,-99],[27,-70]]],
  ['slip-paper', [[-57,-34],[41,-34],[55,-19],[55,34],[-57,34]]],
  ['slip-fold', [[41,-34],[55,-19],[41,-19]]],
  ['slip-line-top', [[-38,-13],[35,-13]]],
  ['slip-line-middle', [[-38,-1],[23,-1]]],
  ['slip-line-bottom', [[-38,11],[11,11]]],
  ['boat-hull', [[-43,7],[47,7],[24,25],[-27,25]]],
  ['boat-mast', [[0,7],[0,-49]]],
  ['boat-main-sail', [[3,-48],[32,2],[3,2]]],
  ['boat-small-sail', [[-4,-30],[-24,2],[-4,2]]],
  ['flight-craft', [[-19,-18],[38,0],[-19,18],[-8,0]]],
]);

const encounterLegacyCanvasControls = {
  surfaceProfile() {
    return [1280, 720, false];
  },
  seaLayout() {
    return [36, 6, 0.63, 845, 300, 470, 0.21];
  },
  settingsAction(event, matched) {
    const reset = matched && event === 'click';
    const changed = reset || (matched && event === 'input');
    return [changed || event === 'encounter:live-refresh', reset, matched && event === 'submit', changed, reset];
  },
  settingsText() {
    return [' = ', '\n'];
  },
  settingsSurface() {
    return ['canvas-settings', '[data-canvas-setting]', '[data-canvas-reset]', '[data-encounter-draft]', 'data-canvas-value'];
  },
  drawingVertex(name, index) {
    const point = encounterLegacyCanvasDrawings.get(name)?.[index];
    return point ? [true, ...point] : [false, 0, 0];
  },
  playback(useAudio, audioTime, start, now, anchor, duration) {
    const position = Math.max(0, Math.min(duration, useAudio ? audioTime - start : (now - anchor) / 1000));
    return [position, position >= duration, 'Replay shot'];
  },
  frameTime(start, position, duration) {
    return start + Math.min(position, duration - 0.001);
  },
  timelineAdmission(validNumbers) {
    return [validNumbers, validNumbers ? '' : 'The canvas timeline is unavailable.'];
  },
  cueSelection(absolute, validBounds, from, to) {
    const selected = validBounds && absolute >= from && absolute < to;
    return [selected, selected ? absolute - from : 0];
  },
  confirmLeave(sameForm, prevented, dirty) {
    return (!sameForm || prevented) && dirty;
  },
  scrub(requested, duration, audioPlaying) {
    return [Math.max(0, Math.min(duration, requested)), audioPlaying];
  },
  playToggle(playing, position, duration, enabled) {
    const ended = position >= duration;
    return playing ? [true, position, false, ended ? 'Replay shot' : 'Play shot']
      : [false, ended ? 0 : position, enabled, 'Pause shot'];
  },
  soundChange(playing, enabled) {
    return [playing && enabled, playing && !enabled];
  },
  narrationResult(token, activeToken, playing, enabled, failed, usingAudio) {
    const current = token === activeToken;
    const resetClock = failed && current && playing;
    return [(!failed && current) || usingAudio, !failed && !current && (!playing || !enabled), resetClock,
      resetClock ? 'Narration could not start. The animation is playing silently.' : ''];
  },
  narrationFault(playing, usingAudio) {
    return [!playing && usingAudio, playing, playing ? 'Narration is unavailable. The animation is playing silently.' : ''];
  },
  settingChanged(_currentLength, _savedLength, current, saved) {
    return current !== saved;
  },
  clockAnchor(now, position) {
    return now - position * 1000;
  },
  audioPosition(start, position) {
    return start + position;
  },
  ease(position) {
    const bounded = Math.max(0, Math.min(1, position));
    return bounded * bounded * (3 - 2 * bounded);
  },
  camera(width, height, dx, dy, zoom, zoomPercent, pan) {
    return [width / 2 + dx + pan * width / 100, height / 2 + dy, zoom * zoomPercent / 100,
      0 - width / 2, 0 - height / 2];
  },
  routePoint(fromX, fromY, toX, toY, remaining, length) {
    if (!(remaining > 0)) return [false, fromX, fromY, remaining];
    const fraction = Math.min(1, remaining / length);
    return [true, fromX + (toX - fromX) * fraction, fromY + (toY - fromY) * fraction, remaining - length];
  },
  sceneFrame(scene, time) {
    switch (scene) {
      case 'still': return [3, 5.4 + time * 0.12, 0, true];
      case 'intent-shift': return [5, time + 2, 1.3, false];
      case 'intent-close': return [5, time + 2.1, 0.9, false];
      case 'strata-close': return [6, time + 5, 0, false];
      case 'refactor': return [9, time, 0, true];
      case 'closing': return [13, time, 0, true];
    }
    const scenes = ['flight', 'launch', 'arrival', 'collision', 'intent', 'strata', 'branches', 'gate',
      'rebuild', 'network', 'signals', 'harbours', 'home'];
    return [scenes.indexOf(scene) + 1, time, 0, false];
  },
  sceneCamera(code, time, offset, alternate) {
    const cameras = [
      null,
      [1, 0, 1, 0, 0, 0, false],
      [1.15, 0.09, 6, -26, -7, 0, true],
      [1.05, 0.1, 7, -12, -2, 0, false],
      [1.02, 0.21, 11, -18, -2, 0.37, true],
      [1.06, 0.09, 6, 23, -5, 0.28, false],
      [1.1, 0.1, 6, -8, 1, 0, false],
      [1.04, 0.09, 9, -21, -3, 0, false],
      [1.05, 0.13, 6, -17, 4, 0, false],
      [1.07, 0.15, 8, 16, -7, 0.26, true],
      [1.02, 0.13, 14, -9, -2, 0, false],
      [1.11, 0.09, 8, -5, -8, 0, true],
      [1.08, 0.12, 12, 18, -9, 0.21, false],
      [1.07, 0.14, 12, -11, -5, 0, false],
    ];
    const [base, change, duration, x, y, frequency, warm] = cameras[code] ?? cameras[1];
    const advance = base + change * this.ease(time / duration);
    const zoom = code === 8 ? advance - 0.07 * this.ease((time - 9) / 5) : advance;
    return [warm || code === 13 && alternate, zoom, frequency ? x * Math.sin(time * frequency + offset) : x, y];
  },
  palette() {
    return ['#65c1b0', '#bef7dc', '#f5e1b4', '#ef8269', '#ffc779', '#507e83'];
  },
  waterStyle(warm) {
    return warm ? ['#152735', '#244b4b', '#081c28', '#bb8754'] : ['#071a26', '#113d48', '#081c28', '#4badac'];
  },
  seaWave(time, row, column) {
    const x = (column * 237 + row * 83 + time * (18 + row * 0.7)) % 1536 - 125;
    const y = 245 + row * 13;
    const length = 13 + (row * 17 + column * 43) % 95;
    return [x, y, x + length * 0.46, y - 2, x + length, (row + column) % 7 === 0 ? '#77c5b536' : '#5ba6a12a', row > 22 ? 2 : 1];
  },
  beaconLayout(y, scale) {
    return [y + 66 * scale, 97 * scale, 34 * scale, 23 * scale];
  },
  placeVertex(x, y, scale, dx, dy) {
    return [x + dx * scale, y + dy * scale];
  },
  beaconStripes(x, y, scale) {
    return [x - 15 * scale, x + 15 * scale, y - 16 * scale, y + 16 * scale, 7 * scale];
  },
  beaconGlow(time, y, scale) {
    return [y - 54 * scale, 63 * scale, 0.42 + 0.07 * Math.sin(time * 2), y - 55 * scale, 5 * scale];
  },
  beaconReflection(time, row, scale, baseY, baseX) {
    const radius = (9 + 26 * Math.abs(Math.sin(time * 1.3 + row * 2))) * scale;
    return [baseY + (88 + row * 7) * scale, baseX - radius, baseX + radius, 2 * scale,
      row % 2 === 0 ? '#ffc77925' : '#ffc7793a'];
  },
  boatBob(time, y) {
    return y + Math.sin(time * 2.3) * 3;
  },
  boatWake(time, ring) {
    const phase = (time * 0.8 + ring * 0.32) % 1;
    return [0.29 * (1 - phase), 11 + phase * 67, 3 + phase * 16];
  },
  pulseRing(time, ring) {
    const phase = (time * 0.45 + ring / 3) % 1;
    return [(1 - phase) * 0.42, 8 + phase * 63, 4 + phase * 24];
  },
  routeDistance(length, progress) {
    return length * Math.max(0, Math.min(1, progress));
  },
  routeSegment(fromX, fromY, toX, toY, total) {
    const length = Math.hypot(toX - fromX, toY - fromY);
    return [length, total + length];
  },
  plateGeometry(x, y, rx, ry, depth) {
    return [x - rx, x + rx, y - ry, y + ry, y + depth, y + ry + depth];
  },
  flightStar(time, index) {
    return [(index * 223 - time * (44 + index % 4 * 30) + 2500) % 1280,
      (index * 131) % 644, 1 + index % 3 * 0.5];
  },
  flightPosition(time) {
    return [320 + time * 70, 324 + 92 * Math.sin(time * 1.65)];
  },
  flightTrail(time, index, x, y) {
    return [x - index * 16, y + Math.sin(time * 12 + index) * 8, 7 - index];
  },
  flightPlate(time, index) {
    return [(1000 + index * 247 - time * 215 + 2560) % 1450 - 90, 163 + index * 76, index % 2 !== 0, 33, 19, 13];
  },
  flightBeacon(time) {
    return [time > 3.8, this.ease(time - 3.8) * 0.54, 1026, 149, 100, 11];
  },
  collisionSlip(time, index) {
    const q = this.ease((time - index * 0.22) / 2);
    const angle = index * 2.399 + time * 0.05;
    const radius = 352 - 102 * q;
    return [q > 0, 640 + radius * Math.cos(angle), 367 + radius * 0.64 * Math.sin(angle),
      0.35 + q * 0.29, 0.2 * Math.sin(time + index), index % 3 !== 0];
  },
  collisionRoute(time) {
    return [time > 5, this.ease((time - 5) / 2)];
  },
  intentSlip(time, index) {
    const target = [[278, 300], [990, 288], [309, 528], [971, 510]][index];
    const [targetX, targetY] = target ?? [640, 376];
    const q = this.ease((time - 1 - index * 0.57) / 2);
    const x = 640 + (targetX - 640) * q;
    const y = 376 + (targetY - 376) * q;
    return [Boolean(target) && q > 0, x, y, 640 + (x - 640) * 0.56, q, 0.68 * q, 0.12 * Math.sin(time + index)];
  },
  strataPlate(time, index) {
    const q = this.ease(time / 3.5);
    const x = 640 + Math.sin(time * 0.7 + index * 0.5) * 9;
    const y = 510 - index * 46 - q * index * 37;
    return [x, y, 260 - index * 19, 88 - index * 6, 25, ['#507e83', '#65c1b0', '#f5e1b4'][index] ?? '#bef7dc'];
  },
  strataRoute(time, index, x, y) {
    return [x + 260 - index * 19, 965 - index * 7, y - 58, time > 3,
      this.ease((time - 3 - index * 0.46) / 1.8), 2.3];
  },
  strataStar(time, index) {
    const angle = index * 2.399 + time * 0.13;
    return [640 + 446 * Math.cos(angle), 408 + 192 * Math.sin(angle)];
  },
  networkNode(index) {
    const angle = index * 2.399;
    return [640 + 457 * Math.cos(angle) * (0.32 + index % 5 / 7),
      345 + 229 * Math.sin(angle) * (0.34 + index % 7 / 10), (index * 7 + 11) % 49];
  },
  networkMark(time, progress, index) {
    return [progress >= index * 0.22, time + index, index % 2 !== 0 || index === 4, -0.18 + 0.06 * index];
  },
  launchPhase(time) {
    return [0.12 + 0.88 * this.ease(time / 2.8), this.ease((time - 0.4) / 2.7)];
  },
  launchSlip(time, index) {
    const progress = this.ease((time - 0.5 - index * 0.38) / 1.6);
    return [250 + progress * 110 + index * 55, 523 - progress * (70 + index * 33),
      -0.2 + 0.09 * index, index === 3];
  },
  arrivalPhase(time, still) {
    return [this.ease(time / 5.5), still ? time * 0.15 : time];
  },
  intentBook(time) {
    return this.ease(time / 2.2 + 0.12);
  },
  gateArms(open) {
    return [631 - 30 * open, 642 + 30 * open, 399 - 136 * open, 452, 834, 399, 7];
  },
  rebuildPhase(time, refactor) {
    const progress = refactor ? this.ease((time - 0.5) / 8) : this.ease(time / 6);
    return [progress, refactor ? 1 : progress];
  },
  rebuildPlate(time, progress, index, baseX, baseY, refactor) {
    const offset = (index - 1) * (129 + 112 * Math.sin(Math.PI * progress));
    return [refactor ? 640 + offset : baseX,
      refactor ? 448 + (index % 2) * 34 : baseY - 55 * (1 - this.ease((time - index) / 2))];
  },
  networkProgress(time) {
    return this.ease((time - 0.6) / 11.2);
  },
  signalPhase(time, index) {
    const [x, y] = [[202, 305], [1080, 307], [640, 561]][index] ?? [0, 0];
    return [this.ease((time - index * 0.8) / 2.5), time + index, index === 1, x, y];
  },
  signalsBook(time) {
    return this.ease((time - 0.9) / 2.9);
  },
  harboursProgress(time) {
    return this.ease((time - 1.4) / 4);
  },
  harbourLayout(index) {
    const [x, scale] = [[317, 1.05], [963, 1.15]][index] ?? [0, 0];
    return [x, scale, 484, 400, 640, 333, 383, 448];
  },
  homePhase(time) {
    return [44 * Math.sin(time * 0.34), this.ease(time / 10.5)];
  },
  lightAlpha(alpha, light) {
    return Math.max(0, Math.min(1, alpha * light / 100));
  },
  clockDisplay(position) {
    const seconds = Math.floor(position);
    const remainder = seconds % 60;
    return [Math.floor(seconds / 60), remainder, ':', remainder >= 0 && remainder < 10 ? '0' : ''];
  },
  bookGeometry(x, y, scale, opening) {
    const width = 190 * scale * opening;
    return [x - width, x + width, y + 60 * scale, y + 20 * scale, y - 89 * scale, y - 42 * scale,
      y - 41 * scale, y + 59 * scale];
  },
  bookDetails(x, scale, opening) {
    return [opening > 0.22, x - 190 * scale * opening * 0.82, 1.6 * scale, 2.6 * scale, 3.5 * scale];
  },
  bookDetailGeometry(x, y, scale, opening, index) {
    const [dx, dy] = [[41,-18], [76,4], [118,-27], [155,-13]][index] ?? [155,-13];
    const advance = index * 15 * scale;
    return [x - 25 * scale, y - 20 * scale + advance, y - 52 * scale + advance,
      x + dx * scale * opening, y + dy * scale, index === 3];
  },
  cueTime(offset, motion) {
    return offset * motion / 100;
  },
  branchPhase(time) {
    const firstBranch = time < 3.8;
    return [this.ease(time / 3.1), this.ease((time - 2.7) / 4.8), firstBranch,
      this.ease(firstBranch ? time / 3.2 : (time - 3.8) / 4.7)];
  },
  gatePhase(time) {
    const open = this.ease((time - 8.2) / 1.9);
    return [open, open > 0.64, open > 0.5, 0.49 * this.ease(time / 4.2) + 0.51 * this.ease((time - 8.7) / 5.1)];
  },
  closingFade(time) {
    const title = this.ease((time - 6.8) / 2.2);
    return [title, 0.68 * title, 'Sourcery + Temple', '#fff0cf', 'bold 75px Georgia,serif'];
  },
  warmth(setting) {
    return [Math.abs(setting) / 100 * 0.36, setting === 0 ? '' : setting > 0 ? '#ff983d' : '#3973ff'];
  },
};
