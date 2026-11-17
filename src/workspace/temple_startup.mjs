const embeddedChromeSheets = new WeakSet();

const storageKey = 'sourcery.os.temples.v1';
const templeWasm = loadBrowserWasm(encounterTempleWasm);
const templeText = (...values) => browserWasmText(templeWasm.memory, ...values);
const templePolicy = selectBrowserPolicy(templeWasm ? {
  selection(selected, available, preferred, preferredAvailable, first) {
    const [selectedText, preferredText, firstText] = templeText(selected, preferred, first);
    return templeWasm.selection(selectedText, available, preferredText, preferredAvailable, firstText);
  },
  workspaceName(workspace) {
    return templeWasm.workspaceName(...templeText(workspace));
  },
  navigationItem(workspace, selected) {
    return templeWasm.navigationItem(...templeText(workspace, selected));
  },
  workspaceNotice(phase) {
    return templeWasm.workspaceNotice(...templeText(phase));
  },
  subscription: templeWasm.subscription,
  timing: templeWasm.timing,
  frameReady: templeWasm.frameReady,
  showFrame: templeWasm.showFrame,
  frameTimedOut: templeWasm.frameTimedOut,
  workspaceDestination: templeWasm.workspaceDestination,
  workspaceOpen: templeWasm.workspaceOpen,
  surfacePlan: templeWasm.surfacePlan,
  preferenceReply: templeWasm.preferenceReply,
  connectionNotice: templeWasm.connectionNotice,
  connectionTimedOut: templeWasm.connectionTimedOut,
  messageBody: templeWasm.messageBody,
  subscriptionRequest: templeWasm.subscriptionRequest,
  subscriptionReply(pendingId, observedId, pendingWorkspace, observedWorkspace) {
    return templeWasm.subscriptionReply(pendingId, observedId, ...templeText(pendingWorkspace, observedWorkspace));
  },
  subscriptionTimedOut(pendingId, observedId, pendingWorkspace, observedWorkspace) {
    return templeWasm.subscriptionTimedOut(pendingId, observedId, ...templeText(pendingWorkspace, observedWorkspace));
  },
  retryConnection: templeWasm.retryConnection,
  catalogueLimit: templeWasm.catalogueLimit,
  savedCatalogue: templeWasm.savedCatalogue,
  savedTempleAdmission: templeWasm.savedTempleAdmission,
  savedOriginMatch(current, saved) {
    return browserWasmTextMatches(templeWasm.memory, templeWasm.savedOriginMatch, current, saved);
  },
  retainSavedTemple: templeWasm.retainSavedTemple,
  greetingWorkspaceCount: templeWasm.greetingWorkspaceCount,
  greetingPlan(subscriptionVersion, reconnecting, selected, path) {
    return templeWasm.greetingPlan(subscriptionVersion, reconnecting, ...templeText(selected, path));
  },
  platformAppCount: templeWasm.platformAppCount,
  platformApp(view, ...fields) {
    return templeWasm.platformApp(...templeText(view), ...fields);
  },
  followWorkspaceLink(hasLink, primary, prevented, modified, target) {
    return templeWasm.followWorkspaceLink(hasLink, primary, prevented, modified, ...templeText(target));
  },
  frameLoadAction(active, targetDocument, local, workspace, connected) {
    return templeWasm.frameLoadAction(active, targetDocument, local, ...templeText(workspace), connected);
  },
  frameMount(workspace, local) {
    return templeWasm.frameMount(...templeText(workspace), local);
  },
  frameObservation: templeWasm.frameObservation,
  frameSignIn: templeWasm.frameSignIn,
  originInput: templeWasm.originInput,
  connectionCoordinates: templeWasm.connectionCoordinates,
  originAllowed(protocol, ...observations) {
    return templeWasm.originAllowed(...templeText(protocol), ...observations);
  },
  workspaceLocation(path, view, uniqueView) {
    return templeWasm.workspaceLocation(...templeText(path, view), uniqueView);
  },
  workspacePath(workspace) {
    return templeWasm.workspacePath(...templeText(workspace));
  },
  historyRestore(path, view, uniqueView) {
    return templeWasm.historyRestore(...templeText(path, view), uniqueView);
  },
  workspaceHistory(mode, samePath, sameQuery) {
    return templeWasm.workspaceHistory(...templeText(mode), samePath, sameQuery);
  },
  launchFields(workspace, local) {
    return templeWasm.launchFields(...templeText(workspace), local);
  },
  launchValueAllowed(workspace, name, value, count, local) {
    return templeWasm.launchValueAllowed(...templeText(workspace, name, value), count, local);
  },
  platformTarget(workspace, view, item) {
    return templeWasm.platformTarget(...templeText(workspace, view, item));
  },
  identityAdmission(id) {
    return templeWasm.identityAdmission(...templeText(id));
  },
  workspaceReply(type, workspace, kind, hasView, validApps, entryMatches) {
    return templeWasm.workspaceReply(...templeText(type, workspace, kind),
      hasView, validApps, entryMatches);
  },
  greetingAccepted(protocol, savedTemple, observedTemple, knownTemple, validTemple, validWorkspaces) {
    return templeWasm.greetingAccepted(...templeText(protocol, savedTemple, observedTemple),
      knownTemple, validTemple, validWorkspaces);
  },
} : null);
if (!templePolicy) {
  const loading = document.getElementById('loading');
  loading.hidden = false;
  loading.textContent = 'This release requires WebAssembly to start Temple.';
  throw new Error(loading.textContent);
}
const templeMessage = message => templeWasm ? browserWasmTextResult(templeWasm.memory, message) : message;
const node = id => document.getElementById(id);
const chooser = node('chooser');
const navigation = node('workspaces');
const loading = node('loading');
const surface = node('surface');
const catalogueLimit = templePolicy.catalogueLimit();
const [initialRetry, connectionDeadline, workspaceDeadline, assurancePoll] = templePolicy.timing();

function readSaved() {
  try {
    const record = JSON.parse(localStorage.getItem(storageKey));
    const version = Number.isFinite(record?.version) ? record.version : 0;
    if (!templePolicy.savedCatalogue(version, Array.isArray(record?.temples))) return { temples: [] };
    const temples = record.temples.slice(0, catalogueLimit).filter(item => {
      const validIdentity = typeof item?.id === 'string' && Boolean(templePolicy.identityAdmission(item.id));
      const canonicalOrigin = validIdentity && parseOrigin(item.origin) === item.origin;
      return templePolicy.savedTempleAdmission(validIdentity, canonicalOrigin);
    });
    const active = typeof record.active === 'string' ? record.active : null;
    return { temples, active: findSavedTemple(temples, active)?.origin ?? null };
  } catch {
    return { temples: [] };
  }
}

function findSavedTemple(temples, origin) {
  return temples.find(item => templePolicy.savedOriginMatch(item.origin, origin));
}

function parseOrigin(input) {
  const text = typeof input === 'string';
  if (!templePolicy.originInput(text, text ? input.length : 0)) return null;
  try {
    const url = new URL(input);
    const allowed = templePolicy.originAllowed(url.protocol, url.hostname === '127.0.0.1', Boolean(url.port),
      url.pathname === '/', Boolean(url.username || url.password), Boolean(url.search || url.hash));
    return allowed ? url.origin : null;
  } catch {
    return null;
  }
}

let saved = readSaved();
let connection;
let target;
let frame;
let ready = false;
let available = [];
let retry;
let timer;
let retryDelay = initialRetry;
let frameTimer;
let embeddedCleanup;
let selection = workspaceLocation(new URL(location.href));
let launch = location.search;
let loadKey;
let frameReady = false;
let subscriptions = false;
let subscriptionId = 0;
let pending;
let subscriptionTimer;

function save() {
  try {
    localStorage.setItem(storageKey, JSON.stringify({ version: 1, ...saved }));
  } catch {
    node('problem').textContent = 'This browser could not save the Temple for next time.';
  }
}

function templateFragment(name) {
  const template = document.createElement('template');
  template.innerHTML = templePresentation[name];
  return template.content;
}

function renderSaved() {
  node('saved').replaceChildren(...saved.temples.map(temple => {
    const button = templateFragment('button').firstElementChild;
    button.textContent = temple.origin === document.body.dataset.demoOrigin ? 'Sourcery Tech demo' : new URL(temple.origin).host;
    button.addEventListener('click', () => connect(temple.origin));
    return button;
  }));
}

function showChooser(message = '') {
  chooser.hidden = false;
  node('problem').textContent = message;
  node('connection').textContent = 'Choose a Temple';
  loading.hidden = true;
  navigation.hidden = true;
  node('disconnect').hidden = true;
  node('choose').hidden = true;
  renderSaved();
}

function removeWorkspaceSurface() {
  clearTimeout(frameTimer);
  embeddedCleanup?.();
  embeddedCleanup = undefined;
  surface.replaceChildren();
  frame = undefined;
  frameReady = false;
  loadKey = undefined;
}

function stop() {
  clearTimeout(retry);
  clearTimeout(timer);
  clearTimeout(subscriptionTimer);
  pending = undefined;
  const previous = connection;
  connection = undefined;
  previous?.close();
  ready = false;
  target = undefined;
  available = [];
  retryDelay = initialRetry;
  removeWorkspaceSurface();
}

function disconnect(clear = false) {
  stop();
  if (clear) {
    saved = { temples: [] };
    try { localStorage.removeItem(storageKey); } catch { /* storage is unavailable */ }
  } else {
    saved.active = null;
    save();
  }
  showChooser();
  node('choose-title').focus();
}

function workspaceName(id) {
  return templeMessage(templePolicy.workspaceName(id));
}

function showWorkspaceNotice(phase, id = '') {
  const [prefix, suffix] = templePolicy.workspaceNotice(phase);
  loading.textContent = templeMessage(prefix) + workspaceName(id) + templeMessage(suffix);
}

function renderNavigation() {
  navigation.replaceChildren(...available.map(id => {
    const [label, current] = templePolicy.navigationItem(id, selection ?? '');
    const button = templateFragment('button').firstElementChild;
    button.textContent = templeMessage(label);
    const ariaCurrent = templeMessage(current);
    if (ariaCurrent) button.setAttribute('aria-current', ariaCurrent);
    button.addEventListener('click', () => openWorkspace(id));
    return button;
  }));
  navigation.hidden = !templePolicy.workspaceOpen(ready, available.length > 0);
}

function workspaceCoordinates(url) {
  const views = url.searchParams.getAll('view');
  return [url.pathname, views[0] ?? '', views.length === 1];
}

function workspaceLocation(url) {
  return templeMessage(templePolicy.workspaceLocation(...workspaceCoordinates(url)));
}

function workspaceUrl(id) {
  const url = new URL(templeMessage(templePolicy.workspacePath(id)), target);
  if (launch) {
    const observed = new URLSearchParams(launch);
    const local = target === location.origin;
    for (const name of templePolicy.launchFields(id, local).map(templeMessage)) {
      if (!name) continue;
      const values = observed.getAll(name);
      if (templePolicy.launchValueAllowed(id, name, values[0] ?? '', values.length, local)) {
        url.searchParams.set(name, values[0]);
      }
    }
  }
  return url;
}

function openWorkspace(id, historyMode = 'push', resubscribe = false) {
  if (!templePolicy.workspaceOpen(ready, available.includes(id))) return;
  selection = id;
  const url = workspaceUrl(id);
  launch = '';
  const item = url.searchParams.get('item');
  const [project, viewText, includeItem] = templePolicy.platformTarget(id, url.searchParams.get('view') ?? '', item ?? '');
  const view = templeMessage(viewText) || undefined;
  if (project) {
    url.search = '';
    if (view) url.searchParams.set('view', view);
    if (includeItem) url.searchParams.set('item', item);
  }
  const historyMethod = templeMessage(templePolicy.workspaceHistory(historyMode,
    location.pathname === url.pathname, location.search === url.search));
  if (historyMethod) {
    history[historyMethod](null, '', url.pathname + url.search);
  }
  renderNavigation();
  const mounted = loadKey === url.href;
  const pendingHere = pending?.url.href === url.href;
  const action = templePolicy.subscription(resubscribe, mounted, pendingHere, subscriptions);
  if (action === 0) return;

  if (loadKey !== url.href) removeWorkspaceSurface();
  clearTimeout(subscriptionTimer);
  pending = undefined;
  surface.hidden = true;
  loading.hidden = false;
  showWorkspaceNotice('opening', id);
  if (action === 1) {
    showWorkspace(id, url, 1);
    return;
  }
  const [messageType, requestId] = templePolicy.subscriptionRequest(subscriptionId);
  subscriptionId = requestId;
  const request = { type: templeMessage(messageType), id: requestId, workspace: id, view };
  pending = { id: request.id, workspace: id, url, view };
  connection.send(JSON.stringify(request));
  subscriptionTimer = setTimeout(() => {
    const [expire, suffix] = templePolicy.subscriptionTimedOut(pending?.id ?? 0, request.id, pending?.workspace ?? '', id);
    if (!expire) return;
    pending = undefined;
    loading.textContent = workspaceName(id) + templeMessage(suffix);
  }, workspaceDeadline);
}

function matchesSubscription(id, workspace) {
  return templePolicy.subscriptionReply(pending?.id ?? 0, Number.isSafeInteger(id) ? id : 0,
    pending?.workspace ?? '', typeof workspace === 'string' ? workspace : '');
}

function workspaceMessage(message) {
  if (!matchesSubscription(message?.id, message?.workspace)) return;
  const { workspace, url, view } = pending;
  pending = undefined;
  clearTimeout(subscriptionTimer);
  const data = message.data;
  const kind = typeof data?.kind === 'string' ? data.kind : '';
  const type = typeof message.type === 'string' ? message.type : '';
  const validApps = validPlatformApps(data);
  const entryMatches = data?.entry === url.pathname;
  const action = templePolicy.workspaceReply(type, workspace, kind, Boolean(view), validApps, entryMatches);
  if (action) {
    showWorkspace(workspace, url, action, data);
  } else {
    removeWorkspaceSurface();
    showWorkspaceNotice('unavailable', workspace);
  }
}

function validPlatformApps(data) {
  const array = Array.isArray(data?.apps);
  const apps = array ? data.apps : [];
  if (!templePolicy.platformAppCount(array, apps.length, new Set(apps.map(app => app?.view)).size)) return false;
  return apps.every(app => {
    const view = typeof app?.view === 'string' ? app.view : '';
    const titleText = typeof app?.title === 'string';
    const detailText = typeof app?.detail === 'string';
    return templePolicy.platformApp(view, titleText, titleText ? app.title.length : 0,
      detailText, detailText ? app.detail.length : 0);
  });
}

function showWorkspace(id, url, action, data) {
  const [plan, loadingHidden, frameHidden] = templePolicy.surfacePlan(loadKey === url.href, Boolean(frame), frameReady, action === 2);
  surface.hidden = false;
  loading.hidden = Boolean(loadingHidden);
  if (plan === 0) {
    if (frame) frame.hidden = Boolean(frameHidden);
    return;
  }
  loadKey = url.href;
  if (plan === 2) {
    renderPlatform(data.apps);
  } else {
    mountFrame(id, url);
  }
}

function renderPlatform(apps) {
  const panel = templateFragment('launcher').firstElementChild;
  const links = panel.querySelector('nav');
  for (const app of apps) {
    const anchor = templateFragment('card').firstElementChild;
    anchor.href = '/workspace/platform?view=' + app.view;
    anchor.querySelector('strong').textContent = app.title;
    anchor.querySelector('small').textContent = app.detail;
    anchor.addEventListener('click', event => {
      const modified = Boolean(event.ctrlKey || event.metaKey || event.shiftKey || event.altKey);
      if (!templePolicy.followWorkspaceLink(true, event.button === 0, event.defaultPrevented, modified, anchor.target)) return;
      event.preventDefault();
      launch = new URL(anchor.href).search;
      openWorkspace('platform');
    });
    links.append(anchor);
  }
  surface.append(panel);
  if (target === location.origin) mountPerformanceWarnings(panel);
}

function mountPerformanceWarnings(panel) {
  const fragment = templateFragment('warnings');
  const badge = fragment.querySelector('section');
  panel.append(fragment);

  const lifetime = new AbortController();
  let refreshTimer;
  async function refresh(refreshAssuranceList) {
    await refreshAssuranceList(badge, '/workspace/platform/performance-badge', true, lifetime.signal);
    if (!lifetime.signal.aborted) refreshTimer = setTimeout(refresh, assurancePoll, refreshAssuranceList);
  }
  embeddedCleanup = () => {
    lifetime.abort();
    clearTimeout(refreshTimer);
  };
  void import('./assurance-updates.mjs').then(({refreshAssuranceList}) => {
    if (!lifetime.signal.aborted) return refresh(refreshAssuranceList);
  }).catch(() => { badge.hidden = true; });
}

function mountFrame(id, url) {
  const current = templateFragment('frame').firstElementChild;
  frame = current;
  current.title = workspaceName(id) + ' workspace';
  const local = target === location.origin;
  const [sandbox, homeSelector, preferenceForm, referrer] = templePolicy.frameMount(id, local).map(templeMessage);
  current.referrerPolicy = referrer;
  if (sandbox) current.setAttribute('sandbox', sandbox);
  function reveal() {
    if (frame !== current) return;
    frameReady = true;
    clearTimeout(frameTimer);
    if (!templePolicy.showFrame(ready, Boolean(pending), frameReady)) return;
    loading.hidden = true;
    current.hidden = false;
  }
  current.addEventListener('load', () => {
    const active = frame === current;
    let document;
    if (active) {
      try { document = current.contentDocument; } catch { /* different origin */ }
    }
    const action = templePolicy.frameLoadAction(active, document?.location?.origin === target, local, id, ready);
    if (action === 0) return;
    if (action === 2) {
      clearTimeout(frameTimer);
      const [path, message, label] = templePolicy.frameSignIn().map(templeMessage);
      const link = templateFragment('signIn').firstElementChild;
      link.href = path;
      link.textContent = label;
      loading.replaceChildren(message, link);
      return;
    }
    if (action === 3) {
      reveal();
      return;
    }
    embeddedCleanup?.();
    const root = document.documentElement;
    if (!root) return;
    root.dataset.templeEmbedded = 'true';
    if (!embeddedChromeSheets.has(document)) {
      const sheet = new document.defaultView.CSSStyleSheet();
      sheet.replaceSync(templePresentation.css);
      document.adoptedStyleSheets.push(sheet);
      embeddedChromeSheets.add(document);
    }
    function switchWorkspace(event) {
      const anchor = event.target.closest?.('a[href]');
      const modified = Boolean(event.ctrlKey || event.metaKey || event.shiftKey || event.altKey);
      if (!templePolicy.followWorkspaceLink(Boolean(anchor), event.button === 0, event.defaultPrevented,
        modified, String(anchor?.target ?? ''))) return;
      const next = new URL(anchor.href);
      const workspace = workspaceLocation(next);
      if (!templePolicy.workspaceDestination(next.origin === target, available.includes(workspace))) return;
      event.preventDefault();
      launch = next.search;
      openWorkspace(workspace);
    }
    async function saveDefaultWorkspace(event) {
      const form = event.target;
      if (!form.matches?.(preferenceForm)) return;
      event.preventDefault();
      const fields = new URLSearchParams(new FormData(form));
      const button = form.querySelector('button[type="submit"]');
      const status = form.querySelector('[role="status"]');
      button.disabled = true;
      status.textContent = 'Saving…';
      try {
        const response = await fetch('/workspace/default', {
          method: 'POST', headers: { Accept: 'application/json' }, body: fields,
        });
        const saved = response.ok ? await response.json() : null;
        const id = response.ok ? workspaceLocation(new URL(saved.environment, location.origin)) : undefined;
        const [action, message] = templePolicy.preferenceReply(response.ok, frame === current, ready, available.includes(id));
        if (action !== 0) status.textContent = templeMessage(message);
        if (action === 1) openWorkspace(id);
      } catch {
        const [, message] = templePolicy.preferenceReply(false, frame === current, ready, false);
        status.textContent = templeMessage(message);
      } finally {
        button.disabled = false;
      }
    }
    document.addEventListener('click', switchWorkspace, true);
    if (preferenceForm) document.addEventListener('submit', saveDefaultWorkspace);
    // Home and Aster have separate bridges. Only Home can signal that its apps are bound.
    const homeConnection = homeSelector ? document.querySelector(homeSelector) : null;
    const [attribute, bridge] = templePolicy.frameObservation(Boolean(homeConnection)).map(templeMessage);
    const isReady = waitForBridge => templePolicy.frameReady(Boolean(homeConnection),
      homeConnection?.dataset.state === 'ready', root.dataset.encounter === 'ready', waitForBridge);
    const observer = new MutationObserver(() => {
      if (isReady(true)) reveal();
    });
    observer.observe(homeConnection || root, {
      attributes: true, attributeFilter: [attribute],
    });
    embeddedCleanup = () => {
      observer.disconnect();
      document.removeEventListener('click', switchWorkspace, true);
      document.removeEventListener('submit', saveDefaultWorkspace);
    };
    if (isReady(Boolean(document.querySelector(bridge)))) reveal();
  });
  frameTimer = setTimeout(() => {
    if (!templePolicy.frameTimedOut(frame === current, ready)) return;
    showWorkspaceNotice('slow', id);
  }, workspaceDeadline);
  current.src = url.href;
  surface.append(current);
}

function connect(origin, reconnecting = false) {
  if (!origin) {
    showChooser('Enter an HTTPS Temple origin or an HTTP address on 127.0.0.1 with its port.');
    return;
  }
  if (!reconnecting) {
    stop();
    saved.active = null;
    save();
  }
  target = origin;
  const address = new URL(origin);
  const [path, protocol] = templePolicy.connectionCoordinates(address.protocol === 'https:').map(templeMessage);
  const url = new URL(path, address);
  url.protocol = protocol;
  const previousIdentity = findSavedTemple(saved.temples, origin);
  let greeted = false;
  chooser.hidden = true;
  loading.hidden = false;
  loading.textContent = templeMessage(templePolicy.connectionNotice(reconnecting));
  node('connection').textContent = loading.textContent;
  node('disconnect').hidden = false;
  node('choose').hidden = false;
  let socket;
  try { socket = new WebSocket(url); } catch {
    stop();
    showChooser('This browser could not start the Temple connection.');
    return;
  }
  connection = socket;
  timer = setTimeout(() => {
    if (templePolicy.connectionTimedOut(connection === socket, greeted)) socket.close();
  }, connectionDeadline);
  socket.addEventListener('message', event => {
    if (connection !== socket) return;
    let message;
    try {
      const text = typeof event.data === 'string';
      if (templePolicy.messageBody(text, text ? event.data.length : 0)) message = JSON.parse(event.data);
    } catch { message = null; }
    if (greeted) {
      workspaceMessage(message);
      return;
    }
    const protocol = typeof message?.protocol === 'string' ? message.protocol : '';
    const observedTemple = typeof message?.temple === 'string' ? message.temple : '';
    const savedTemple = previousIdentity?.id ?? '';
    const validTemple = templePolicy.identityAdmission(observedTemple);
    const workspaces = message?.workspaces;
    const hasWorkspaceList = Array.isArray(workspaces);
    const validWorkspaces = templePolicy.greetingWorkspaceCount(hasWorkspaceList, hasWorkspaceList ? workspaces.length : 0) &&
      workspaces.every(id => typeof id === 'string' && workspaceName(id));
    const accepted = templePolicy.greetingAccepted(protocol, savedTemple, observedTemple,
      Boolean(previousIdentity), validTemple, validWorkspaces);
    if (!accepted) {
      stop();
      showChooser('Temple identity or protocol did not match. Clear stored Temples before pairing a replacement.');
      return;
    }
    greeted = ready = true;
    const subscriptionVersion = Number.isFinite(message.workspaceSubscriptions) ? message.workspaceSubscriptions : 0;
    const [subscribe, refreshLaunch] = templePolicy.greetingPlan(subscriptionVersion, reconnecting, selection, location.pathname);
    subscriptions = Boolean(subscribe);
    clearTimeout(timer);
    retryDelay = initialRetry;
    const temples = [{origin, id: observedTemple}];
    for (const item of saved.temples) {
      if (templePolicy.retainSavedTemple(temples.length, templePolicy.savedOriginMatch(item.origin, origin))) temples.push(item);
    }
    saved.temples = temples;
    saved.active = origin;
    save();
    available = [...new Set(message.workspaces)];
    node('connection').textContent = 'Connected · ' + new URL(origin).host;
    const preferred = typeof message.defaultWorkspace === 'string' ? message.defaultWorkspace : '';
    const [action, workspace] = templePolicy.selection(selection, available.includes(selection),
      preferred, available.includes(preferred), available[0] ?? '');
    const destination = templeMessage(workspace);
    if (action === 1) {
      launch = '';
      removeWorkspaceSurface();
      renderNavigation();
      loading.hidden = false;
      showWorkspaceNotice('unavailable', destination);
    } else if (action === 2) {
      if (refreshLaunch) launch = location.search;
      openWorkspace(destination, 'replace', reconnecting);
    } else {
      removeWorkspaceSurface();
      renderNavigation();
      showWorkspaceNotice('empty');
    }
  });
  socket.addEventListener('close', () => {
    if (connection !== socket) return;
    clearTimeout(timer);
    connection = undefined;
    ready = false;
    clearTimeout(subscriptionTimer);
    pending = undefined;
    surface.hidden = true;
    renderNavigation();
    const [willRetry, wait, nextDelay, notice] = templePolicy.retryConnection(greeted, reconnecting, retryDelay);
    const message = templeMessage(notice);
    if (willRetry) {
      loading.hidden = false;
      loading.textContent = message;
      node('connection').textContent = loading.textContent;
      retry = setTimeout(() => connect(origin, true), wait);
      retryDelay = nextDelay;
    } else {
      stop();
      showChooser(message);
    }
  });
}

node('existing').addEventListener('submit', event => {
  event.preventDefault();
  connect(parseOrigin(node('temple-address').value.trim()));
});
node('demo').addEventListener('click', () => connect(parseOrigin(document.body.dataset.demoOrigin)));
node('choose').addEventListener('click', () => disconnect());
node('disconnect').addEventListener('click', () => disconnect());
node('clear').addEventListener('click', () => disconnect(true));
window.addEventListener('popstate', () => {
  const url = new URL(location.href);
  const [workspace, mode] = templePolicy.historyRestore(...workspaceCoordinates(url)).map(templeMessage);
  if (mode) {
    selection = workspace;
    launch = url.search;
    openWorkspace(workspace, mode);
  }
});
window.addEventListener('storage', event => {
  if (event.key === storageKey && event.newValue === null) {
    stop();
    saved = { temples: [] };
    showChooser();
  }
});
if (saved.active) connect(saved.active, true);
else showChooser();
