// Browser capability bindings for the Encounter guest console policy.
const policy = loadBrowserWasm(encounterGuestConsoleWasm);
if (!policy) {
  document.querySelector('#guest-console-status').textContent = 'The console requires WebAssembly.';
  throw new Error('Encounter guest console policy is unavailable');
}
const readText = handle => browserWasmTextResult(policy.memory, handle);
const [endpoint, selector, prefix, displayMode, serialMode, keyCommand, shift, mouseCommand] =
  policy.protocol().map(readText);
const [resetHandle, pointerInterval, displayBuffer, terminalChunk, terminalBuffer,
  approvalHistory, serialHistory] = policy.options();
const resetCommand = readText(resetHandle);
const form = document.querySelector('#guest-console-form');
const input = document.querySelector('#guest-console-command');
const send = form.querySelector('[type="submit"]');
const reconnect = document.querySelector('#guest-console-reconnect');
const status = document.querySelector('#guest-console-status');
const output = document.querySelector('#guest-console-output');
const modes = document.querySelectorAll('#guest-console-modes button');
const approval = document.querySelector('#guest-terminal-approval');
const approvalCode = document.querySelector('#guest-terminal-code');
const copyCode = document.querySelector('#guest-terminal-copy');
const terminalPane = document.querySelector('#guest-terminal');
// xterm's DOM renderer creates styles for measured cells and terminal colours.
const terminalDocument = terminalPane && new Proxy(document, {
  get(target, key) {
    if (key === 'createElement') return (tag, options) => {
      const element = target.createElement(tag, options);
      if (tag === 'style') element.nonce = terminalPane.nonce;
      return element;
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  },
});
const terminal = terminalPane ? new window.Terminal({documentOverride: terminalDocument,
  screenReaderMode: true, disableStdin: true, fontSize: 14,
  theme: {background: '#151b21', foreground: '#f1f5f9'}}) : null;
const display = document.querySelector('#guest-display');
const frame = document.querySelector('#guest-display-frame');
let frameUrl;
let mode = serialMode;
let connection;
let inputPaused = false;
let capturedPointer = null;
let pendingMove;
let moveTimer;
let parentWindow;
try {
  parentWindow = window.frameElement?.closest('.desktop-app-window');
} catch {
  // The page can also be opened directly.
}

function show(message, connected) {
  status.textContent = message;
  if (input) input.disabled = send.disabled = !connected;
  if (terminal) terminal.options.disableStdin = !connected;
  for (const button of modes) button.disabled = !connected;
}

function setMode(next) {
  if (next === mode) return;
  releasePointer();
  mode = next;
  for (const button of modes) button.setAttribute('aria-pressed', String(button.dataset.mode === mode));
  const displaying = mode === displayMode;
  display.hidden = !displaying;
  form.hidden = output.hidden = displaying;
  if (displaying) frame.focus();
  else input.focus();
}

function clearApproval() {
  if (!approval) return;
  approval.hidden = true;
  approvalCode.value = '';
  copyCode.textContent = 'Copy code';
}

async function copyApprovalCode() {
  const code = approvalCode.value;
  try {
    await navigator.clipboard.writeText(code);
    if (approvalCode.value === code) copyCode.textContent = 'Copied';
  } catch {
    if (approvalCode.value !== code) return;
    approvalCode.focus();
    approvalCode.select();
  }
}

function connect() {
  if (!policy.connect(Boolean(connection), Boolean(parentWindow?.hidden))) return;
  reconnect.hidden = true;
  show('Connecting…', false);
  clearApproval();
  terminal?.reset();
  const address = new URL(endpoint, location.href);
  address.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  address.searchParams.set(selector, form.dataset.guest);
  const socket = new WebSocket(address);
  socket.binaryType = 'arraybuffer';
  const decoder = new TextDecoder();
  let endedWithStatus = false;
  let startDisplay = form.dataset.startDisplay === 'true';
  let signInOutput = '';
  let signingIn = Boolean(terminal);
  connection = socket;
  socket.addEventListener('message', ({ data }) => {
    if (connection !== socket) return;
    if (typeof data === 'string') {
      const state = JSON.parse(data);
      endedWithStatus = !state.connected;
      inputPaused = Boolean(state.inputPaused);
      const [enabled, requestDisplay] = policy.applyStatus(
        Boolean(state.connected), inputPaused, startDisplay, Boolean(state.mode));
      if (inputPaused) releasePointer();
      if (approvalCode?.value && !state.connected) {
        show('Terminal closed during sign-in. Reconnect for a new code.', false);
        clearApproval();
      } else {
        show(state.status, Boolean(enabled));
      }
      if (state.mode) setMode(state.mode);
      if (requestDisplay) {
        startDisplay = false;
        socket.send(prefix + displayMode);
      }
      if (terminal && state.connected) {
        fit.fit();
        sendSize();
        terminal.focus();
      }
      return;
    }
    const bytes = new Uint8Array(data);
    const frameType = policy.frame(bytes[0] ?? -1, Boolean(frame));
    if (frameType === 1) {
      const nextUrl = URL.createObjectURL(new Blob([bytes.subarray(1)], {type: 'image/png'}));
      frame.src = nextUrl;
      if (frameUrl) URL.revokeObjectURL(frameUrl);
      frameUrl = nextUrl;
      return;
    }
    if (frameType !== 0) return;
    if (terminal) {
      terminal.write(bytes.subarray(1));
      if (signingIn) {
        signInOutput = (signInOutput + decoder.decode(bytes.subarray(1), {stream: true})).slice(-approvalHistory);
        if (signInOutput.includes('Signed in as ')) {
          signingIn = false;
          clearApproval();
          show('Connected', true);
        } else {
          const code = signInOutput.match(/Enter this code on the approval page: ([A-Za-z0-9_-]{12})[\r\n]/)?.[1];
          if (code && !approvalCode.value) {
            approvalCode.value = code;
            approval.hidden = false;
            show('Waiting for Temple approval…', true);
          }
        }
      }
      return;
    }
    const text = decoder.decode(bytes.subarray(1), { stream: true }).replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '');
    output.textContent = (output.textContent + text).slice(-serialHistory);
    output.scrollTop = output.scrollHeight;
  });
  socket.addEventListener('close', () => {
    if (connection !== socket) return;
    connection = undefined;
    setMode(serialMode);
    if (!endedWithStatus) {
      show(approvalCode?.value ? 'Terminal closed during sign-in. Reconnect for a new code.' :
        'Console disconnected.', false);
    }
    clearApproval();
    reconnect.hidden = false;
  });
}

function disconnect() {
  const socket = connection;
  connection = undefined;
  socket?.close();
  clearApproval();
  setMode(serialMode);
  if (frameUrl) {
    URL.revokeObjectURL(frameUrl);
    frame.removeAttribute('src');
    frameUrl = undefined;
  }
  show('Console disconnected.', false);
}

const fit = terminal ? new window.FitAddon.FitAddon() : null;
function sendSize() {
  if (connection?.readyState === WebSocket.OPEN) connection.send(terminal.rows + ' ' + terminal.cols);
}
if (terminal) {
  terminal.loadAddon(fit);
  terminal.open(terminalPane);
  copyCode.addEventListener('click', copyApprovalCode);
  terminal.attachCustomKeyEventHandler(event => {
    if (event.type !== 'keydown' || !event.ctrlKey || event.altKey || event.metaKey ||
        event.shiftKey || event.key.toLowerCase() !== 'c') return true;
    if (terminal.hasSelection()) return false;
    if (!approvalCode.value) return true;
    event.preventDefault();
    void copyApprovalCode();
    return false;
  });
  terminal.onResize(sendSize);
  new ResizeObserver(() => fit.fit()).observe(terminalPane);
  terminal.onData(data => {
    if (connection?.readyState !== WebSocket.OPEN || !policy.bufferReady(connection.bufferedAmount, terminalBuffer)) return;
    const bytes = new TextEncoder().encode(data);
    for (let offset = 0; offset < bytes.length && policy.bufferReady(connection.bufferedAmount, terminalBuffer); offset += terminalChunk) {
      connection.send(bytes.subarray(offset, offset + terminalChunk));
    }
  });
}

form.addEventListener('submit', event => {
  event.preventDefault();
  const command = policy.command(input.disabled, connection?.readyState === WebSocket.OPEN,
    Boolean(input.value.trim()), new TextEncoder().encode(input.value).length);
  if (command === 0) return;
  if (command < 0) {
    show('Guest commands are limited to 254 bytes.', true);
    return;
  }
  connection.send(input.value);
  input.value = '';
  input.focus();
});
for (const button of modes) {
  button.addEventListener('click', () => {
    if (connection?.readyState === WebSocket.OPEN) connection.send(prefix + button.dataset.mode);
  });
}
function displayReady() {
  return policy.displayReady(inputPaused, mode === displayMode,
    connection?.readyState === WebSocket.OPEN, frame?.naturalWidth ?? 0, frame?.naturalHeight ?? 0);
}

function guestPoint(event, clamp) {
  const rect = frame.getBoundingClientRect();
  const [accepted, x, y] = policy.pointer(rect.width, rect.height, frame.naturalWidth,
    frame.naturalHeight, event.clientX - rect.left, event.clientY - rect.top, clamp);
  return accepted ? [x, y] : null;
}

function sendPointer(event, point) {
  connection.send(prefix + mouseCommand + point.join(' ') + ' ' + (event.buttons & 7));
}

function clearMove() {
  clearTimeout(moveTimer);
  moveTimer = undefined;
  pendingMove = undefined;
}

function releasePointer() {
  clearMove();
  if (capturedPointer === null) return;
  capturedPointer = null;
  if (connection?.readyState === WebSocket.OPEN && mode === displayMode) connection.send(prefix + resetCommand);
}

frame?.addEventListener('pointerdown', event => {
  if (!policy.pointerPress(event.isPrimary, displayReady(), event.buttons & 7)) return;
  const point = guestPoint(event, false);
  if (!point) return;
  event.preventDefault();
  frame.focus({preventScroll: true});
  frame.setPointerCapture(event.pointerId);
  capturedPointer = event.pointerId;
  clearMove();
  sendPointer(event, point);
});
frame?.addEventListener('pointermove', event => {
  if (!event.isPrimary || !displayReady()) return;
  const point = guestPoint(event, capturedPointer === event.pointerId);
  if (!point) return;
  // Coalesce movement, while sending presses and releases immediately.
  pendingMove = {event, point};
  if (moveTimer !== undefined) return;
  moveTimer = setTimeout(() => {
    const move = pendingMove;
    clearMove();
    if (displayReady() && policy.bufferReady(connection.bufferedAmount, displayBuffer)) sendPointer(move.event, move.point);
  }, pointerInterval);
});
frame?.addEventListener('pointerup', event => {
  if (capturedPointer !== event.pointerId) return;
  capturedPointer = null;
  clearMove();
  if (!displayReady()) return;
  const point = guestPoint(event, true);
  if (point) sendPointer(event, point);
  else connection.send(prefix + resetCommand);
});
frame?.addEventListener('pointercancel', releasePointer);
frame?.addEventListener('lostpointercapture', releasePointer);
frame?.addEventListener('blur', releasePointer);
frame?.addEventListener('dragstart', event => event.preventDefault());
frame?.addEventListener('contextmenu', event => event.preventDefault());
frame?.addEventListener('keydown', event => {
  const [code] = browserWasmText(policy.memory, event.code);
  if (!policy.key(inputPaused, mode === displayMode, connection?.readyState === WebSocket.OPEN,
      event.metaKey || event.ctrlKey || event.altKey, code)) return;
  event.preventDefault();
  if (policy.bufferReady(connection.bufferedAmount, displayBuffer)) {
    connection.send(prefix + keyCommand + (event.shiftKey ? shift : '') + event.code);
  }
});
reconnect.addEventListener('click', connect);
window.addEventListener('pagehide', disconnect);
window.addEventListener('pageshow', connect);
if (parentWindow) {
  new MutationObserver(() => parentWindow.hidden ? disconnect() : connect())
    .observe(parentWindow, { attributes: true, attributeFilter: ['hidden'] });
}
connect();
