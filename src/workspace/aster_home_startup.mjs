import {asterStartupCoordinates, asterStartupPlan} from '/_encounter/browser.mjs?wasm=1';

const [bridge, panel, viewParameter, openKey, openValue, stateAttribute, ready] = asterStartupCoordinates();
const launch = () => import(bridge).catch(error => console.error('Aster startup failed', error));
const connection = document.querySelector(panel);
const view = new URL(location.href).searchParams.get(viewParameter) ?? '';
const idle = typeof requestIdleCallback === 'function';
let restored = false;
try { restored = sessionStorage.getItem(openKey) === openValue; } catch {}

const plan = deadline => asterStartupPlan(Boolean(connection), view, restored,
  connection?.getAttribute(stateAttribute) === ready, deadline, idle);

function apply(action, delay) {
  if (action === 1) void launch();
  if (action === 2) requestIdleCallback(launch, {timeout: delay});
  if (action === 3) setTimeout(launch, delay);
}

const [action, delay] = plan(false);
if (action) {
  apply(action, delay);
} else {
  const observer = new MutationObserver(() => advance(false));
  const timer = setTimeout(() => advance(true), delay);
  observer.observe(connection, {attributes: true, attributeFilter: [stateAttribute]});
  function advance(deadline) {
    const [nextAction, nextDelay] = plan(deadline);
    if (!nextAction) return;
    observer.disconnect();
    clearTimeout(timer);
    apply(nextAction, nextDelay);
  }
}
