const launch = () => import('/_aster/browser.mjs').catch(error => console.error('Aster startup failed', error));
const connection = document.querySelector('[data-home-connection]');
const view = new URL(location.href).searchParams.get('view');
let restore = false;
try { restore = sessionStorage.getItem('sourcery.aster.open') === '1'; } catch {}

if (!connection || view === 'aster' || restore) {
  void launch();
} else {
  let deadline;
  const observer = new MutationObserver(ready);
  function start() {
    observer.disconnect();
    clearTimeout(deadline);
    if ('requestIdleCallback' in window) requestIdleCallback(launch, { timeout: 750 });
    else setTimeout(launch, 0);
  }
  function ready() {
    if (connection.dataset.state === 'ready') start();
  }
  observer.observe(connection, { attributes: true, attributeFilter: ['data-state'] });
  deadline = setTimeout(start, 2500);
  ready();
}
