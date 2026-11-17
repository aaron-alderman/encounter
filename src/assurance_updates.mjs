async function boundedResponse(response) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = '';
  for (;;) {
    const {done, value} = await reader.read();
    if (done) return text + decoder.decode();
    size += value.byteLength;
    if (size > 1_048_576) {
      await reader.cancel();
      throw new Error('Browser response exceeds the observation limit');
    }
    text += decoder.decode(value, {stream: true});
  }
}

let assurancePolicy;

async function refreshAssuranceList(surface, path, isWarnings, lifetime) {
  if (assurancePolicy === undefined) {
    const module = loadBrowserWasm(typeof encounterAssuranceWasm === 'string' ? encounterAssuranceWasm : null);
    assurancePolicy = selectBrowserPolicy(module, 'assurance');
  }
  const policy = assurancePolicy;
  if (!policy) throw new Error('This release requires the browser Wasm Assurance policy');
  const decode = value => policy.memory ? browserWasmTextResult(policy.memory, value) : value;
  const list = surface.querySelector('ol, ul');
  const retained = new Map([...list.children].map(row => [row.dataset.assuranceKey, row]));
  const url = new URL(path, location.origin);
  url.searchParams.set('updates', '1');
  url.searchParams.set('known', [...retained.keys()].join(''));
  if (isWarnings) url.searchParams.set('unread', surface.dataset.unread || '0');
  const clear = dropUnread => {
    list.replaceChildren();
    surface.hidden = true;
    if (dropUnread) delete surface.dataset.unread;
  };
  try {
    const timeout = AbortSignal.timeout(5000);
    const signal = lifetime ? AbortSignal.any([timeout, lifetime]) : timeout;
    const response = await fetch(url, {redirect:'manual', cache:'no-store', signal});
    const [action, dropUnread] = policy.response(response.status, isWarnings);
    if (action === 2) {
      clear(dropUnread);
      return response.status;
    }
    if (action === 1) {
      const {order, rows, unread, openLimit, exchangeLimit} = JSON.parse(await boundedResponse(response));
      const metadata = [unread, openLimit, exchangeLimit].map(value => Number.isSafeInteger(value) ? value : -1);
      const admitted = policy.updateEnvelope(isWarnings, Array.isArray(order) ? order.length : -1,
        Boolean(rows && typeof rows === 'object'), ...metadata);
      if (!admitted) throw new Error('Invalid Assurance update');
      const seen = new Set();
      const actions = order.map(key => {
        const text = typeof key === 'string' ? key : '';
        const input = policy.memory ? browserWasmText(policy.memory, text) : [text];
        const rowAction = policy.rowAction(...input, !seen.has(text), retained.has(text),
          typeof rows[text] === 'string');
        if (!rowAction) throw new Error('Invalid Assurance update');
        seen.add(key);
        return rowAction;
      });
      const next = order.map((key, index) => {
        if (actions[index] === 1) return retained.get(key);
        const row = document.createElement('li');
        row.dataset.assuranceKey = key;
        row.innerHTML = rows[key];
        return row;
      });
      for (const [index, row] of next.entries()) {
        if (list.children[index] !== row) list.insertBefore(row, list.children[index] ?? null);
      }
      while (list.children.length > next.length) list.lastElementChild.remove();
      if (isWarnings) {
        surface.dataset.unread = String(unread);
        const [unreadSuffix, budgetPrefix, budgetDivider, budgetSuffix] = policy.warningHeader(unread).map(decode);
        surface.querySelector('mark').textContent = unread + unreadSuffix;
        surface.querySelector('p').textContent = budgetPrefix + openLimit + budgetDivider + exchangeLimit + budgetSuffix;
      }
    }
    const open = surface.closest('dialog')?.open ?? true;
    const [visible, showEmptyHistory, refreshAges] = policy.presentation(open, isWarnings, list.children.length > 0);
    surface.hidden = !visible;
    if (refreshAges) {
      const now = Date.now();
      for (const time of list.querySelectorAll('.regression-time time')) {
        const timestamp = Date.parse(time.dateTime);
        const [hours, minutes, hourText, minuteText, separator, prefix, ending] = policy.warningAge(now,
          Number.isFinite(timestamp) ? timestamp : now);
        const hourSuffix = decode(hourText);
        const minuteSuffix = decode(minuteText);
        const text = decode(prefix) + (hourSuffix ? hours + hourSuffix : '') + decode(separator) +
          (minuteSuffix ? minutes + minuteSuffix : '') + decode(ending);
        const previous = time.nextSibling;
        if (!previous) time.after(document.createTextNode(text));
        else if (previous.textContent !== text) previous.textContent = text;
      }
    } else {
      surface.querySelector(':scope > p').hidden = !showEmptyHistory;
    }
    return 200;
  } catch {
    const [, dropUnread] = policy.response(503, isWarnings);
    clear(dropUnread);
    return 503;
  }
}

