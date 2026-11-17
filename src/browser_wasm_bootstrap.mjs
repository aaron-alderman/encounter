function loadBrowserWasm(source) {
  if (!source || typeof WebAssembly !== 'object') return null;
  const bytes = Uint8Array.from(atob(source), byte => byte.charCodeAt(0));
  try {
    return new WebAssembly.Instance(new WebAssembly.Module(bytes), {
      'encounter.math': {sin: Math.sin, cos: Math.cos, hypot: Math.hypot, remainder: (value, divisor) => value % divisor},
    }).exports;
  } catch (error) {
    // Releases without Wasm permission still use the existing browser paths.
    if (!(error instanceof WebAssembly.CompileError)) throw error;
    return null;
  }
}

// Pack an offset and byte length for each UTF-16 observation in the module's scratch page.
function browserWasmText(memory, ...values) {
  return packBrowserWasmText(memory, 128, values);
}

function packBrowserWasmText(memory, limit, values) {
  const page = new DataView(memory.buffer, 0, 65_536);
  let offset = 0;
  return values.map(value => {
    // Reserve a length outside the equality bound for overlong observations.
    if (value.length > limit) return BigInt(page.byteLength) << 32n;
    const length = value.length * 2;
    for (let index = 0; index < value.length; index++) {
      page.setUint16(offset + index * 2, value.charCodeAt(index), true);
    }
    const input = (BigInt(length) << 32n) | BigInt(offset);
    offset += length;
    return input;
  });
}

function browserWasmTextResult(memory, handle) {
  const length = Number(handle >> 32n);
  const offset = Number(handle & 0xffff_ffffn);
  const end = offset + length;
  if (length < 0 || length > 256 || length % 2 !== 0 || end > memory.buffer.byteLength ||
      (offset < 65_536 && end > 65_536)) {
    throw new RangeError('Invalid browser Wasm text result');
  }
  const view = new DataView(memory.buffer, offset, length);
  const units = Array.from({length: length / 2}, (_, index) => view.getUint16(index * 2, true));
  return String.fromCharCode(...units);
}

// Transfer as many bounded UTF-16 pairs as the Encounter comparison needs.
function browserWasmTextMatches(memory, compare, current, saved, limit = 128) {
  const savedLength = saved?.length ?? -1;
  const savedText = saved ?? '';
  for (let offset = 0; offset < Math.max(1, current.length); offset += limit) {
    const end = offset + limit;
    const fields = packBrowserWasmText(memory, limit, [current.slice(offset, end), savedText.slice(offset, end)]);
    if (!compare(current.length, savedLength, ...fields)) return false;
  }
  return true;
}

function browserWasmTextChanged(memory, compare, current, saved) {
  return !browserWasmTextMatches(memory, (...fields) => !compare(...fields), current, saved);
}

function browserWasmTextEvery(memory, accept, text, start = 0) {
  for (let offset = start; offset < text.length; offset += 128) {
    if (!accept(...browserWasmText(memory, text.slice(offset, offset + 128)))) return false;
  }
  return true;
}
