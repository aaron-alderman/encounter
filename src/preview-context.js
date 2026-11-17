"use strict";

const previewWasm = loadBrowserWasm(encounterPreviewWasm);
const previewText = (...values) => browserWasmText(previewWasm.memory, ...values);
const previewResultText = value => previewWasm ? browserWasmTextResult(previewWasm.memory, value) : value;
const previewPolicy = selectBrowserPolicy(previewWasm ? {
  returnVisible: previewWasm.returnVisible,
  pickClick: previewWasm.pickClick,
  pickAlias: previewWasm.pickAlias,
  pickerStarts: previewWasm.pickerStarts,
  pickerView: previewWasm.pickerView,
  menuChoice: previewWasm.menuChoice,
  menuTarget: previewWasm.menuTarget,
  commentSummary: previewWasm.commentSummary,
  commentControls: previewWasm.commentControls,
  paneAdmission: previewWasm.paneAdmission,
  commentBadge(context, ...observations) {
    return previewWasm.commentBadge(...previewText(context), ...observations);
  },
  contextLabel(context) {
    return previewWasm.contextLabel(...previewText(context));
  },
  sameContext(current, saved) {
    return browserWasmTextMatches(previewWasm.memory, previewWasm.sameContext, current, saved,
      previewWasm.textEqualityUnits.value);
  },
  panePlan: previewWasm.panePlan,
  leaveCard(status, reduction, proposalFound) {
    return previewWasm.leaveCard(...previewText(status.slice(-128), reduction.slice(0, 128)), proposalFound);
  },
  supportCoordinates: previewWasm.supportCoordinates,
  leaveStep(path) {
    return previewWasm.leaveStep(...previewText(path.slice(-128)));
  },
  targetFamily(route) {
    return previewWasm.targetFamily(...previewText(route));
  },
  selectionFollowup(source) {
    return previewWasm.selectionFollowup(...previewText(source));
  },
  formContext(action, step, hasListItem) {
    return previewWasm.formContext(...previewText(action, step), hasListItem);
  },
  approvedContext(approvedCount, step) {
    return previewWasm.approvedContext(approvedCount, ...previewText(step));
  },
  commonTargets: previewWasm.commonTargets,
  targetAdmission: previewWasm.targetAdmission,
  targetSelectors: previewWasm.targetSelectors,
  reportTarget: previewWasm.reportTarget,
  contextLabelSource: previewWasm.contextLabelSource,
  selectionView(value, ...observations) {
    return previewWasm.selectionView(...previewText(value), ...observations);
  },
  commentVisible(filter, context) {
    return browserWasmTextMatches(previewWasm.memory, previewWasm.commentVisible, filter, context,
      previewWasm.textEqualityUnits.value);
  },
  pickKey(picking, key, hasTarget) {
    return previewWasm.pickKey(picking, ...previewText(key), hasTarget);
  },
  selectValue(value, available) {
    return previewWasm.selectValue(...previewText(value), available);
  },
  optionDisabled(value, available) {
    return previewWasm.optionDisabled(...previewText(value), available);
  },
} : null);
const app = document.querySelector(".pilot-preview-surface");
const appScope = app.querySelector(".pilot-app-scope");
const surface = app.querySelector("main");
const sidebar = document.querySelector(".pilot-preview-comments");
const frame = sidebar.querySelector("iframe");
const support = sidebar.querySelector(".pilot-aster-support");
const supportBase = support?.href;
const picker = document.getElementById("pilot-context-picker");
const status = document.getElementById("pilot-context-status");
if (!previewPolicy) {
  status.textContent = "This release requires WebAssembly to select preview areas.";
  throw new Error(status.textContent);
}
const [taskCoordinate, entryCoordinate, contextCoordinate, supportSource] =
  previewPolicy.supportCoordinates().map(previewResultText);
const [screenTarget, appTarget] = previewPolicy.commonTargets().map(previewResultText);
const requested = new URL(location.href).searchParams.get(contextCoordinate);
let selection = requested;
let select = null;
let boundDocument = null;
let commentFilter = requested;
let commentRows = [];
let commentList = null;
let filterNote = null;
let clearFilter = null;
const badges = [];
const originalTabIndex = new Map();
const pickIds = new Map();
let panePicker = null;
let targets = new Map();
let picking = false;
let jumpOnLoad = requested !== null;
let offerReturn = false;

const [backLabel, clearFilterLabel] = previewPolicy.commentControls().map(previewResultText);
const back = document.createElement("a");
back.className = "pilot-context-back";
back.href = "#preview-comments";
back.textContent = backLabel;
back.hidden = true;
sidebar.after(back);

function previewTargets() {
  const found = new Map();
  const add = (id, element) => {
    if (previewPolicy.targetAdmission(Boolean(id), Boolean(element?.getClientRects().length))) found.set(id, element);
  };
  const family = previewPolicy.targetFamily(location.pathname.split("/").at(-1));
  const [primarySelector, secondarySelector, field, forms, links, report] = previewPolicy.targetSelectors(family);
  const [primary, secondary, coordinate] = [primarySelector, secondarySelector, field].map(previewResultText);
  if (forms) {
    const step = previewResultText(previewPolicy.leaveStep(location.pathname));
    for (const form of surface.querySelectorAll(primary)) {
      const action = form.elements.namedItem(coordinate)?.value ?? "";
      const listItem = form.closest("li");
      const [context, useListItem] = previewPolicy.formContext(action, step, Boolean(listItem));
      const id = previewResultText(context);
      if (id) add(id, useListItem ? listItem : form);
    }
    const approved = [];
    let proposal;
    for (const card of surface.querySelectorAll(secondary)) {
      const [isApproved, proposalContext] = previewPolicy.leaveCard(card.firstElementChild?.textContent ?? "",
        card.children[1]?.textContent ?? "", Boolean(proposal));
      if (isApproved) approved.push(card);
      const id = previewResultText(proposalContext);
      if (id) proposal = [id, card];
    }
    const id = previewResultText(previewPolicy.approvedContext(approved.length, step));
    if (id) add(id, approved[0]);
    if (proposal) add(...proposal);
  }
  if (links) {
    for (const link of surface.querySelectorAll(primary)) {
      add(new URL(link.href).searchParams.get(coordinate), link.closest(secondary));
    }
  }
  if (report) {
    for (let index = 0; ; index++) {
      const [id, selector] = previewPolicy.reportTarget(index).map(previewResultText);
      if (!id) break;
      add(id, surface.querySelector(selector));
    }
  }
  found.set(screenTarget, surface);
  found.set(appTarget, app);
  return found;
}

function setPicking(active) {
  picking = active;
  const [buttonText, notice] = previewPolicy.pickerView(active);
  for (const button of [picker, panePicker]) {
    if (!button) continue;
    button.setAttribute("aria-pressed", String(active));
    button.textContent = previewResultText(buttonText);
  }
  if (active) {
    for (const [id, target] of targets) {
      const [bind, initialise] = previewPolicy.pickAlias(pickIds.has(target), previewPolicy.sameContext(id, selection));
      if (bind) pickIds.set(target, id);
      if (!initialise) continue;
      originalTabIndex.set(target, target.getAttribute("tabindex"));
      target.setAttribute("data-pilot-context-pick", "");
      target.setAttribute("tabindex", "0");
    }
  } else {
    for (const [target, value] of originalTabIndex) {
      target.removeAttribute("data-pilot-context-pick");
      if (value === null) target.removeAttribute("tabindex");
      else target.setAttribute("tabindex", value);
    }
    originalTabIndex.clear();
    pickIds.clear();
  }
  status.textContent = previewResultText(notice);
}

function updateReturn() {
  const bounds = sidebar.getBoundingClientRect();
  const visible = previewPolicy.returnVisible(offerReturn, bounds.top, bounds.bottom, innerHeight);
  back.hidden = !visible;
}

function show(value, { scroll = false, updateUrl = false } = {}) {
  const target = targets.get(value);
  const [urlAction, linkContext, scrollApp, blockHandle, updateStatus, readLabel, message, fallback] =
    previewPolicy.selectionView(value ?? "", Boolean(target), scroll, picking, updateUrl);
  const scrollBlock = previewResultText(blockHandle);
  for (const marked of surface.querySelectorAll("[data-pilot-context-active]")) marked.removeAttribute("data-pilot-context-active");
  surface.removeAttribute("data-pilot-context-active");
  app.removeAttribute("data-pilot-context-active");
  if (target) target.setAttribute("data-pilot-context-active", "");
  offerReturn = Boolean(scrollBlock);
  if (urlAction) {
    const url = new URL(location.href);
    if (urlAction === 2) url.searchParams.set(contextCoordinate, value);
    else url.searchParams.delete(contextCoordinate);
    history.replaceState(null, "", url);
  }
  if (support) {
    const current = new URL(location.href);
    const source = new URL(current.pathname, current.origin);
    for (const key of [taskCoordinate, entryCoordinate]) {
      const coordinate = current.searchParams.get(key);
      if (coordinate) source.searchParams.set(key, coordinate);
    }
    if (linkContext) source.searchParams.set(contextCoordinate, value);
    const url = new URL(supportBase);
    url.searchParams.set(supportSource, source.href);
    support.href = url.href;
  }
  if (scrollBlock) (scrollApp ? appScope : target).scrollIntoView({ block: scrollBlock, inline: "nearest" });
  updateReturn();
  if (updateStatus) {
    let label = "";
    if (readLabel) {
      const option = select?.selectedOptions[0]?.textContent.trim();
      const element = target.getAttribute("aria-label");
      const [source] = previewPolicy.contextLabelSource(Boolean(option), Boolean(element), false);
      label = source ? [option, element][source - 1] : previewResultText(fallback);
    }
    status.textContent = previewResultText(message) + label;
  }
}

function contextLabel(id) {
  const label = previewResultText(previewPolicy.contextLabel(id ?? ""));
  if (label) return label;
  const option = [...(select?.options || [])].find(item => previewPolicy.sameContext(item.value, id));
  const optionLabel = option?.textContent.trim();
  const elementLabel = targets.get(id)?.getAttribute("aria-label");
  const commentLabel = commentRows.find(row => previewPolicy.sameContext(row.dataset.previewCommentContext, id))
    ?.querySelector("small")?.textContent.trim();
  const [source, fallback] = previewPolicy.contextLabelSource(Boolean(optionLabel), Boolean(elementLabel), Boolean(commentLabel));
  return source ? [optionLabel, elementLabel, commentLabel][source - 1] : previewResultText(fallback);
}

function filterComments(id) {
  commentFilter = id;
  const filter = id ?? "";
  let visible = 0;
  for (const row of commentRows) {
    const context = row.dataset.previewCommentContext;
    const matches = previewPolicy.commentVisible(filter, context);
    row.hidden = !matches;
    if (!row.hidden) visible++;
  }
  const [showList, showCaption, separator, suffix] = previewPolicy.commentSummary(Boolean(id), visible);
  if (commentList) commentList.hidden = !showList;
  if (filterNote) filterNote.textContent = showCaption
    ? contextLabel(id) + previewResultText(separator) + visible + previewResultText(suffix)
    : "";
  if (clearFilter) clearFilter.hidden = !showCaption;
}

function addCommentCounts(doc) {
  commentRows = [...doc.querySelectorAll("[data-preview-comment-context]")];
  commentList = doc.querySelector('ol[aria-label="Preview comments"]');
  const controls = doc.createElement("div");
  controls.className = "pilot-comment-filter";
  filterNote = doc.createElement("p");
  filterNote.setAttribute("role", "status");
  filterNote.tabIndex = -1;
  clearFilter = doc.createElement("button");
  clearFilter.type = "button";
  clearFilter.textContent = clearFilterLabel;
  clearFilter.addEventListener("click", () => filterComments(null));
  controls.append(filterNote, clearFilter);
  const panel = doc.querySelector(".nr-preview-comments");
  panel.insertBefore(controls, commentList);
  const counts = new Map();
  for (const row of commentRows) {
    const id = row.dataset.previewCommentContext;
    counts.set(id, (counts.get(id) || 0) + 1);
  }
  for (const [id, count] of counts) {
    const target = targets.get(id);
    const [placement, prefix, suffix, labelSeparator] = previewPolicy.commentBadge(id, count, Boolean(target),
      target === app, target === surface, Boolean(target?.matches("li")));
    if (!placement) continue;
    const badge = document.createElement("button");
    badge.type = "button";
    badge.className = "pilot-comment-count";
    badge.dataset.commentTarget = id;
    const text = count + previewResultText(suffix);
    badge.textContent = previewResultText(prefix) + text;
    badge.setAttribute("aria-label", contextLabel(id) + previewResultText(labelSeparator) + text);
    badge.addEventListener("click", () => choose(id, "badge"));
    if (placement === 1) appScope.append(badge);
    else if (placement === 2) target.prepend(badge);
    else if (placement === 3) target.append(badge);
    else target.before(badge);
    badges.push(badge);
  }
  filterComments(commentFilter);
}

function focusComment([, , sidebarFocus, compose, filter, sidebarBlock, filterBlock]) {
  if (!sidebarFocus) return;
  offerReturn = false;
  updateReturn();
  sidebar.focus({ preventScroll: true });
  sidebar.scrollIntoView({ block: previewResultText(sidebarBlock) });
  if (compose) boundDocument?.querySelector('textarea[name="review-note"]')?.focus({ preventScroll: true });
  if (filter && filterNote) {
    filterNote.focus({ preventScroll: true });
    filterNote.scrollIntoView({ block: previewResultText(filterBlock), inline: "nearest" });
  }
}

function choose(value, source) {
  const followup = previewPolicy.selectionFollowup(source);
  const [scroll, syncSelect] = followup;
  setPicking(false);
  if (syncSelect && select) select.value = selectContextValue(value);
  selection = value;
  show(value, { scroll, updateUrl: true });
  filterComments(value);
  focusComment(followup);
}

function togglePicking() {
  const active = previewPolicy.pickerStarts(picking, targets.size > 0);
  setPicking(Boolean(active));
  if (active) pickIds.keys().next().value.focus();
}
picker.addEventListener("click", togglePicking);
app.addEventListener("click", event => {
  if (!picking) return;
  let element = event.target;
  while (element && !pickIds.has(element)) element = element.parentElement;
  if (!previewPolicy.pickClick(picking, Boolean(element))) return;
  event.preventDefault();
  event.stopImmediatePropagation();
  choose(pickIds.get(element), "picker");
}, true);
function keys(event) {
  if (!picking) return;
  const id = pickIds.get(event.target);
  const action = previewPolicy.pickKey(picking, event.key ?? "", id !== undefined);
  if (action === 1) {
    setPicking(false);
    picker.focus();
  } else if (action === 2) {
    event.preventDefault();
    choose(id, "picker");
  }
}
document.addEventListener("keydown", keys);
window.addEventListener("scroll", updateReturn, { passive: true });
window.addEventListener("resize", updateReturn);
back.addEventListener("click", event => {
  event.preventDefault();
  focusComment(previewPolicy.selectionFollowup("return"));
});

function selectContextValue(value) {
  const available = targets.has(value);
  const selected = previewPolicy.selectValue(value ?? "", available);
  return selected ? value : "";
}

function bindPane() {
  const doc = frame.contentDocument;
  if (!previewPolicy.paneAdmission(Boolean(doc?.querySelector(".nr-preview-comments")), doc === boundDocument)) return;
  boundDocument = doc;
  panePicker = null;
  setPicking(false);
  for (const badge of badges.splice(0)) badge.remove();
  targets = previewTargets();
  select = doc.querySelector('select[aria-label="Context"]');
  if (select) {
    const options = [...select.options];
    const allowed = new Set(options.map(option => previewResultText(previewPolicy.menuTarget(option.value === "")) || option.value));
    targets = new Map([...targets].filter(([id]) => allowed.has(id)));
    for (const option of options) {
      const available = targets.has(option.value);
      const disabled = previewPolicy.optionDisabled(option.value, available);
      option.hidden = option.disabled = Boolean(disabled);
    }
  }
  const [useDefault, showPicker, showPanePicker, scroll] =
    previewPolicy.panePlan(selection !== null, Boolean(select), targets.size > 0, jumpOnLoad);
  if (select) {
    if (useDefault) selection = select.value || "";
    select.value = selectContextValue(selection);
    select.addEventListener("change", () => {
      const value = select.value;
      const action = previewPolicy.menuChoice(value === "", targets.has(screenTarget), targets.has(value));
      if (action === 0) {
        select.value = selectContextValue(selection);
        return;
      }
      choose(action === 1 ? screenTarget : value, "menu");
    });
    doc.addEventListener("keydown", keys);
  }
  if (showPanePicker) {
    panePicker = doc.createElement("button");
    panePicker.type = "button";
    panePicker.textContent = previewResultText(previewPolicy.pickerView(false)[0]);
    panePicker.setAttribute("aria-pressed", "false");
    panePicker.addEventListener("click", togglePicking);
    select.closest("label").after(panePicker);
  }
  picker.hidden = !showPicker;
  addCommentCounts(doc);
  show(selection, { scroll });
  jumpOnLoad = false;
}

frame.addEventListener("load", bindPane);
if (frame.contentDocument?.readyState === "complete") bindPane();
