// Compatibility for browser releases without a Wasm catalog.
const encounterLegacyCountdown = {
  caption(interval, remaining, refreshing) {
    return !interval ? 0 : refreshing || remaining <= 0 ? -1 : Math.ceil(remaining / 1000);
  },
  dispatch(interval, remaining, refreshing, idle) {
    return Boolean(interval && !refreshing && remaining <= 0 && idle);
  },
  deadline(hasAnchor, anchor, interval, now) {
    return hasAnchor ? anchor + interval : now;
  },
  anchor(now, due) {
    return now - due < 1000 ? due : now;
  },
  delay(remaining, refreshing) {
    return refreshing || remaining <= 0 ? 250 : remaining % 1000 || 1000;
  },
  bindingAllowed(ref, duplicate, used, storage, array, count) {
    return /^#[a-z0-9-]{1,80}$/.test(ref) && !duplicate && used < 16 &&
      /^[a-z0-9.-]{1,120}$/.test(storage) && array && count >= 1 && count <= 12;
  },
  choiceAllowed(name, duplicate, whole, milliseconds, defaultConflict) {
    return /^[a-z0-9-]{1,32}$/.test(name) && !duplicate && whole &&
      (milliseconds === 0 || milliseconds >= 1000 && milliseconds <= 3_600_000) && !defaultConflict;
  },
  optionsReady(hasDefault, optionsPresent) {
    return hasDefault && optionsPresent;
  },
  controlsAllowed(captionInPanel, preferenceInPanel, panelInDesktop, correctTypes) {
    return captionInPanel && preferenceInPanel && panelInDesktop && correctTypes;
  },
  tickVisible(bound, panelHidden, desktopHidden) {
    return bound && !panelHidden && !desktopHidden;
  },
  refreshAnchor(bound, scheduled) {
    return bound && !scheduled;
  },
  tick(hasAnchor, anchor, interval, now, requests, scheduled, idle) {
    const refreshing = scheduled || requests > 0;
    const due = this.deadline(hasAnchor, anchor, interval, now);
    const remaining = due - now;
    const caption = this.caption(interval, remaining, refreshing);
    const showSeconds = caption > 0;
    const label = caption === 0 ? 'Paused' : caption === -1 ? 'Refreshing…' : 'Next refresh in ';
    return [caption, this.dispatch(interval, remaining, refreshing, idle),
      this.anchor(now, due), interval ? this.delay(remaining, refreshing) : 0, label, showSeconds ? 's' : '', showSeconds];
  },
  selectedInterval(known, selected, defaultInterval) {
    return known ? selected : defaultInterval;
  },
  preferenceChoice(known, candidateSelected, defaultSelected) {
    return [known, !(known ? candidateSelected : defaultSelected)];
  },
};
