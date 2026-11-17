const encounterLegacyPreview = {
  sameContext(current, saved) {
    return current === saved;
  },
  panePlan(hasSelection, hasMenu, hasTargets, jumpOnLoad) {
    return [hasMenu && !hasSelection, hasMenu, hasMenu && hasTargets, jumpOnLoad];
  },
  leaveCard(status, reduction, proposalFound) {
    const proposalContext = !proposalFound && reduction.startsWith("Reduction to ") ? "propose" : "";
    return [status.endsWith(" approved minutes"), proposalContext];
  },
  supportCoordinates() {
    return ["review-task", "entry", "context", "source"];
  },
  leaveStep(path) {
    return /-([367])\/sick-leave$/.exec(path)?.[1] ?? "";
  },
  formContext(action, step, hasListItem) {
    const context = action === 'notify-sick' ? 'notify' : action === 'approve-sick' ? 'approve'
      : action === 'adjust-sick' && step === '7' ? 'increase' : action === 'approve-reduction' ? 'confirm' : '';
    return [context, hasListItem && context !== '' && context !== 'notify'];
  },
  approvedContext(approvedCount, step) {
    return approvedCount === 1 && step === '3' ? 'approve' : approvedCount === 1 && step === '6' ? 'confirm' : '';
  },
  commonTargets() {
    return ['screen', 'app'];
  },
  menuTarget(emptyValue) {
    return emptyValue ? 'screen' : '';
  },
  targetAdmission(hasId, visible) {
    return hasId && visible;
  },
  returnVisible(offered, top, bottom, height) {
    return offered && !(top < height - 120 && bottom > 0);
  },
  selectionView(value, hasTarget, scroll, picking, updateUrl) {
    const status = value && !hasTarget ? 2 : picking ? 0 : hasTarget && value !== 'screen' ? 3 : 1;
    const messages = ['', '', 'This area is unavailable in the current preview.', 'Highlighted: '];
    const scrollTarget = scroll && hasTarget;
    const scrollApp = scrollTarget && value === 'app';
    return [updateUrl ? (value ? 2 : 1) : 0, Boolean(value && hasTarget), scrollApp,
      scrollTarget ? (scrollApp ? 'start' : 'center') : '',
      status !== 0, status === 3, messages[status], status === 3 ? 'selected area' : ''];
  },
  commentVisible(filter, context) {
    return !filter || filter === context;
  },
  pickKey(picking, key, hasTarget) {
    return !picking ? 0 : key === 'Escape' ? 1 : hasTarget && (key === 'Enter' || key === ' ') ? 2 : 0;
  },
  targetFamily(route) {
    return ['sick-leave', 'timesheet', 'report'].indexOf(route) + 1;
  },
  targetSelectors(family) {
    if (family === 1) return ['form', 'main > ul > li', 'action', true, false, false];
    if (family === 2) return ["section[aria-label='Your entries'] li a[href]", 'li', 'entry', false, true, false];
    return ['', '', '', false, false, family === 3];
  },
  reportTarget(index) {
    const targets = [
      ['filters', "[aria-label='Report filters']"],
      ['employee-totals', "table[aria-label='Employee totals']"],
      ['minutes-by-employee', "section[aria-label='Minutes by employee']"],
    ];
    return targets[index] ?? ['', ''];
  },
  pickClick(picking, hasTarget) {
    return picking && hasTarget;
  },
  pickAlias(hasAlias, selected) {
    return [selected || !hasAlias, !hasAlias];
  },
  pickerStarts(picking, hasTargets) {
    return !picking && hasTargets;
  },
  menuChoice(emptyValue, screenAvailable, targetAvailable) {
    return emptyValue ? (screenAvailable ? 1 : 0) : (targetAvailable ? 2 : 0);
  },
  selectionFollowup(source) {
    const fromMenu = source === 'menu';
    const returning = source === 'return';
    const compose = returning || source === 'picker';
    return [fromMenu, !fromMenu && !returning, !fromMenu, compose, !fromMenu && !compose, 'nearest', 'center'];
  },
  commentControls() {
    return ['Back to comments', 'Show all comments'];
  },
  commentSummary(filtered, count) {
    return [count > 0, filtered, filtered ? " · " : "", count === 1 ? " comment" : " comments"];
  },
  commentBadge(context, count, hasTarget, onApp, onScreen, inList) {
    return [hasTarget ? (onApp ? 1 : onScreen ? 2 : inList ? 3 : 4) : 0,
      context === "screen" ? "This screen · " : "", count === 1 ? " comment" : " comments", ": "];
  },
  contextLabel(context) {
    return context === 'screen' ? 'This screen' : context === 'app' ? 'Whole app' : '';
  },
  contextLabelSource(option, element, comment) {
    const source = option ? 1 : element ? 2 : comment ? 3 : 0;
    return [source, source ? '' : 'Selected area'];
  },
  pickerView(active) {
    return active ? ['Cancel picking', 'Pick an area, this screen, or Whole app. Press Escape to cancel.'] : ['Pick on preview', ''];
  },
  paneAdmission(hasPane, alreadyBound) {
    return hasPane && !alreadyBound;
  },
  selectValue(value, available) {
    return available && value !== 'screen';
  },
  optionDisabled(value, available) {
    return Boolean(value && !available);
  },
};
