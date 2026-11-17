const encounterLegacyAssurance = {
  response(status, warnings) {
    const action = status === 204 ? 0 : status === 200 ? 1 : 2;
    return [action, warnings && action === 2];
  },
  rowLimit(isWarnings) {
    return isWarnings ? 4 : 40;
  },
  presentation(open, warnings, hasRows) {
    return [open && (!warnings || hasRows), !warnings && !hasRows, warnings];
  },
  updateEnvelope(warnings, length, rowsObject, unread, openLimit, exchangeLimit) {
    return length >= 0 && length <= this.rowLimit(warnings) && rowsObject &&
      (!warnings || [unread, openLimit, exchangeLimit].every(value => value >= 0));
  },
  warningHeader(unread) {
    return [unread === 1 ? ' unread warning' : ' unread warnings', 'Budget: under ', ' ms · up to ', ' exchanges'];
  },
  rowAction(key, unique, retained, hasMarkup) {
    return key.length === 20 && !/[^a-f0-9]/.test(key) && unique ? (retained ? 1 : hasMarkup ? 2 : 0) : 0;
  },
  warningAge(now, timestamp) {
    const minutes = Math.max(0, Math.floor((now - timestamp) / 60000));
    const hours = Math.floor(minutes / 60);
    const remainder = minutes % 60;
    const hourSuffix = hours ? (hours === 1 ? ' hour' : ' hours') : '';
    const minuteSuffix = remainder ? (remainder === 1 ? ' minute' : ' minutes') : '';
    return [hours, remainder, hourSuffix, minuteSuffix, hours && remainder ? ' ' : '',
      minutes ? ' · ' : ' · Just now', minutes ? ' ago' : ''];
  },
};
