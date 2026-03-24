import dotenv from 'dotenv';

dotenv.config();

/**
 * Simple structured logger with levels.
 *
 * Set LOG_LEVEL to one of: error | warn | info | debug (default: info)
 * - error: only errors
 * - warn: errors + warnings
 * - info: errors + warnings + informational
 * - debug: everything (includes sensitive debug lines — use only in dev/staging)
 *
 * Aliases: LOG_LEVEL=information maps to info, LOG_LEVEL=warning maps to warn.
 */

const LEVEL_NUM = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

function normalizeLevel(raw) {
  const s = String(raw || 'info').trim().toLowerCase();
  if (s === 'warning') return 'warn';
  if (s === 'information' || s === 'inform') return 'info';
  if (LEVEL_NUM[s] !== undefined) return s;
  return 'info';
}

const configured = normalizeLevel(process.env.LOG_LEVEL);
const threshold = LEVEL_NUM[configured] ?? LEVEL_NUM.info;

function should(level) {
  return LEVEL_NUM[level] <= threshold;
}

/** True when `LOG_LEVEL=debug` — use for optional sensitive diagnostics (e.g. recovery links in logs only). */
export function isDebugEnabled() {
  return threshold >= LEVEL_NUM.debug;
}

function formatPrefix(level) {
  const ts = new Date().toISOString();
  return `[${ts}] [${level.toUpperCase()}]`;
}

export const logger = {
  /** Normalized level name from `LOG_LEVEL`. */
  level: configured,

  error(...args) {
    if (should('error')) console.error(formatPrefix('error'), ...args);
  },

  warn(...args) {
    if (should('warn')) console.warn(formatPrefix('warn'), ...args);
  },

  info(...args) {
    if (should('info')) console.info(formatPrefix('info'), ...args);
  },

  debug(...args) {
    if (should('debug')) console.debug(formatPrefix('debug'), ...args);
  },
};
