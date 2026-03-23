/**
 * Internal workflow status (independent of Kanban board columns: to_do, in_progress, etc.)
 */
export const DEFAULT_WORKFLOW_STATUS = 'Dev In Progress';

export const WORKFLOW_STATUSES = [
  'Dev In Progress',
  'Dev Complete',
  'Released for UAT',
  'UAT In Progress',
  'UAT Complete',
  'Production Released',
  'Require Internal Clarification',
  'Waiting for Client Clarification',
];

const SET = new Set(WORKFLOW_STATUSES);

/**
 * @param {unknown} value
 * @returns {string} always one of WORKFLOW_STATUSES
 */
export function normalizeWorkflowStatus(value) {
  if (value == null || value === '') return DEFAULT_WORKFLOW_STATUS;
  const s = String(value).trim();
  return SET.has(s) ? s : DEFAULT_WORKFLOW_STATUS;
}

/**
 * @param {unknown} value
 * @returns {{ ok: true, value: string } | { ok: false, error: string }}
 */
export function validateWorkflowStatus(value) {
  if (value === undefined || value === null || value === '') {
    return { ok: true, value: DEFAULT_WORKFLOW_STATUS };
  }
  const s = String(value).trim();
  if (!SET.has(s)) {
    return { ok: false, error: `Invalid workflow_status. Allowed: ${WORKFLOW_STATUSES.join(', ')}` };
  }
  return { ok: true, value: s };
}
