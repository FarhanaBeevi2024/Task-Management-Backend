/**
 * Internal workflow status (independent of Kanban board columns: to_do, in_progress, in_review, done).
 * Allowed workflow values depend on board column — see WORKFLOW_STATUSES_FOR_*.
 */

export const DEFAULT_WORKFLOW_STATUS = 'Dev In Progress';

/** Full list (DB / legacy / To Do & Done columns may still store any of these). */
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

/** First four workflow steps — only for board column **In Progress** (`status === 'in_progress'`). */
export const WORKFLOW_STATUSES_FOR_IN_PROGRESS = [
  'Dev In Progress',
  'Dev Complete',
  'Released for UAT',
  'UAT In Progress',
];

/** Last four workflow steps — only for board column **In Review** (`status === 'in_review'`). */
export const WORKFLOW_STATUSES_FOR_IN_REVIEW = [
  'UAT Complete',
  'Production Released',
  'Require Internal Clarification',
  'Waiting for Client Clarification',
];

const FULL_SET = new Set(WORKFLOW_STATUSES);
const IN_PROGRESS_SET = new Set(WORKFLOW_STATUSES_FOR_IN_PROGRESS);
const IN_REVIEW_SET = new Set(WORKFLOW_STATUSES_FOR_IN_REVIEW);

export function defaultWorkflowForBoardStatus(boardStatus) {
  const s = String(boardStatus || '').trim();
  if (s === 'in_review') return WORKFLOW_STATUSES_FOR_IN_REVIEW[0];
  if (s === 'in_progress') return WORKFLOW_STATUSES_FOR_IN_PROGRESS[0];
  return DEFAULT_WORKFLOW_STATUS;
}

/**
 * When board column changes, keep workflow valid for the new column.
 */
export function coerceWorkflowForBoardStatus(currentWorkflow, boardStatus) {
  const w = String(currentWorkflow || '').trim();
  const bs = String(boardStatus || '').trim();
  if (bs === 'in_progress') {
    return IN_PROGRESS_SET.has(w) ? w : WORKFLOW_STATUSES_FOR_IN_PROGRESS[0];
  }
  if (bs === 'in_review') {
    return IN_REVIEW_SET.has(w) ? w : WORKFLOW_STATUSES_FOR_IN_REVIEW[0];
  }
  if (FULL_SET.has(w)) return w;
  return DEFAULT_WORKFLOW_STATUS;
}

/**
 * @param {unknown} value
 * @param {string} [boardStatus] issues.status — required for strict validation on in_progress / in_review
 * @returns {string} always one of WORKFLOW_STATUSES
 */
export function normalizeWorkflowStatus(value, boardStatus) {
  if (value == null || value === '') {
    return defaultWorkflowForBoardStatus(boardStatus);
  }
  const s = String(value).trim();
  if (!FULL_SET.has(s)) return defaultWorkflowForBoardStatus(boardStatus);
  const bs = String(boardStatus || '').trim();
  if (bs === 'in_progress' && IN_PROGRESS_SET.has(s)) return s;
  if (bs === 'in_review' && IN_REVIEW_SET.has(s)) return s;
  if (bs === 'in_progress') return WORKFLOW_STATUSES_FOR_IN_PROGRESS[0];
  if (bs === 'in_review') return WORKFLOW_STATUSES_FOR_IN_REVIEW[0];
  return s;
}

/**
 * @param {unknown} value
 * @param {string} [boardStatus]
 * @returns {{ ok: true, value: string } | { ok: false, error: string }}
 */
export function validateWorkflowStatus(value, boardStatus) {
  if (value === undefined || value === null || value === '') {
    return { ok: true, value: defaultWorkflowForBoardStatus(boardStatus) };
  }
  const s = String(value).trim();
  if (!FULL_SET.has(s)) {
    return { ok: false, error: `Invalid workflow_status. Allowed: ${WORKFLOW_STATUSES.join(', ')}` };
  }
  const bs = String(boardStatus || '').trim();
  if (bs === 'in_progress' && !IN_PROGRESS_SET.has(s)) {
    return {
      ok: false,
      error: `For In Progress tasks, workflow_status must be one of: ${WORKFLOW_STATUSES_FOR_IN_PROGRESS.join(', ')}`,
    };
  }
  if (bs === 'in_review' && !IN_REVIEW_SET.has(s)) {
    return {
      ok: false,
      error: `For In Review tasks, workflow_status must be one of: ${WORKFLOW_STATUSES_FOR_IN_REVIEW.join(', ')}`,
    };
  }
  return { ok: true, value: s };
}
