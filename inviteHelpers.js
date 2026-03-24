import crypto from 'crypto';

export function normalizeInviteEmail(e) {
  return String(e || '').trim().toLowerCase();
}

/** Escape `%` and `_` for PostgREST `ilike` exact match. */
export function escapeIlikeExact(value) {
  return String(value || '')
    .replace(/\\/g, '\\\\')
    .replace(/%/g, '\\%')
    .replace(/_/g, '\\_');
}

export function inviteEmailsMatch(a, b) {
  return normalizeInviteEmail(a) === normalizeInviteEmail(b);
}

/**
 * Workspace directory roles after invite acceptance are only admin | user (see roleWorkspace.js).
 * Kept for any legacy callers; prefer validating invite bodies in route handlers.
 */
export const INVITE_GLOBAL_ROLES = ['admin', 'user'];

export function normalizeGlobalRole(role) {
  const r = (role || 'user').toString().trim().toLowerCase();
  return INVITE_GLOBAL_ROLES.includes(r) ? r : 'user';
}

export function generateInviteToken() {
  return crypto.randomBytes(32).toString('hex');
}

export function inviteSignupUrl(token) {
  const base = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
  const sep = base.includes('?') ? '&' : '?';
  return `${base}${sep}invite=${encodeURIComponent(token)}`;
}
