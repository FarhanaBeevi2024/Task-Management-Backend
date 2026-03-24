import { supabaseAdmin } from './supabaseAdmin.js';
import { userRoleFromOrgMemberRole } from './roleWorkspace.js';
import { normalizeInviteEmail, escapeIlikeExact } from './inviteHelpers.js';

/**
 * Find user id by profile email (case-insensitive exact match).
 * Profile id matches auth.users id when the row exists.
 */
export async function findProfileUserIdByNormalizedEmail(emailNorm) {
  const e = normalizeInviteEmail(emailNorm);
  if (!e || !e.includes('@')) return null;
  const { data: prof, error } = await supabaseAdmin
    .from('profiles')
    .select('id')
    .ilike('email', escapeIlikeExact(e))
    .maybeSingle();
  if (error) throw error;
  return prof?.id || null;
}

/**
 * Find auth.users id for this email: profiles first (fast), then paginated Auth admin list.
 * Use this when deciding whether to add organization_members vs sending an invite.
 */
export async function findAuthUserIdByNormalizedEmail(emailNorm) {
  const fromProfile = await findProfileUserIdByNormalizedEmail(emailNorm);
  if (fromProfile) return fromProfile;

  const e = normalizeInviteEmail(emailNorm);
  if (!e || !e.includes('@')) return null;

  let page = 1;
  const perPage = 1000;
  for (let i = 0; i < 50; i += 1) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const users = data?.users ?? [];
    for (const u of users) {
      if (normalizeInviteEmail(u.email) === e) return u.id;
    }
    const next = data?.nextPage;
    if (next == null || users.length === 0) break;
    page = next;
  }
  return null;
}

/**
 * Ensure user is in organization_members for this org. If they were only in other orgs before,
 * does not overwrite user_roles (multi-workspace).
 */
export async function ensureOrganizationMember({ organizationId, userId, orgMemberRole }) {
  const orgIdStr = String(organizationId);
  const { data: allMem, error: memErr } = await supabaseAdmin
    .from('organization_members')
    .select('organization_id')
    .eq('user_id', userId);
  if (memErr) throw memErr;

  const inThisOrg = (allMem || []).some((m) => String(m.organization_id) === orgIdStr);
  if (inThisOrg) {
    return { alreadyMember: true, inserted: false };
  }

  const membershipsOutsideTarget = (allMem || []).filter(
    (m) => String(m.organization_id) !== orgIdStr
  );
  const shouldSyncGlobalUserRole = membershipsOutsideTarget.length === 0;

  const { error: insErr } = await supabaseAdmin.from('organization_members').insert([
    {
      organization_id: organizationId,
      user_id: userId,
      role: orgMemberRole,
    },
  ]);
  if (insErr) throw insErr;

  if (shouldSyncGlobalUserRole) {
    const ur = userRoleFromOrgMemberRole(orgMemberRole);
    await supabaseAdmin
      .from('user_roles')
      .upsert({ user_id: userId, role: ur, is_active: true }, { onConflict: 'user_id' });
  }

  return { alreadyMember: false, inserted: true };
}

/**
 * True if logged-in user matches the invitation email (JWT, Supabase Auth, or profiles row).
 */
export async function invitationMatchesUser(userId, invitationEmailNorm, jwtEmail = null) {
  const expected = normalizeInviteEmail(invitationEmailNorm);
  if (!expected) return false;

  if (normalizeInviteEmail(jwtEmail) === expected) return true;

  const { data: authData, error: authErr } = await supabaseAdmin.auth.admin.getUserById(userId);
  if (authErr) throw authErr;
  const authEmail = normalizeInviteEmail(authData?.user?.email);
  if (authEmail === expected) return true;

  const { data: prof, error: profErr } = await supabaseAdmin
    .from('profiles')
    .select('email')
    .eq('id', userId)
    .maybeSingle();
  if (profErr) throw profErr;
  const profileEmail = normalizeInviteEmail(prof?.email);
  return profileEmail === expected;
}
