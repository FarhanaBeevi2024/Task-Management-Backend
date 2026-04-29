import { supabaseAdmin } from '../supabaseAdmin.js';
import { canManageUsers } from '../accessConfig.js';

// Get user role
export const getUserRole = async (userId) => {
  const { data, error } = await supabaseAdmin
    .from('user_roles')
    .select('role')
    .eq('user_id', userId)
    .single();

  if (error || !data) return 'user';
  return data.role;
};

export async function isOrgAdminUser(userId, organizationId) {
  if (!organizationId) return false;
  const { data: m } = await supabaseAdmin
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .maybeSingle();
  return m?.role === 'admin';
}

/** User directory + invites: superadmin, global canManageUsers, or org workspace admin. */
export async function canManageOrgDirectory(req) {
  if (req.isSuperAdmin) return true;
  const globalRole = await getUserRole(req.user.id);
  if (canManageUsers(globalRole)) return true;
  if (await isOrgAdminUser(req.user.id, req.organizationId)) return true;
  return false;
}

/** Org member/invitation admin APIs: superadmin bypass; global canManageUsers; or org admin. */
export async function requireCanManageOrgMembers(req, res, next) {
  try {
    if (req.isSuperAdmin) return next();
    const globalRole = await getUserRole(req.user.id);
    if (canManageUsers(globalRole)) return next();
    if (await isOrgAdminUser(req.user.id, req.organizationId)) return next();
    return res.status(403).json({ error: 'You do not have permission to manage organization members' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

