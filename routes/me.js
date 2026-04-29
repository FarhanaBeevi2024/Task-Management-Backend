import express from 'express';

import { authenticate, loadGlobalRole } from '../middleware/auth.js';
import { supabaseAdmin } from '../supabaseAdmin.js';
import { getUserRole } from '../services/authz.js';

const router = express.Router();

// Get user info
router.get('/user', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const role = await getUserRole(req.user.id);

    // Profiles may not have first/last columns in older DBs; don't block /api/user.
    let firstName = null;
    let lastName = null;
    try {
      const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('first_name, last_name')
        .eq('id', req.user.id)
        .maybeSingle();
      firstName = profile?.first_name ?? null;
      lastName = profile?.last_name ?? null;
    } catch {
      // Ignore profile projection errors; keep null names.
    }
    let orgMemberRole = null;
    const orgHeader = (req.headers['x-organization-id'] || '').trim();
    if (orgHeader && !req.isSuperAdmin) {
      const { data: om } = await supabaseAdmin
        .from('organization_members')
        .select('role')
        .eq('organization_id', orgHeader)
        .eq('user_id', req.user.id)
        .maybeSingle();
      orgMemberRole = om?.role ?? null;
    }

    res.json({
      id: req.user.id,
      email: req.user.email,
      role: role,
      first_name: firstName,
      last_name: lastName,
      org_member_role: orgMemberRole,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/** Organizations the current user belongs to (for workspace switcher). */
router.get('/me/organizations', authenticate, loadGlobalRole, async (req, res) => {
  try {
    if (req.isSuperAdmin) {
      return res.json({ organizations: [], is_superadmin: true });
    }
    const { data, error } = await supabaseAdmin
      .from('organization_members')
      .select('organization_id, role, organizations:organization_id(id, name, status)')
      .eq('user_id', req.user.id);
    if (error) throw error;
    const orgs = (data || [])
      .filter((m) => m.organizations?.status === 'active')
      .map((m) => ({
        id: m.organization_id,
        name: m.organizations?.name || 'Organization',
        org_role: m.role,
      }));
    res.json({ organizations: orgs, is_superadmin: false });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;

