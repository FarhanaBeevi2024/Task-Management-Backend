import express from 'express';

import { supabaseAdmin } from '../supabaseAdmin.js';
import { authenticate, loadGlobalRole } from '../middleware/auth.js';
import { requireOrgContext } from '../middleware/organization.js';
import { generateInviteToken, inviteSignupUrl } from '../inviteHelpers.js';
import {
  findAuthUserIdByNormalizedEmail,
  ensureOrganizationMember,
} from '../orgMembershipHelpers.js';
import {
  inviteWorkspaceRoleToOrgRole,
  workspaceRoleFromOrgMember,
  userRoleFromOrgMemberRole,
} from '../roleWorkspace.js';
import { canManageOrgDirectory, requireCanManageOrgMembers } from '../services/authz.js';

const router = express.Router();

// SuperAdmin: create organization
router.post('/organizations', authenticate, loadGlobalRole, async (req, res) => {
  try {
    if (!req.isSuperAdmin) return res.status(403).json({ error: 'Only superadmin can create organizations' });
    const { name } = req.body || {};
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'name is required' });

    const { data: org, error } = await supabaseAdmin
      .from('organizations')
      .insert([{ name: String(name).trim(), created_by: req.user.id, status: 'active' }])
      .select('*')
      .single();
    if (error) throw error;
    res.status(201).json(org);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// SuperAdmin: disable/enable organization
router.patch('/organizations/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    if (!req.isSuperAdmin) return res.status(403).json({ error: 'Only superadmin can update organizations' });
    const { status, name } = req.body || {};
    const updates = {};
    if (status !== undefined) updates.status = status;
    if (name !== undefined) updates.name = name;
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No valid fields' });

    const { data, error } = await supabaseAdmin
      .from('organizations')
      .update(updates)
      .eq('id', req.params.id)
      .select('*')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Org Admin: list members
router.get(
  '/organizations/:id/members',
  authenticate,
  loadGlobalRole,
  (req, _res, next) => {
    req.orgIdFromRoute = req.params.id;
    next();
  },
  requireOrgContext,
  requireCanManageOrgMembers,
  async (req, res) => {
    try {
      if (!req.isSuperAdmin && String(req.organizationId) !== String(req.params.id)) {
        return res.status(403).json({ error: 'Cannot access other organizations' });
      }
      const { data: members, error } = await supabaseAdmin
        .from('organization_members')
        .select('user_id, role, joined_at')
        .eq('organization_id', req.organizationId);
      if (error) throw error;

      const userIds = (members || []).map((m) => m.user_id);
      const [{ data: profiles }, { data: roles }] = await Promise.all([
        supabaseAdmin.from('profiles').select('id, email').in('id', userIds),
        supabaseAdmin.from('user_roles').select('user_id, role, is_active').in('user_id', userIds),
      ]);

      const emailById = new Map((profiles || []).map((p) => [p.id, p.email]));
      const globalById = new Map((roles || []).map((r) => [r.user_id, r]));

      res.json(
        (members || []).map((m) => {
          const gr = globalById.get(m.user_id)?.role || 'user';
          return {
            user_id: m.user_id,
            email: emailById.get(m.user_id) || 'Unknown',
            org_role: m.role,
            joined_at: m.joined_at,
            workspace_role: workspaceRoleFromOrgMember(m.role, gr),
            global_role: gr,
            active: globalById.get(m.user_id)?.is_active !== false,
          };
        })
      );
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// Org Admin: workspace role as organization_members (admin | team_member) + user_roles (admin | user)
router.put(
  '/organizations/:id/members/:userId',
  authenticate,
  loadGlobalRole,
  (req, _res, next) => {
    req.orgIdFromRoute = req.params.id;
    next();
  },
  requireOrgContext,
  requireCanManageOrgMembers,
  async (req, res) => {
    try {
      if (!req.isSuperAdmin && String(req.organizationId) !== String(req.params.id)) {
        return res.status(403).json({ error: 'Cannot access other organizations' });
      }
      const { role } = req.body || {};
      const allowed = ['admin', 'team_member'];
      if (!allowed.includes(role)) return res.status(400).json({ error: 'Invalid role' });

      const { data, error } = await supabaseAdmin
        .from('organization_members')
        .update({ role })
        .eq('organization_id', req.organizationId)
        .eq('user_id', req.params.userId)
        .select('organization_id, user_id, role')
        .single();
      if (error) throw error;

      const ur = userRoleFromOrgMemberRole(role);
      await supabaseAdmin
        .from('user_roles')
        .upsert({ user_id: req.params.userId, role: ur, is_active: true }, { onConflict: 'user_id' });
      res.json(data);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

async function createOrgInvitationRecord({ organizationId, emailRaw, orgRole, invitedByUserId }) {
  const email = String(emailRaw || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    const err = new Error('Valid email required');
    err.statusCode = 400;
    throw err;
  }
  const role = inviteWorkspaceRoleToOrgRole(orgRole);

  // Existing portal user: add to this workspace directly (no signup link / email mismatch).
  const existingUserId = await findAuthUserIdByNormalizedEmail(email);
  if (existingUserId) {
    const { data: inOrg, error: inOrgErr } = await supabaseAdmin
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', organizationId)
      .eq('user_id', existingUserId)
      .maybeSingle();
    if (inOrgErr) throw inOrgErr;
    if (inOrg) {
      const err = new Error('This user is already a member of this organization');
      err.statusCode = 409;
      throw err;
    }
    await supabaseAdmin.from('profiles').upsert({ id: existingUserId, email }, { onConflict: 'id' });
    await ensureOrganizationMember({
      organizationId,
      userId: existingUserId,
      orgMemberRole: role,
    });
    await supabaseAdmin
      .from('organization_invitations')
      .delete()
      .eq('organization_id', organizationId)
      .eq('email', email);
    return {
      added_existing_user: true,
      user_id: existingUserId,
      email,
      organization_id: organizationId,
      role,
      signup_url: null,
      email_send_error: null,
    };
  }

  const token = generateInviteToken();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  await supabaseAdmin.from('organization_invitations').delete().eq('organization_id', organizationId).eq('email', email);

  const { data, error } = await supabaseAdmin
    .from('organization_invitations')
    .insert([
      {
        organization_id: organizationId,
        email,
        role,
        invitation_token: token,
        invited_by: invitedByUserId,
        status: 'pending',
        expires_at: expiresAt,
      },
    ])
    .select('*')
    .single();
  if (error) throw error;

  // Send Supabase-managed invite email (user will complete password on Supabase).
  let emailSendError = null;
  try {
    await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
      redirectTo: inviteSignupUrl(token),
      data: { invitation_token: token, organization_id: organizationId },
    });
  } catch (e) {
    console.error('Failed to send Supabase invite email:', e?.message || e);
    emailSendError = e?.message || String(e);
  }

  return {
    ...data,
    signup_url: inviteSignupUrl(token),
    email_send_error: emailSendError,
  };
}

// Org Admin: create invitation (signup link + email in response)
router.post(
  '/organizations/:id/invitations',
  authenticate,
  loadGlobalRole,
  (req, _res, next) => {
    req.orgIdFromRoute = req.params.id;
    next();
  },
  requireOrgContext,
  requireCanManageOrgMembers,
  async (req, res) => {
    try {
      if (!req.isSuperAdmin && String(req.organizationId) !== String(req.params.id)) {
        return res.status(403).json({ error: 'Cannot access other organizations' });
      }
      const { email, role } = req.body || {};
      const row = await createOrgInvitationRecord({
        organizationId: req.organizationId,
        emailRaw: email,
        orgRole: role,
        invitedByUserId: req.user.id,
      });
      res.status(201).json(row);
    } catch (e) {
      const code = e.statusCode || 500;
      res.status(code).json({ error: e.message });
    }
  }
);

// Same as POST /api/organizations/:id/invitations but uses active org from X-Organization-Id (Users page).
router.post(
  '/organization/invitations',
  authenticate,
  loadGlobalRole,
  requireOrgContext,
  requireCanManageOrgMembers,
  async (req, res) => {
    try {
      const { email, role } = req.body || {};
      const row = await createOrgInvitationRecord({
        organizationId: req.organizationId,
        emailRaw: email,
        orgRole: role,
        invitedByUserId: req.user.id,
      });
      res.status(201).json(row);
    } catch (e) {
      const code = e.statusCode || 500;
      res.status(code).json({ error: e.message });
    }
  }
);

// Org Admin: list invitations (pending/accepted/expired)
router.get(
  '/organizations/:id/invitations',
  authenticate,
  loadGlobalRole,
  (req, _res, next) => {
    req.orgIdFromRoute = req.params.id;
    next();
  },
  requireOrgContext,
  requireCanManageOrgMembers,
  async (req, res) => {
    try {
      if (!req.isSuperAdmin && String(req.organizationId) !== String(req.params.id)) {
        return res.status(403).json({ error: 'Cannot access other organizations' });
      }
      const { status } = req.query || {};
      let q = supabaseAdmin
        .from('organization_invitations')
        .select('*')
        .eq('organization_id', req.organizationId)
        .order('created_at', { ascending: false });
      if (status) q = q.eq('status', status);
      const { data, error } = await q;
      if (error) throw error;
      res.json(data || []);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

/**
 * Add a user who already has auth + profiles row but no organization_members row
 * into the caller's organization (typical self-signup onboarding).
 */
router.post('/organization/add-member', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    if (req.isSuperAdmin) {
      return res.status(400).json({ error: 'Superadmin: use organization-specific member APIs' });
    }
    if (!(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to add organization members' });
    }
    const { user_id: userId, org_role: orgRoleBody } = req.body || {};
    if (!userId) return res.status(400).json({ error: 'user_id is required' });
    const orgRole = inviteWorkspaceRoleToOrgRole(orgRoleBody);

    const { data: alreadyHere, error: hereErr } = await supabaseAdmin
      .from('organization_members')
      .select('organization_id, user_id, role')
      .eq('organization_id', req.organizationId)
      .eq('user_id', userId)
      .maybeSingle();
    if (hereErr) throw hereErr;
    if (alreadyHere) {
      return res.status(409).json({ error: 'This user is already a member of this organization' });
    }

    await ensureOrganizationMember({
      organizationId: req.organizationId,
      userId,
      orgMemberRole: orgRole,
    });

    const { data, error } = await supabaseAdmin
      .from('organization_members')
      .select('organization_id, user_id, role')
      .eq('organization_id', req.organizationId)
      .eq('user_id', userId)
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;

