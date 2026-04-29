import express from 'express';

import { supabaseAdmin } from '../supabaseAdmin.js';
import { authenticate, loadGlobalRole } from '../middleware/auth.js';
import { requireOrgContext } from '../middleware/organization.js';
import {
  canManageUsers,
  canViewAllUsers,
  refreshRoleAccessCache,
  getAccessConfigPayload,
  upsertRoleAccessFromBody,
} from '../accessConfig.js';
import {
  inviteWorkspaceRoleToOrgRole,
  workspaceRoleFromOrgMember,
  workspaceRoleToOrgMemberRole,
} from '../roleWorkspace.js';
import { ensureOrganizationMember } from '../orgMembershipHelpers.js';
import { canManageOrgDirectory, getUserRole } from '../services/authz.js';

const router = express.Router();

// Get all users (for task assignment or user management) - org-scoped unless superadmin
router.get('/users', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);

    // SuperAdmin can still view all users across orgs if allowed by config
    if (req.isSuperAdmin && canViewAllUsers(userRole)) {
      const { data: profiles, error: profilesError } = await supabaseAdmin.from('profiles').select('id, email');
      if (profilesError) throw profilesError;
      const profileIds = profiles.map((p) => p.id);
      const { data: userRoles, error: rolesError } = await supabaseAdmin
        .from('user_roles')
        .select('user_id, role, is_active')
        .in('user_id', profileIds);
      if (rolesError) throw rolesError;
      const roleByUserId = new Map(userRoles.map((ur) => [ur.user_id, ur]));
      const users = profiles.map((p) => {
        const ur = roleByUserId.get(p.id);
        return {
          user_id: p.id,
          email: p.email || 'Unknown',
          role: ur?.role || 'user',
          active: ur?.is_active !== false,
          pending_org_membership: false,
        };
      });
      return res.json(users);
    }

    if (!req.isSuperAdmin && !canViewAllUsers(userRole) && !(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to list organization users' });
    }

    // Org-scoped list: members of this org.
    const { data: members, error: membersError } = await supabaseAdmin
      .from('organization_members')
      .select('user_id, role')
      .eq('organization_id', req.organizationId);
    if (membersError) throw membersError;

    const memberIds = (members || []).map((m) => m.user_id);
    const orgRoleById = new Map((members || []).map((m) => [m.user_id, m.role]));

    let userIds = [...memberIds];

    const projectId = String(req.query?.project_id || '').trim();
    if (projectId) {
      const { data: allAssocRows, error: allowedErr } = await supabaseAdmin
        .from('organization_user_project_access')
        .select('user_id')
        .eq('organization_id', req.organizationId);
      if (allowedErr) throw allowedErr;
      const usersWithExplicitAssociation = new Set((allAssocRows || []).map((r) => r.user_id));

      const { data: projectRows, error: projectRowsErr } = await supabaseAdmin
        .from('organization_user_project_access')
        .select('user_id')
        .eq('organization_id', req.organizationId)
        .eq('project_id', projectId);
      if (projectRowsErr) throw projectRowsErr;
      const allowedUserIdsForProject = new Set((projectRows || []).map((r) => r.user_id));

      // Default behavior: if a user has no explicit project rows, they are allowed on all projects.
      // If they have explicit rows, they are allowed only on listed projects.
      userIds = userIds.filter((id) => !usersWithExplicitAssociation.has(id) || allowedUserIdsForProject.has(id));
    }

    if (userIds.length === 0) {
      return res.json([]);
    }

    const [{ data: profiles, error: profilesError }, { data: userRoles, error: rolesError }] = await Promise.all([
      supabaseAdmin.from('profiles').select('id, email, first_name, last_name').in('id', userIds),
      supabaseAdmin.from('user_roles').select('user_id, role, is_active').in('user_id', userIds),
    ]);
    if (profilesError) throw profilesError;
    if (rolesError) throw rolesError;

    const profileById = new Map((profiles || []).map((p) => [p.id, p]));
    const globalById = new Map((userRoles || []).map((r) => [r.user_id, r]));

    const rows = userIds
      .map((id) => {
        const orgRole = orgRoleById.get(id) ?? null;
        const gr = globalById.get(id)?.role || 'user';
        const workspaceRole = workspaceRoleFromOrgMember(orgRole, gr);
        return {
          user_id: id,
          email: profileById.get(id)?.email || 'Unknown',
          first_name: profileById.get(id)?.first_name || '',
          last_name: profileById.get(id)?.last_name || '',
          role: workspaceRole,
          active: globalById.get(id)?.is_active !== false,
          pending_org_membership: !orgRoleById.has(id),
        };
      })
      .filter((row) => {
        // Non-superadmins shouldn't see superadmin accounts in Users UI.
        if (req.isSuperAdmin) return true;
        const globalRole = globalById.get(row.user_id)?.role || 'user';
        return globalRole !== 'superadmin';
      });
    rows.sort((a, b) => String(a.email || '').localeCompare(String(b.email || ''), undefined, { sensitivity: 'base' }));
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Role access matrix (for UI + permission checks; stored in role_access_config)
router.get('/access-config', authenticate, (req, res) => {
  try {
    res.json(getAccessConfigPayload());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/admin/role-access', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const currentUserRole = await getUserRole(req.user.id);
    if (!canManageUsers(currentUserRole)) {
      return res.status(403).json({ error: 'You do not have permission to edit role access' });
    }
    const body = req.body || {};
    if (!body.roles || typeof body.roles !== 'object') {
      return res.status(400).json({ error: 'Expected JSON body: { roles: { [roleKey]: { global, project } } }' });
    }
    await upsertRoleAccessFromBody(body.roles);
    await refreshRoleAccessCache();
    res.json(getAccessConfigPayload());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: get user-project associations
router.get('/admin/user-project-associations', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    if (!(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to view user project associations' });
    }
    const { data, error } = await supabaseAdmin
      .from('organization_user_project_access')
      .select('user_id, project_id')
      .eq('organization_id', req.organizationId);
    if (error) throw error;
    res.json({ associations: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put(
  '/admin/users/:userId/project-associations',
  authenticate,
  loadGlobalRole,
  requireOrgContext,
  async (req, res) => {
    try {
      if (!(await canManageOrgDirectory(req))) {
        return res.status(403).json({ error: 'You do not have permission to manage user project associations' });
      }

      const userId = req.params.userId;
      const inputIds = Array.isArray(req.body?.project_ids) ? req.body.project_ids : null;
      if (inputIds == null) {
        return res.status(400).json({ error: 'project_ids must be an array' });
      }
      const nextProjectIds = [...new Set(inputIds.map((v) => String(v || '').trim()).filter(Boolean))];

      // Only allow projects from caller's organization.
      let validProjectIds = [];
      if (nextProjectIds.length > 0) {
        const { data: validProjects, error: validErr } = await supabaseAdmin
          .from('projects')
          .select('id')
          .eq('organization_id', req.organizationId)
          .in('id', nextProjectIds);
        if (validErr) throw validErr;
        validProjectIds = (validProjects || []).map((p) => p.id);
      }

      const { error: delErr } = await supabaseAdmin
        .from('organization_user_project_access')
        .delete()
        .eq('organization_id', req.organizationId)
        .eq('user_id', userId);
      if (delErr) throw delErr;

      if (validProjectIds.length > 0) {
        const rows = validProjectIds.map((projectId) => ({
          organization_id: req.organizationId,
          user_id: userId,
          project_id: projectId,
        }));
        const { error: insErr } = await supabaseAdmin.from('organization_user_project_access').insert(rows);
        if (insErr) throw insErr;
      }

      res.json({ ok: true, user_id: userId, project_ids: validProjectIds });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Admin create user
router.post('/admin/users/create', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    if (!(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to create users' });
    }

    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const firstName = String(req.body?.first_name || '').trim();
    const lastName = String(req.body?.last_name || '').trim();
    const workspaceRole = String(req.body?.role || 'user').trim().toLowerCase();
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (workspaceRole !== 'admin' && workspaceRole !== 'user') {
      return res.status(400).json({ error: 'Role must be admin or user' });
    }

    const created = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        ...(firstName ? { first_name: firstName } : {}),
        ...(lastName ? { last_name: lastName } : {}),
      },
    });
    if (created.error) throw created.error;
    const userId = created.data?.user?.id;
    if (!userId) {
      return res.status(500).json({ error: 'Failed to create user account' });
    }

    const orgRole = inviteWorkspaceRoleToOrgRole(workspaceRole);
    await ensureOrganizationMember({
      organizationId: req.organizationId,
      userId,
      orgMemberRole: orgRole,
    });

    const { error: roleErr } = await supabaseAdmin
      .from('user_roles')
      .upsert({ user_id: userId, role: workspaceRole, is_active: true }, { onConflict: 'user_id' });
    if (roleErr) throw roleErr;

    const { error: profileErr } = await supabaseAdmin
      .from('profiles')
      .upsert({ id: userId, email, first_name: firstName || null, last_name: lastName || null }, { onConflict: 'id' });
    if (profileErr) throw profileErr;

    res.status(201).json({ user_id: userId, email, role: workspaceRole, active: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;

