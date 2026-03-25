import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jiraRouter from './jira_api.js';
import superadminRouter from './superadminRoutes.js';
import publicInviteRouter from './publicInviteRoutes.js';
import { generateInviteToken, inviteSignupUrl } from './inviteHelpers.js';
import {
  findAuthUserIdByNormalizedEmail,
  ensureOrganizationMember,
} from './orgMembershipHelpers.js';
import {
  workspaceRoleFromOrgMember,
  workspaceRoleToOrgMemberRole,
  userRoleFromOrgMemberRole,
  inviteWorkspaceRoleToOrgRole,
} from './roleWorkspace.js';
import {
  canManageUsers,
  canViewAllUsers,
  refreshRoleAccessCache,
  getAccessConfigPayload,
  upsertRoleAccessFromBody,
} from './accessConfig.js';
import { supabaseAdmin } from './supabaseAdmin.js';
import { authenticate, loadGlobalRole } from './middleware/auth.js';
import { requireOrgContext } from './middleware/organization.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/api/public', publicInviteRouter);

// Get user role
const getUserRole = async (userId) => {
  const { data, error } = await supabaseAdmin
    .from('user_roles')
    .select('role')
    .eq('user_id', userId)
    .single();
  
  if (error || !data) return 'user';
  return data.role;
};

async function isOrgAdminUser(userId, organizationId) {
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
async function canManageOrgDirectory(req) {
  if (req.isSuperAdmin) return true;
  const globalRole = await getUserRole(req.user.id);
  if (canManageUsers(globalRole)) return true;
  if (await isOrgAdminUser(req.user.id, req.organizationId)) return true;
  return false;
}

/** Org member/invitation admin APIs: superadmin bypass; global canManageUsers; or org admin. */
async function requireCanManageOrgMembers(req, res, next) {
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

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// JIRA-like API routes
app.use('/api/jira', jiraRouter);
app.use('/api/superadmin', superadminRouter);

// Get all tasks
app.get('/api/tasks', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    let query = supabaseAdmin.from('tasks').select('*');
    
    // Team members and users can only see tasks assigned to them
    if (userRole === 'user' || userRole === 'team_member') {
      query = query.or(`assigned_to.eq.${req.user.id},created_by.eq.${req.user.id}`);
    }
    // Team leaders, admins and superadmins can see all tasks
    
    const { data, error } = await query.order('created_at', { ascending: false });
    
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single task
app.get('/api/tasks/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (error) throw error;
    
    const userRole = await getUserRole(req.user.id);
    
    // Check access
    if (userRole === 'user' || userRole === 'team_member') {
      if (data.assigned_to !== req.user.id && data.created_by !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create task
app.post('/api/tasks', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    const isManager = userRole === 'team_leader' || userRole === 'admin' || userRole === 'superadmin';

    // Only managers can assign tasks to others
    if (req.body.assigned_to && req.body.assigned_to !== req.user.id && !isManager) {
      return res.status(403).json({ error: 'Only team leaders/admins can assign tasks to others' });
    }
    
    const taskData = {
      ...req.body,
      created_by: req.user.id,
      assigned_to: req.body.assigned_to || req.user.id,
      status: req.body.status || 'pending'
    };
    
    const { data, error } = await supabaseAdmin
      .from('tasks')
      .insert([taskData])
      .select()
      .single();
    
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update task
app.put('/api/tasks/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    // Get current task
    const { data: task, error: taskError } = await supabaseAdmin
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (taskError) throw taskError;
    
    const userRole = await getUserRole(req.user.id);
    const isManager = userRole === 'team_leader' || userRole === 'admin' || userRole === 'superadmin';
    
    // Check permissions
    if (userRole === 'user') {
      // Users can only update their own tasks
      if (task.created_by !== req.user.id) {
        return res.status(403).json({ error: 'You can only update your own tasks' });
      }
    } else if (userRole === 'team_member') {
      // Team members can update status of assigned tasks
      if (task.assigned_to !== req.user.id && task.created_by !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
      }
      // Team members can only update status, not assign to others
      if (req.body.assigned_to && req.body.assigned_to !== task.assigned_to) {
        return res.status(403).json({ error: 'Team members cannot reassign tasks' });
      }
    }
    // Team leaders / admins / superadmins can update anything
    
    const { data, error } = await supabaseAdmin
      .from('tasks')
      .update(req.body)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete task
app.delete('/api/tasks/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const { data: task, error: taskError } = await supabaseAdmin
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (taskError) throw taskError;
    
    const userRole = await getUserRole(req.user.id);
    const isManager = userRole === 'team_leader' || userRole === 'admin' || userRole === 'superadmin';
    
    // Only creator or manager can delete
    if (task.created_by !== req.user.id && !isManager) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const { error } = await supabaseAdmin
      .from('tasks')
      .delete()
      .eq('id', req.params.id);
    
    if (error) throw error;
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user info
app.get('/api/user', authenticate, loadGlobalRole, async (req, res) => {
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
app.get('/api/me/organizations', authenticate, loadGlobalRole, async (req, res) => {
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

// (Removed) GET /api/organizations: was used for workspace switching.
// SuperAdmin uses /api/superadmin/organizations-overview instead.

// SuperAdmin: create organization
app.post('/api/organizations', authenticate, loadGlobalRole, async (req, res) => {
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
app.patch('/api/organizations/:id', authenticate, loadGlobalRole, async (req, res) => {
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
app.get('/api/organizations/:id/members', authenticate, loadGlobalRole, (req, _res, next) => {
  req.orgIdFromRoute = req.params.id;
  next();
}, requireOrgContext, requireCanManageOrgMembers, async (req, res) => {
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

    res.json((members || []).map((m) => {
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
    }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Org Admin: workspace role as organization_members (admin | team_member) + user_roles (admin | user)
app.put('/api/organizations/:id/members/:userId', authenticate, loadGlobalRole, (req, _res, next) => {
  req.orgIdFromRoute = req.params.id;
  next();
}, requireOrgContext, requireCanManageOrgMembers, async (req, res) => {
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
      .upsert(
        { user_id: req.params.userId, role: ur, is_active: true },
        { onConflict: 'user_id' }
      );
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function createOrgInvitationRecord({
  organizationId,
  emailRaw,
  orgRole,
  invitedByUserId,
}) {
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
    await supabaseAdmin.from('profiles').upsert(
      { id: existingUserId, email },
      { onConflict: 'id' }
    );
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

  await supabaseAdmin
    .from('organization_invitations')
    .delete()
    .eq('organization_id', organizationId)
    .eq('email', email);

  const { data, error } = await supabaseAdmin
    .from('organization_invitations')
    .insert([{
      organization_id: organizationId,
      email,
      role,
      invitation_token: token,
      invited_by: invitedByUserId,
      status: 'pending',
      expires_at: expiresAt,
    }])
    .select('*')
    .single();
  if (error) throw error;

  // Send Supabase-managed invite email (user will complete password on Supabase).
  // Note: Supabase's default inbuilt SMTP may only send to pre-authorized team addresses.
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

// Org Admin: create invitation (signup link + email in response; configure SMTP separately for real email)
app.post('/api/organizations/:id/invitations', authenticate, loadGlobalRole, (req, _res, next) => {
  req.orgIdFromRoute = req.params.id;
  next();
}, requireOrgContext, requireCanManageOrgMembers, async (req, res) => {
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
});

// Same as POST /api/organizations/:id/invitations but uses active org from X-Organization-Id (Users page).
app.post('/api/organization/invitations', authenticate, loadGlobalRole, requireOrgContext, requireCanManageOrgMembers, async (req, res) => {
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
});

// Org Admin: list invitations (pending/accepted/expired)
app.get('/api/organizations/:id/invitations', authenticate, loadGlobalRole, (req, _res, next) => {
  req.orgIdFromRoute = req.params.id;
  next();
}, requireOrgContext, requireCanManageOrgMembers, async (req, res) => {
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
});

// Get all users (for task assignment or user management) - now org-scoped unless superadmin
app.get('/api/users', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);

    // SuperAdmin can still view all users across orgs if allowed by config
    if (req.isSuperAdmin && canViewAllUsers(userRole)) {
      const { data: profiles, error: profilesError } = await supabaseAdmin.from('profiles').select('id, email');
      if (profilesError) throw profilesError;
      const profileIds = profiles.map((p) => p.id);
      const { data: userRoles, error: rolesError } = await supabaseAdmin.from('user_roles').select('user_id, role, is_active').in('user_id', profileIds);
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

    // Org-scoped list: members of this org. If user can manage users, also include accounts
    // that have signed up (profiles) but are not in organization_members yet — otherwise
    // self-service signups never appear in the Users UI.
    const { data: members, error: membersError } = await supabaseAdmin
      .from('organization_members')
      .select('user_id, role')
      .eq('organization_id', req.organizationId);
    if (membersError) throw membersError;

    const memberIds = (members || []).map((m) => m.user_id);
    const orgRoleById = new Map((members || []).map((m) => [m.user_id, m.role]));

    let userIds = [...memberIds];
    // Only for User Management: signed-up profiles with no org would pollute assignee
    // dropdowns if we always merged them into GET /api/users.
    const wantPendingSignups =
      String(req.query?.include_pending_signups || '') === '1' ||
      String(req.query?.include_pending_signups || '').toLowerCase() === 'true';
    if (wantPendingSignups && (await canManageOrgDirectory(req))) {
      // Limit pending-signup rows to users invited for this organization.
      // Without this, any orphan profile in the whole system can appear here.
      const { data: invites, error: invitesErr } = await supabaseAdmin
        .from('organization_invitations')
        .select('email, status')
        .eq('organization_id', req.organizationId);
      if (invitesErr) throw invitesErr;
      const invitedEmails = new Set(
        (invites || [])
          .filter((i) => {
            const s = String(i?.status || '').toLowerCase();
            return s === 'pending' || s === 'accepted';
          })
          .map((i) => String(i?.email || '').trim().toLowerCase())
          .filter(Boolean)
      );
      const { data: anyMemberships, error: anyMemErr } = await supabaseAdmin
        .from('organization_members')
        .select('user_id');
      if (anyMemErr) throw anyMemErr;
      const inAnyOrganization = new Set((anyMemberships || []).map((m) => m.user_id));
      const { data: allProfiles, error: allProfilesError } = await supabaseAdmin
        .from('profiles')
        .select('id, email');
      if (allProfilesError) throw allProfilesError;
      const orphanIds = (allProfiles || [])
        .filter((p) => {
          if (!p?.id || inAnyOrganization.has(p.id)) return false;
          const email = String(p.email || '').trim().toLowerCase();
          return invitedEmails.has(email);
        })
        .map((p) => p.id);
      userIds = [...new Set([...memberIds, ...orphanIds])];
    }

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

    const rows = userIds.map((id) => {
      const orgRole = orgRoleById.get(id) ?? null;
      const gr = globalById.get(id)?.role || 'user';
      const workspaceRole = orgRole != null
        ? workspaceRoleFromOrgMember(orgRole, gr)
        : workspaceRoleFromOrgMember(null, gr);
      return {
        user_id: id,
        email: profileById.get(id)?.email || 'Unknown',
        first_name: profileById.get(id)?.first_name || '',
        last_name: profileById.get(id)?.last_name || '',
        role: workspaceRole,
        active: globalById.get(id)?.is_active !== false,
        pending_org_membership: !orgRoleById.has(id),
      };
    }).filter((row) => {
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

app.get('/api/admin/user-project-associations', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
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

app.put('/api/admin/users/:userId/project-associations', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
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
      const { error: insErr } = await supabaseAdmin
        .from('organization_user_project_access')
        .insert(rows);
      if (insErr) throw insErr;
    }

    res.json({ ok: true, user_id: userId, project_ids: validProjectIds });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Add a user who already has auth + profiles row but no organization_members row
 * into the caller's organization (typical self-signup onboarding).
 */
app.post('/api/organization/add-member', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
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

// Role access matrix (for UI + permission checks; stored in role_access_config)
app.get('/api/access-config', authenticate, (req, res) => {
  try {
    res.json(getAccessConfigPayload());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/role-access', authenticate, loadGlobalRole, async (req, res) => {
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

app.post('/api/admin/users/create', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
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
      .upsert(
        { user_id: userId, role: workspaceRole, is_active: true },
        { onConflict: 'user_id' }
      );
    if (roleErr) throw roleErr;

    const { error: profileErr } = await supabaseAdmin
      .from('profiles')
      .upsert(
        { id: userId, email, first_name: firstName || null, last_name: lastName || null },
        { onConflict: 'id' }
      );
    if (profileErr) throw profileErr;

    res.status(201).json({ user_id: userId, email, role: workspaceRole, active: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/users/:userId', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    if (!(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to update users' });
    }

    const userId = req.params.userId;
    const emailRaw = req.body?.email;
    const passwordRaw = req.body?.password;
    const firstNameRaw = req.body?.first_name;
    const lastNameRaw = req.body?.last_name;
    const roleRaw = req.body?.role;
    const activeRaw = req.body?.active;

    const updates = {};
    const email = emailRaw == null ? null : String(emailRaw).trim().toLowerCase();
    const password = passwordRaw == null ? null : String(passwordRaw);
    const firstName = firstNameRaw == null ? null : String(firstNameRaw).trim();
    const lastName = lastNameRaw == null ? null : String(lastNameRaw).trim();
    const nextRole = roleRaw == null ? null : String(roleRaw).trim().toLowerCase();
    const nextActive = activeRaw == null ? null : Boolean(activeRaw);

    if (emailRaw !== undefined) {
      if (!email || !email.includes('@')) {
        return res.status(400).json({ error: 'Valid email is required' });
      }
      updates.email = email;
    }
    if (passwordRaw !== undefined) {
      if (!password || password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      updates.password = password;
    }
    if (firstNameRaw !== undefined) updates.first_name = firstName;
    if (lastNameRaw !== undefined) updates.last_name = lastName;

    if (roleRaw !== undefined) {
      if (nextRole !== 'admin' && nextRole !== 'user') {
        return res.status(400).json({ error: 'Role must be admin or user' });
      }
      if (String(req.user.id) === String(userId) && nextRole === 'user') {
        return res.status(403).json({ error: 'You cannot change your own role to user' });
      }
      updates.role = nextRole;
    }
    if (activeRaw !== undefined) {
      updates.active = nextActive;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    if (updates.email || updates.password || updates.first_name !== undefined || updates.last_name !== undefined) {
      const authPayload = {};
      if (updates.email) authPayload.email = updates.email;
      if (updates.password) authPayload.password = updates.password;
      if (updates.email) authPayload.email_confirm = true;
      if (updates.first_name !== undefined || updates.last_name !== undefined) {
        authPayload.user_metadata = {
          ...(updates.first_name !== undefined ? { first_name: updates.first_name || '' } : {}),
          ...(updates.last_name !== undefined ? { last_name: updates.last_name || '' } : {}),
        };
      }
      const authRes = await supabaseAdmin.auth.admin.updateUserById(userId, authPayload);
      if (authRes.error) throw authRes.error;

      const profilePayload = { id: userId };
      if (updates.email) profilePayload.email = updates.email;
      if (updates.first_name !== undefined) profilePayload.first_name = updates.first_name || null;
      if (updates.last_name !== undefined) profilePayload.last_name = updates.last_name || null;
      const { error: profileErr } = await supabaseAdmin
        .from('profiles')
        .upsert(profilePayload, { onConflict: 'id' });
      if (profileErr) throw profileErr;
    }

    if (updates.role || updates.active !== undefined) {
      const row = {};
      if (updates.role) row.role = updates.role;
      if (updates.active !== undefined) row.is_active = updates.active;
      const { error: roleErr } = await supabaseAdmin
        .from('user_roles')
        .upsert({ user_id: userId, ...row }, { onConflict: 'user_id' });
      if (roleErr) throw roleErr;
      if (updates.role) {
        const orgMemberRole = workspaceRoleToOrgMemberRole(updates.role);
        await supabaseAdmin
          .from('organization_members')
          .update({ role: orgMemberRole })
          .eq('organization_id', req.organizationId)
          .eq('user_id', userId);
      }
    }

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ====== ADMIN: Manage user roles (gated by accessConfig) ======
app.put('/api/admin/users/:userId/role', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    if (!(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to change user roles' });
    }

    const { role } = req.body;
    if (role !== 'admin' && role !== 'user') {
      return res.status(400).json({ error: 'Role must be admin or user' });
    }
    if (String(req.user.id) === String(req.params.userId) && role === 'user') {
      return res.status(403).json({ error: 'You cannot change your own role to user' });
    }

    const targetGlobal = await getUserRole(req.params.userId);
    if (targetGlobal === 'superadmin') {
      return res.status(403).json({ error: 'Cannot change superadmin role here' });
    }

    const orgMemberRole = workspaceRoleToOrgMemberRole(role);

    const { data, error } = await supabaseAdmin
      .from('user_roles')
      .upsert(
        { user_id: req.params.userId, role },
        { onConflict: 'user_id' }
      )
      .select('user_id, role')
      .single();

    if (error) throw error;

    await supabaseAdmin
      .from('organization_members')
      .update({ role: orgMemberRole })
      .eq('organization_id', req.organizationId)
      .eq('user_id', req.params.userId);

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ====== ADMIN: Activate/deactivate users (gated by accessConfig) ======
app.put('/api/admin/users/:userId/active', authenticate, loadGlobalRole, requireOrgContext, async (req, res) => {
  try {
    if (!(await canManageOrgDirectory(req))) {
      return res.status(403).json({ error: 'You do not have permission to change user status' });
    }

    const { active } = req.body;
    const value = active === false ? false : true;

    const { data: existingRow, error: fetchErr } = await supabaseAdmin
      .from('user_roles')
      .select('user_id, role')
      .eq('user_id', req.params.userId)
      .maybeSingle();
    if (fetchErr) throw fetchErr;

    let data;
    if (!existingRow) {
      const ins = await supabaseAdmin
        .from('user_roles')
        .insert([{ user_id: req.params.userId, role: 'user', is_active: value }])
        .select('user_id, is_active')
        .single();
      if (ins.error) throw ins.error;
      data = ins.data;
    } else {
      const upd = await supabaseAdmin
        .from('user_roles')
        .update({ is_active: value })
        .eq('user_id', req.params.userId)
        .select('user_id, is_active')
        .single();
      if (upd.error) throw upd.error;
      data = upd.data;
    }

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function startServer() {
  try {
    await refreshRoleAccessCache();
  } catch (err) {
    console.error('Failed to load role_access_config (using defaults):', err?.message || err);
  }
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();

