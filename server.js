import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jiraRouter from './jira_api.js';
import superadminRouter from './superadminRoutes.js';
import { canManageUsers, canViewAllUsers } from './accessConfig.js';
import { supabaseAdmin } from './supabaseAdmin.js';
import { authenticate, loadGlobalRole } from './middleware/auth.js';
import { requireOrgContext, requireOrgRole } from './middleware/organization.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

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
    res.json({
      id: req.user.id,
      email: req.user.email,
      role: role,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
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
  req.organizationId = req.params.id;
  next();
}, requireOrgContext, requireOrgRole(['org_admin']), async (req, res) => {
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

    res.json((members || []).map((m) => ({
      user_id: m.user_id,
      email: emailById.get(m.user_id) || 'Unknown',
      org_role: m.role,
      joined_at: m.joined_at,
      global_role: globalById.get(m.user_id)?.role || 'user',
      active: globalById.get(m.user_id)?.is_active !== false,
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Org Admin: update a member's org role (org_admin/team_leader/team_member/client)
app.put('/api/organizations/:id/members/:userId', authenticate, loadGlobalRole, (req, _res, next) => {
  req.organizationId = req.params.id;
  next();
}, requireOrgContext, requireOrgRole(['org_admin']), async (req, res) => {
  try {
    if (!req.isSuperAdmin && String(req.organizationId) !== String(req.params.id)) {
      return res.status(403).json({ error: 'Cannot access other organizations' });
    }
    const { role } = req.body || {};
    const allowed = ['org_admin', 'team_leader', 'team_member', 'client'];
    if (!allowed.includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const { data, error } = await supabaseAdmin
      .from('organization_members')
      .update({ role })
      .eq('organization_id', req.organizationId)
      .eq('user_id', req.params.userId)
      .select('organization_id, user_id, role')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Org Admin: create invitation
app.post('/api/organizations/:id/invitations', authenticate, loadGlobalRole, (req, _res, next) => {
  req.organizationId = req.params.id;
  next();
}, requireOrgContext, requireOrgRole(['org_admin']), async (req, res) => {
  try {
    if (!req.isSuperAdmin && String(req.organizationId) !== String(req.params.id)) {
      return res.status(403).json({ error: 'Cannot access other organizations' });
    }
    const { email, role } = req.body || {};
    const allowed = ['org_admin', 'team_leader', 'team_member', 'client'];
    if (!email || !String(email).includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (role && !allowed.includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const { data, error } = await supabaseAdmin
      .from('organization_invitations')
      .insert([{
        organization_id: req.organizationId,
        email: String(email).toLowerCase(),
        role: role || 'team_member',
        invited_by: req.user.id,
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
      }])
      .select('*')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Org Admin: list invitations (pending/accepted/expired)
app.get('/api/organizations/:id/invitations', authenticate, loadGlobalRole, (req, _res, next) => {
  req.organizationId = req.params.id;
  next();
}, requireOrgContext, requireOrgRole(['org_admin']), async (req, res) => {
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
        return { user_id: p.id, email: p.email || 'Unknown', role: ur?.role || 'user', active: ur?.is_active !== false };
      });
      return res.json(users);
    }

    // Org-scoped list: members of this org only
    const { data: members, error: membersError } = await supabaseAdmin
      .from('organization_members')
      .select('user_id, role')
      .eq('organization_id', req.organizationId);
    if (membersError) throw membersError;

    const userIds = (members || []).map((m) => m.user_id);
    const [{ data: profiles, error: profilesError }, { data: userRoles, error: rolesError }] = await Promise.all([
      supabaseAdmin.from('profiles').select('id, email').in('id', userIds),
      supabaseAdmin.from('user_roles').select('user_id, role, is_active').in('user_id', userIds),
    ]);
    if (profilesError) throw profilesError;
    if (rolesError) throw rolesError;

    const emailById = new Map((profiles || []).map((p) => [p.id, p.email]));
    const globalById = new Map((userRoles || []).map((r) => [r.user_id, r]));
    const orgRoleById = new Map((members || []).map((m) => [m.user_id, m.role]));

    res.json(userIds.map((id) => ({
      user_id: id,
      email: emailById.get(id) || 'Unknown',
      role: globalById.get(id)?.role || 'user',
      org_role: orgRoleById.get(id) || null,
      active: globalById.get(id)?.is_active !== false,
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ====== ADMIN: Manage user roles (gated by accessConfig) ======
app.put('/api/admin/users/:userId/role', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const currentUserRole = await getUserRole(req.user.id);
    if (!canManageUsers(currentUserRole)) {
      return res.status(403).json({ error: 'Only users with canManageUsers can change roles' });
    }

    const { role } = req.body;
    const allowedRoles = ['user', 'team_member', 'team_leader', 'client', 'admin', 'superadmin'];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role value' });
    }

    const { data, error } = await supabaseAdmin
      .from('user_roles')
      .upsert(
        { user_id: req.params.userId, role },
        { onConflict: 'user_id' }
      )
      .select('user_id, role')
      .single();

    if (error) throw error;

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ====== ADMIN: Activate/deactivate users (gated by accessConfig) ======
app.put('/api/admin/users/:userId/active', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const currentUserRole = await getUserRole(req.user.id);
    if (!canManageUsers(currentUserRole)) {
      return res.status(403).json({ error: 'Only users with canManageUsers can change user status' });
    }

    const { active } = req.body;
    const value = active === false ? false : true;

    const { data, error } = await supabaseAdmin
      .from('user_roles')
      .update({ is_active: value })
      .eq('user_id', req.params.userId)
      .select('user_id, is_active')
      .single();

    if (error) throw error;

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

