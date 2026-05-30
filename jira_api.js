import express from 'express';
import { supabaseAdmin } from './supabaseAdmin.js';
import {
  canUserCreateProject,
  shouldAutoAddAsProjectMemberOnCreate,
  canAssignIssuesToOthers,
  canCreateIssues,
  canManageProjectMembers,
  canManageMilestones,
  canViewAllProjects,
} from './accessConfig.js';
import { logActivity, logIssueChanges } from './activityLogger.js';
import {
  DEFAULT_WORKFLOW_STATUS,
  validateWorkflowStatus,
  defaultWorkflowForBoardStatus,
  coerceWorkflowForBoardStatus,
} from './workflowStatus.js';
import { authenticate, loadGlobalRole } from './middleware/auth.js';
import {
  requireOrgContext,
  attachOrgFromProject,
  attachOrgFromIssue,
  requireSameOrganizationForResource,
} from './middleware/organization.js';
import { workspaceRoleFromOrgMember } from './roleWorkspace.js';
import { ensureOrganizationMember } from './orgMembershipHelpers.js';

const router = express.Router();

/** Normalize UUID strings for consistent Map keys (Supabase may vary casing). */
function uuidKeyPart(v) {
  if (v == null || v === '') return '';
  return String(v).trim().toLowerCase();
}

function issueCreatorClientMapKey(projectId, userId) {
  const p = uuidKeyPart(projectId);
  const u = uuidKeyPart(userId);
  if (!p || !u) return '';
  return `${p}:${u}`;
}

function isClientProjectMemberRole(role) {
  return String(role || '').trim().toLowerCase() === 'client';
}

/** Prefer reporter (who filed the task); matches client-created tasks on POST /issues. */
function issueCreatorUserId(issue) {
  if (!issue) return null;
  return issue.reporter_id || issue.created_by || null;
}

function issueProjectIdForCreator(issue) {
  if (!issue) return null;
  return issue.project_id ?? issue.project?.id ?? null;
}

// Helper function to get user role
const getUserRole = async (userId) => {
  const { data, error } = await supabaseAdmin
    .from('user_roles')
    .select('role')
    .eq('user_id', userId)
    .single();
  
  if (error || !data) return 'user';
  return data.role;
};

/** Global role config OR project team_leader / project admin */
async function resolveCanManageProjectMembers(userId, projectId, globalRole) {
  if (canManageProjectMembers(globalRole)) return true;
  if (!projectId) return false;
  const { data: pm } = await supabaseAdmin
    .from('project_members')
    .select('project_role')
    .eq('project_id', projectId)
    .eq('user_id', userId)
    .maybeSingle();
  const pr = pm?.project_role;
  return pr === 'team_leader' || pr === 'admin';
}

function defaultProjectRoleForCreator(globalRole) {
  if (globalRole === 'admin' || globalRole === 'superadmin') return 'admin';
  if (globalRole === 'team_leader') return 'team_leader';
  return 'team_member';
}

async function canManageClientsResource(userId, organizationId, globalRole) {
  if (canManageProjectMembers(globalRole)) return true;
  const { data: om } = await supabaseAdmin
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .maybeSingle();
  if (om?.role === 'admin') return true;
  const { data: projects } = await supabaseAdmin
    .from('projects')
    .select('id')
    .eq('organization_id', organizationId);
  const ids = (projects || []).map((p) => p.id);
  if (ids.length === 0) return false;
  const { data: pms } = await supabaseAdmin
    .from('project_members')
    .select('project_role')
    .eq('user_id', userId)
    .in('project_id', ids);
  return (pms || []).some((pm) => pm.project_role === 'team_leader' || pm.project_role === 'admin');
}

/** Project in org + (member OR global canViewAllProjects). */
async function userHasProjectAccess(userId, organizationId, projectId, globalRole) {
  if (!projectId) return false;
  const { data: p } = await supabaseAdmin
    .from('projects')
    .select('id')
    .eq('id', projectId)
    .eq('organization_id', organizationId)
    .maybeSingle();
  if (!p) return false;
  if (canViewAllProjects(globalRole)) return true;
  const { data: mem } = await supabaseAdmin
    .from('project_members')
    .select('project_id')
    .eq('project_id', projectId)
    .eq('user_id', userId)
    .maybeSingle();
  return Boolean(mem);
}

// Helper to create a notification for a user
const createAssignmentNotification = async ({ organizationId, userId, issue, actorEmail }) => {
  if (!userId || !issue) return;
  try {
    const messageParts = [];
    if (actorEmail) {
      messageParts.push(`${actorEmail} assigned you to`);
    } else {
      messageParts.push('You have been assigned to');
    }
    const summary = issue.summary || 'a task';
    const keyPart = issue.issue_key ? ` (${issue.issue_key})` : '';
    messageParts.push(`${summary}${keyPart}`);
    const message = messageParts.join(' ');

    await supabaseAdmin.from('notifications').insert([
      {
        user_id: userId,
        message,
        related_type: 'issue',
        related_id: issue.id,
        organization_id: organizationId || issue.organization_id || null,
      },
    ]);
  } catch (err) {
    // Log and continue; notifications should not break main flow
    console.error('Failed to create assignment notification', err);
  }
};

// Router-level auth + role
router.use(authenticate, loadGlobalRole);

// ========== PROJECTS ==========
// List projects: members see their projects; roles with canViewAllProjects see every project in the org.
router.get('/projects', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);

    const { data: memberships, error: membershipsError } = await supabaseAdmin
      .from('project_members')
      .select('project_id, project_role')
      .eq('user_id', req.user.id);

    if (membershipsError) throw membershipsError;

    const projectRoleByProjectId = new Map(
      (memberships || []).map((row) => [row.project_id, row.project_role])
    );

    if (canViewAllProjects(userRole)) {
      const { data: allProjects, error } = await supabaseAdmin
        .from('projects')
        .select('*')
        .eq('organization_id', req.organizationId)
        .order('created_at', { ascending: false });
      if (error) throw error;
      const projectsWithRole = (allProjects || []).map((p) => ({
        ...p,
        current_user_project_role: projectRoleByProjectId.get(p.id) || null,
      }));
      return res.json(projectsWithRole);
    }

    const projectIds = Array.from(
      new Set(
        (memberships || [])
          .map((row) => row.project_id)
          .filter((id) => id != null)
      )
    );

    if (projectIds.length === 0) {
      return res.json([]);
    }

    const { data, error } = await supabaseAdmin
      .from('projects')
      .select('*')
      .in('id', projectIds)
      .eq('organization_id', req.organizationId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const projectsWithRole = (data || []).map((p) => ({
      ...p,
      current_user_project_role: projectRoleByProjectId.get(p.id) || null,
    }));

    res.json(projectsWithRole);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/projects', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const canCreate = canUserCreateProject(userRole);

    // Only configured roles can create main projects
    if (!canCreate) {
      return res.status(403).json({ error: 'You are not allowed to create projects' });
    }

    const { key, name, description, lead_id, client_id } = req.body;
    const { data: project, error } = await supabaseAdmin
      .from('projects')
      .insert([{
        key: key.toUpperCase(),
        name,
        description,
        lead_id: lead_id || req.user.id,
        client_id: client_id || null,
        created_by: req.user.id,
        organization_id: req.organizationId,
      }])
      .select('*')
      .single();
    if (error) throw error;

    await logActivity(supabaseAdmin, { entity_type: 'PROJECT', entity_id: project.id, action_type: 'CREATE', new_value: project.name, performed_by: req.user.id, organization_id: req.organizationId });

    // Add creator as project member when config says so
    if (shouldAutoAddAsProjectMemberOnCreate(userRole)) {
      try {
        await supabaseAdmin
          .from('project_members')
          .upsert(
            {
              project_id: project.id,
              user_id: req.user.id,
              project_role: defaultProjectRoleForCreator(userRole),
            },
            { onConflict: 'project_id,user_id' }
          );
      } catch (membershipError) {
        console.error('Failed to create project_members row', membershipError);
      }
    }

    res.status(201).json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Current user's project role for this project (e.g. for client column visibility on board).
router.get('/projects/:id/my-role', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const { data: member, error } = await supabaseAdmin
      .from('project_members')
      .select('project_role')
      .eq('project_id', req.params.id)
      .eq('user_id', req.user.id)
      .maybeSingle();
    if (error) throw error;
    if (!member) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }
    res.json({ project_role: member.project_role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/projects/:id', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const { data: member, error: memberError } = await supabaseAdmin
      .from('project_members')
      .select('project_id')
      .eq('project_id', req.params.id)
      .eq('user_id', req.user.id)
      .maybeSingle();
    if (memberError) throw memberError;
    if (!member && !canViewAllProjects(userRole)) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }
    const { data, error } = await supabaseAdmin
      .from('projects')
      .select('*')
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/projects/:id', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!(await resolveCanManageProjectMembers(req.user.id, req.params.id, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to update this project' });
    }

    const updates = {};
    if (req.body.name !== undefined) updates.name = req.body.name;
    if (req.body.description !== undefined) updates.description = req.body.description;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    const { data: existing } = await supabaseAdmin.from('projects').select('name, description, organization_id').eq('id', req.params.id).eq('organization_id', req.organizationId).single();
    if (existing) {
      if (updates.name !== undefined && String(existing.name) !== String(updates.name)) {
        await logActivity(supabaseAdmin, { entity_type: 'PROJECT', entity_id: req.params.id, action_type: 'UPDATE', field_name: 'name', old_value: existing.name, new_value: updates.name, performed_by: req.user.id, organization_id: req.organizationId });
      }
      if (updates.description !== undefined && String(existing.description || '') !== String(updates.description ?? '')) {
        await logActivity(supabaseAdmin, { entity_type: 'PROJECT', entity_id: req.params.id, action_type: 'UPDATE', field_name: 'description', old_value: existing.description, new_value: updates.description, performed_by: req.user.id, organization_id: req.organizationId });
      }
    }

    const { data, error } = await supabaseAdmin
      .from('projects')
      .update(updates)
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .select('*')
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete project (Org Admin / Team Leader). Best-effort cleanup of related rows.
router.delete('/projects/:id', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!(await resolveCanManageProjectMembers(req.user.id, req.params.id, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to delete projects' });
    }
    const projectId = req.params.id;

    // Load issue ids for cleanup
    const { data: issues, error: issuesError } = await supabaseAdmin
      .from('issues')
      .select('id')
      .eq('project_id', projectId)
      .eq('organization_id', req.organizationId);
    if (issuesError) throw issuesError;

    const issueIds = (issues || []).map((i) => i.id);

    // Cleanup notifications/comments/activity logs tied to issues
    if (issueIds.length > 0) {
      await supabaseAdmin
        .from('notifications')
        .delete()
        .eq('organization_id', req.organizationId)
        .eq('related_type', 'issue')
        .in('related_id', issueIds);

      await supabaseAdmin
        .from('issue_comments')
        .delete()
        .in('issue_id', issueIds);

      await supabaseAdmin
        .from('activity_logs')
        .delete()
        .eq('organization_id', req.organizationId)
        .eq('entity_type', 'TASK')
        .in('entity_id', issueIds);
    }

    // Delete issues
    await supabaseAdmin
      .from('issues')
      .delete()
      .eq('project_id', projectId)
      .eq('organization_id', req.organizationId);

    // Delete milestones/releases/sprints tied to this project (if present in schema)
    await supabaseAdmin
      .from('milestones')
      .delete()
      .eq('project_id', projectId)
      .eq('organization_id', req.organizationId);

    await supabaseAdmin
      .from('releases')
      .delete()
      .eq('project_id', projectId);

    await supabaseAdmin
      .from('sprints')
      .delete()
      .eq('project_id', projectId);

    // Delete project members
    await supabaseAdmin
      .from('project_members')
      .delete()
      .eq('project_id', projectId);

    // Delete project activity logs
    await supabaseAdmin
      .from('activity_logs')
      .delete()
      .eq('organization_id', req.organizationId)
      .eq('entity_type', 'PROJECT')
      .eq('entity_id', projectId);

    // Finally delete project
    const { error: deleteProjectError } = await supabaseAdmin
      .from('projects')
      .delete()
      .eq('id', projectId)
      .eq('organization_id', req.organizationId);

    if (deleteProjectError) throw deleteProjectError;

    res.json({ success: true });
  } catch (error) {
    // Common: FK constraint blocks deletion. Return a friendly message.
    const msg = error?.message || 'Failed to delete project';
    if (msg.toLowerCase().includes('foreign key') || msg.toLowerCase().includes('violates')) {
      return res.status(409).json({
        error: 'Cannot delete project due to related records. Remove related items first or enable cascading deletes in DB.',
        detail: msg,
      });
    }
    res.status(500).json({ error: msg });
  }
});

// Project members: list (project member, or global permission to manage members)
router.get('/projects/:id/members', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const { data: callerMember } = await supabaseAdmin
      .from('project_members')
      .select('project_id')
      .eq('project_id', req.params.id)
      .eq('user_id', req.user.id)
      .maybeSingle();
    if (
      !callerMember &&
      !(await resolveCanManageProjectMembers(req.user.id, req.params.id, userRole))
    ) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }

    const { data: memberships, error: membershipsError } = await supabaseAdmin
      .from('project_members')
      .select('project_id, user_id, project_role')
      .eq('project_id', req.params.id);

    if (membershipsError) throw membershipsError;

    if (!memberships || memberships.length === 0) {
      return res.json([]);
    }

    const userIds = memberships.map((m) => m.user_id);

    const [{ data: profiles, error: profilesError }, { data: roles, error: rolesError }, { data: orgMembers, error: orgMemErr }] =
      await Promise.all([
        supabaseAdmin
          .from('profiles')
          .select('id, email, first_name, last_name')
          .in('id', userIds),
        supabaseAdmin
          .from('user_roles')
          .select('user_id, role')
          .in('user_id', userIds),
        supabaseAdmin
          .from('organization_members')
          .select('user_id, role')
          .eq('organization_id', req.organizationId)
          .in('user_id', userIds),
      ]);

    if (profilesError) throw profilesError;
    if (rolesError) throw rolesError;
    if (orgMemErr) throw orgMemErr;

    const profileById = new Map((profiles || []).map((p) => [p.id, p]));
    const globalRoleById = new Map((roles || []).map((r) => [r.user_id, r.role]));
    const orgRoleById = new Map((orgMembers || []).map((r) => [r.user_id, r.role]));

    const displayNameForMember = (profile, emailFallback) => {
      const fn = String(profile?.first_name || '').trim();
      const ln = String(profile?.last_name || '').trim();
      const full = `${fn} ${ln}`.trim();
      if (full) return full;
      const email = String(emailFallback || '').trim();
      if (email.includes('@')) return email.split('@')[0];
      return email || 'Unknown';
    };

    const result = memberships.map((m) => {
      const gr = globalRoleById.get(m.user_id) || 'user';
      const om = orgRoleById.get(m.user_id) ?? null;
      const profile = profileById.get(m.user_id);
      const email = profile?.email || 'Unknown';
      return {
        project_id: m.project_id,
        user_id: m.user_id,
        project_role: m.project_role,
        email,
        first_name: profile?.first_name ?? null,
        last_name: profile?.last_name ?? null,
        display_name: displayNameForMember(profile, email),
        workspace_role: workspaceRoleFromOrgMember(om, gr),
      };
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Project members: add or update
router.post('/projects/:id/members', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!(await resolveCanManageProjectMembers(req.user.id, req.params.id, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to manage project members' });
    }

    const { user_id, project_role } = req.body;
    const allowedProjectRoles = ['admin', 'team_leader', 'team_member', 'client'];

    if (!user_id || !allowedProjectRoles.includes(project_role)) {
      return res.status(400).json({ error: 'Invalid user or project_role' });
    }

    await ensureOrganizationMember({
      organizationId: req.organizationId,
      userId: user_id,
      orgMemberRole: 'team_member',
    });

    const { data, error } = await supabaseAdmin
      .from('project_members')
      .upsert(
        {
          project_id: req.params.id,
          user_id,
          project_role,
        },
        { onConflict: 'project_id,user_id' }
      )
      .select('*')
      .single();

    if (error) throw error;

    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Project members: remove
router.delete('/projects/:id/members/:userId', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!(await resolveCanManageProjectMembers(req.user.id, req.params.id, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to manage project members' });
    }

    const { error } = await supabaseAdmin
      .from('project_members')
      .delete()
      .eq('project_id', req.params.id)
      .eq('user_id', req.params.userId);

    if (error) throw error;

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== MILESTONES ==========
// List milestones: project member or global canViewAllProjects
router.get('/projects/:id/milestones', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const ok = await userHasProjectAccess(req.user.id, req.organizationId, req.params.id, userRole);
    if (!ok) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }

    // Match UI: clients (global or project role) may not list milestones unless canManageMilestones
    if (!canManageMilestones(userRole)) {
      const { data: pm } = await supabaseAdmin
        .from('project_members')
        .select('project_role')
        .eq('project_id', req.params.id)
        .eq('user_id', req.user.id)
        .maybeSingle();
      const projectRole = pm?.project_role ?? null;
      const isClientGlobal = userRole === 'client' || userRole === 'representative';
      const isProjectClient = projectRole === 'client';
      if (isClientGlobal || isProjectClient) {
        return res.status(403).json({ error: 'You do not have permission to view milestones' });
      }
    }

    const { data, error } = await supabaseAdmin
      .from('milestones')
      .select('*')
      .eq('project_id', req.params.id)
      .eq('organization_id', req.organizationId)
      .order('planned_date', { ascending: true, nullsFirst: false })
      .order('version');

    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create milestone (Admin, Team Leader, Superadmin only)
router.post('/projects/:id/milestones', requireOrgContext, attachOrgFromProject, requireSameOrganizationForResource, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canManageMilestones(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to create or edit milestones' });
    }

    const okProject = await userHasProjectAccess(req.user.id, req.organizationId, req.params.id, userRole);
    if (!okProject) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }

    const { version, planned_date, status, description } = req.body;
    if (!version || !version.trim()) {
      return res.status(400).json({ error: 'Version is required' });
    }

    const { data, error } = await supabaseAdmin
      .from('milestones')
      .insert([{
        project_id: req.params.id,
        organization_id: req.organizationId,
        version: version.trim(),
        planned_date: planned_date || null,
        status: status || 'planned',
        description: description || null,
      }])
      .select('*')
      .single();

    if (error) throw error;
    await logActivity(supabaseAdmin, { entity_type: 'MILESTONE', entity_id: data.id, action_type: 'CREATE', new_value: data.version, performed_by: req.user.id, organization_id: req.organizationId });
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update milestone
router.put('/milestones/:milestoneId', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canManageMilestones(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to create or edit milestones' });
    }

    const { data: existing } = await supabaseAdmin
      .from('milestones')
      .select('id, project_id')
      .eq('id', req.params.milestoneId)
      .eq('organization_id', req.organizationId)
      .single();
    if (!existing) {
      return res.status(404).json({ error: 'Milestone not found' });
    }

    const okProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      existing.project_id,
      userRole
    );
    if (!okProject) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }

    const { version, planned_date, status, description } = req.body;
    const updates = {};
    if (version !== undefined) updates.version = version.trim();
    if (planned_date !== undefined) updates.planned_date = planned_date || null;
    if (status !== undefined) updates.status = status;
    if (description !== undefined) updates.description = description || null;
    updates.updated_at = new Date().toISOString();

    const { data: existingMilestone } = await supabaseAdmin.from('milestones').select('version, planned_date, status, description').eq('id', req.params.milestoneId).eq('organization_id', req.organizationId).single();
    if (existingMilestone) {
      if (updates.version !== undefined && String(existingMilestone.version) !== String(updates.version)) {
        await logActivity(supabaseAdmin, { entity_type: 'MILESTONE', entity_id: req.params.milestoneId, action_type: 'UPDATE', field_name: 'version', old_value: existingMilestone.version, new_value: updates.version, performed_by: req.user.id, organization_id: req.organizationId });
      }
      if (updates.status !== undefined && String(existingMilestone.status) !== String(updates.status)) {
        await logActivity(supabaseAdmin, { entity_type: 'MILESTONE', entity_id: req.params.milestoneId, action_type: 'STATUS_CHANGE', field_name: 'status', old_value: existingMilestone.status, new_value: updates.status, performed_by: req.user.id, organization_id: req.organizationId });
      }
      if (updates.planned_date !== undefined && String(existingMilestone.planned_date || '') !== String(updates.planned_date || '')) {
        await logActivity(supabaseAdmin, { entity_type: 'MILESTONE', entity_id: req.params.milestoneId, action_type: 'UPDATE', field_name: 'planned_date', old_value: existingMilestone.planned_date, new_value: updates.planned_date, performed_by: req.user.id, organization_id: req.organizationId });
      }
      if (updates.description !== undefined && String(existingMilestone.description || '') !== String(updates.description ?? '')) {
        await logActivity(supabaseAdmin, { entity_type: 'MILESTONE', entity_id: req.params.milestoneId, action_type: 'UPDATE', field_name: 'description', old_value: existingMilestone.description, new_value: updates.description, performed_by: req.user.id, organization_id: req.organizationId });
      }
    }

    const { data, error } = await supabaseAdmin
      .from('milestones')
      .update(updates)
      .eq('id', req.params.milestoneId)
      .eq('organization_id', req.organizationId)
      .select('*')
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete milestone
router.delete('/milestones/:milestoneId', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canManageMilestones(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to delete milestones' });
    }

    const { data: existing } = await supabaseAdmin
      .from('milestones')
      .select('id, project_id, version')
      .eq('id', req.params.milestoneId)
      .eq('organization_id', req.organizationId)
      .single();
    if (!existing) {
      return res.status(404).json({ error: 'Milestone not found' });
    }

    const okProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      existing.project_id,
      userRole
    );
    if (!okProject) {
      return res.status(404).json({ error: 'Project not found or access denied' });
    }

    await logActivity(supabaseAdmin, { entity_type: 'MILESTONE', entity_id: req.params.milestoneId, action_type: 'DELETE', old_value: existing.version || existing.id, performed_by: req.user.id, organization_id: req.organizationId });

    const { error } = await supabaseAdmin
      .from('milestones')
      .delete()
      .eq('id', req.params.milestoneId);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ISSUE TYPES ==========
router.get('/issue-types', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('issue_types')
      .select('*')
      .order('name');
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ISSUES ==========
router.get('/issues', requireOrgContext, async (req, res) => {
  try {
    const { project_id, sprint_id, release_id, milestone_id, status, assignee_id } = req.query;
    const userRole = await getUserRole(req.user.id);

    if (project_id) {
      const ok = await userHasProjectAccess(req.user.id, req.organizationId, project_id, userRole);
      if (!ok) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
    }

    let query = supabaseAdmin
      .from('issues')
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*),
        sprint:sprints(*),
        milestone:milestones(*)
      `);
    
    query = query.eq('organization_id', req.organizationId);
    
    if (project_id) query = query.eq('project_id', project_id);
    if (sprint_id) query = query.eq('sprint_id', sprint_id);
    if (release_id) query = query.eq('release_id', release_id);
    if (milestone_id) query = query.eq('milestone_id', milestone_id);
    if (status) query = query.eq('status', status);
    if (assignee_id) query = query.eq('assignee_id', assignee_id);
    // Filter by parent_issue_id (null for top-level issues, or specific ID for subtasks)
    if (req.query.parent_issue_id !== undefined) {
      if (req.query.parent_issue_id === null || req.query.parent_issue_id === 'null') {
        query = query.is('parent_issue_id', null);
      } else {
        query = query.eq('parent_issue_id', req.query.parent_issue_id);
      }
    }
    
    const { data: issuesRaw, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    let issues = issuesRaw || [];

    // Project clients: To Do column only shows tasks they created (reporter / created_by).
    if (!req.isSuperAdmin && issues.length > 0) {
      const projectIds = [...new Set(issues.map((i) => i.project_id).filter(Boolean))];
      const { data: memberships } = await supabaseAdmin
        .from('project_members')
        .select('project_id, project_role')
        .eq('user_id', req.user.id)
        .in('project_id', projectIds);
      const clientProjectIds = new Set(
        (memberships || []).filter((m) => isClientProjectMemberRole(m.project_role)).map((m) => m.project_id)
      );
      if (clientProjectIds.size > 0) {
        const viewerId = uuidKeyPart(req.user.id);
        issues = issues.filter((i) => {
          if (i.status !== 'to_do' || !clientProjectIds.has(i.project_id)) return true;
          const creator = issueCreatorUserId(i);
          return uuidKeyPart(creator) === viewerId;
        });
      }
    }
    
    // Get user emails from profiles
    const userIds = new Set();
    issues.forEach((issue) => {
      if (issue.assignee_id) userIds.add(issue.assignee_id);
      if (issue.reporter_id) userIds.add(issue.reporter_id);
      if (issue.created_by) userIds.add(issue.created_by);
      const cr = issueCreatorUserId(issue);
      if (cr) userIds.add(cr);
    });
    
    const userIdsArray = Array.from(userIds);
    let profiles = {};
    if (userIdsArray.length > 0) {
      const { data: profilesData, error: profilesError } = await supabaseAdmin
        .from('profiles')
        .select('id, email')
        .in('id', userIdsArray);
      
      if (!profilesError && profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }

    // Client-created highlight: any issue whose reporter is a project member with role `client`
    // on that project. One query per distinct project (no fragile double-.in() on user ids).
    const uniqueProjectIdsForClients = [
      ...new Set((issues || []).map((i) => issueProjectIdForCreator(i)).filter(Boolean)),
    ];
    const clientReporterKeys = new Set();
    if (uniqueProjectIdsForClients.length > 0) {
      const { data: pmRows, error: pmLookupErr } = await supabaseAdmin
        .from('project_members')
        .select('project_id, user_id, project_role')
        .in('project_id', uniqueProjectIdsForClients);
      if (pmLookupErr) {
        console.error('[GET /issues] project_members lookup for created_by_client failed', pmLookupErr);
      }
      (pmRows || []).forEach((row) => {
        if (!isClientProjectMemberRole(row.project_role)) return;
        const k = issueCreatorClientMapKey(row.project_id, row.user_id);
        if (k) clientReporterKeys.add(k);
      });
    }

    // Attach user info to issues
    const issuesWithUsers = issues.map((issue) => {
      const creatorId = issueCreatorUserId(issue);
      const pid = issueProjectIdForCreator(issue);
      const key = creatorId && pid ? issueCreatorClientMapKey(pid, creatorId) : '';
      const created_by_client = Boolean(key && clientReporterKeys.has(key));
      return {
        ...issue,
        assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
        reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null,
        created_by_client,
      };
    });
    
    res.json(issuesWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/issues/:id', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const { data: issue, error } = await supabaseAdmin
      .from('issues')
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*),
        sprint:sprints(*),
        milestone:milestones(*)
      `)
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .single();
    if (error) throw error;

    const canSeeProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      issue.project_id,
      userRole
    );
    if (!canSeeProject) {
      return res.status(404).json({ error: 'Issue not found' });
    }

    // Project clients cannot open other users' To Do tasks (only their own).
    if (!req.isSuperAdmin) {
      const { data: pm } = await supabaseAdmin
        .from('project_members')
        .select('project_role')
        .eq('project_id', issue.project_id)
        .eq('user_id', req.user.id)
        .maybeSingle();
      if (isClientProjectMemberRole(pm?.project_role)) {
        const creator = issueCreatorUserId(issue);
        if (issue.status === 'to_do' && creator !== req.user.id) {
          return res.status(404).json({ error: 'Issue not found' });
        }
      }
    }

    // Load parent issue and subtasks with separate queries (avoid issues->issues schema cache error)
    let parent_issue = null;
    let subtasks = [];
    if (issue.parent_issue_id) {
      const { data: parent } = await supabaseAdmin
        .from('issues')
        .select('id, issue_key, summary')
        .eq('id', issue.parent_issue_id)
        .eq('organization_id', req.organizationId)
        .single();
      parent_issue = parent;
    }
    const { data: subtasksData } = await supabaseAdmin
      .from('issues')
      .select('id, issue_key, summary, status, internal_priority, client_priority')
      .eq('parent_issue_id', req.params.id)
      .eq('organization_id', req.organizationId);
    if (subtasksData) subtasks = subtasksData;

    // Get user emails from profiles
    const userIds = [];
    if (issue.assignee_id) userIds.push(issue.assignee_id);
    if (issue.reporter_id) userIds.push(issue.reporter_id);
    
    let profiles = {};
    if (userIds.length > 0) {
      const { data: profilesData, error: profilesError } = await supabaseAdmin
        .from('profiles')
        .select('id, email')
        .in('id', userIds);
      
      if (!profilesError && profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }

    const creatorId = issueCreatorUserId(issue);
    const pid = issueProjectIdForCreator(issue);
    let created_by_client = false;
    if (creatorId && pid) {
      const { data: creatorPm } = await supabaseAdmin
        .from('project_members')
        .select('project_role')
        .eq('project_id', pid)
        .eq('user_id', creatorId)
        .maybeSingle();
      created_by_client = isClientProjectMemberRole(creatorPm?.project_role);
    }
    
    // Attach user info, parent, and subtasks
    const issueWithUsers = {
      ...issue,
      parent_issue,
      subtasks,
      assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
      reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null,
      created_by_client,
    };
    
    res.json(issueWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Activity logs for an issue (audit trail). Permission: Admin/Team Leader full; Team Member only for tasks they're part of; Client only status-related.
router.get('/issues/:id/activity-logs', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const issueId = req.params.id;

    const { data: issue, error: issueError } = await supabaseAdmin
      .from('issues')
      .select('id, project_id, assignee_id, reporter_id')
      .eq('id', issueId)
      .eq('organization_id', req.organizationId)
      .single();
    if (issueError || !issue) {
      return res.status(404).json({ error: 'Issue not found' });
    }

    const canSeeProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      issue.project_id,
      userRole
    );
    if (!canSeeProject) {
      return res.status(403).json({ error: 'Access denied to this issue' });
    }

    if (userRole === 'team_member') {
      const isPartOfTask = issue.assignee_id === req.user.id || issue.reporter_id === req.user.id;
      if (!isPartOfTask) {
        return res.status(403).json({ error: 'You can only view activity for tasks you are assigned to or created' });
      }
    }

    // Back-compat: older rows may have organization_id = null.
    let query = supabaseAdmin
      .from('activity_logs')
      .select('*')
      .eq('entity_type', 'TASK')
      .eq('entity_id', issueId)
      .or(`organization_id.eq.${req.organizationId},organization_id.is.null`)
      .order('performed_at', { ascending: false });

    const { data: logs, error: logsError } = await query;
    if (logsError) throw logsError;

    let filtered = logs || [];
    if (userRole === 'client') {
      filtered = filtered.filter((log) => log.action_type === 'STATUS_CHANGE' || log.field_name === 'status');
    }

    const performerIds = [...new Set(filtered.map((l) => l.performed_by).filter(Boolean))];
    let profiles = {};
    if (performerIds.length > 0) {
      const { data: profilesData } = await supabaseAdmin.from('profiles').select('id, email').in('id', performerIds);
      if (profilesData) {
        profilesData.forEach((p) => { profiles[p.id] = p; });
      }
    }

    const result = filtered.map((log) => ({
      ...log,
      performed_by_email: log.performed_by ? (profiles[log.performed_by]?.email || 'Unknown') : null,
    }));

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/issues', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canCreateIssues(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to create issues' });
    }
    const {
      project_id,
      issue_type_id,
      summary,
      description,
      status,
      internal_priority,
      client_priority,
      priority, // backward compatibility
      assignee_id,
      sprint_id,
      release_id,
      milestone_id,
      parent_issue_id,
      story_points,
      labels,
      components,
      due_date,
      estimated_days,
      actual_days,
      exposed_to_client,
      workflow_status,
    } = req.body;

    if (!project_id) {
      return res.status(400).json({ error: 'project_id is required' });
    }
    const canUseProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      project_id,
      userRole
    );
    if (!canUseProject) {
      return res.status(403).json({ error: 'Project not found or access denied' });
    }
    
    // Permission: only roles with canAssignIssuesToOthers can assign to others
    if (assignee_id && assignee_id !== req.user.id && !canAssignIssuesToOthers(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to assign issues to others' });
    }
    
    // Use priority for backward compatibility, but prefer internal_priority
    // Convert old priority values to P1-P5 if needed
    let finalInternalPriority = internal_priority || priority || 'P3';
    const priorityMap = {
      'highest': 'P1', 'high': 'P2', 'medium': 'P3', 'low': 'P4', 'lowest': 'P5'
    };
    if (priorityMap[finalInternalPriority]) {
      finalInternalPriority = priorityMap[finalInternalPriority];
    }

    const boardStatus = status || 'to_do';
    let finalWorkflowStatus = defaultWorkflowForBoardStatus(boardStatus);
    if (workflow_status !== undefined && workflow_status !== null && workflow_status !== '') {
      const wv = validateWorkflowStatus(workflow_status, boardStatus);
      if (!wv.ok) return res.status(400).json({ error: wv.error });
      finalWorkflowStatus = wv.value;
    }

    const { data: issue, error } = await supabaseAdmin
      .from('issues')
      .insert([{
        organization_id: req.organizationId,
        project_id,
        issue_type_id,
        summary,
        description,
        status: boardStatus,
        internal_priority: finalInternalPriority,
        client_priority: client_priority || null,
        assignee_id,
        reporter_id: req.user.id,
        sprint_id,
        release_id: release_id || null,
        milestone_id: milestone_id || null,
        parent_issue_id: parent_issue_id || null,
        story_points,
        labels: labels || [],
        components: components || [],
        due_date,
        estimated_days: estimated_days != null ? parseInt(estimated_days, 10) : null,
        actual_days: actual_days != null ? parseInt(actual_days, 10) : null,
        exposed_to_client: exposed_to_client === true || exposed_to_client === 'true',
        workflow_status: finalWorkflowStatus,
      }])
      .select('*')
      .single();
    
    if (error) throw error;

    await logActivity(supabaseAdmin, {
      entity_type: 'TASK',
      entity_id: issue.id,
      action_type: 'CREATE',
      new_value: issue.issue_key || issue.summary,
      performed_by: req.user.id,
      organization_id: req.organizationId,
    });

    // Fetch project and issue_type with separate queries (avoids any schema cache issues)
    let project = null;
    let issue_type = null;
    const [{ data: projectData }, { data: issueTypeData }] = await Promise.all([
      supabaseAdmin.from('projects').select('*').eq('id', issue.project_id).eq('organization_id', req.organizationId).single(),
      supabaseAdmin.from('issue_types').select('*').eq('id', issue.issue_type_id).single()
    ]);
    if (projectData) project = projectData;
    if (issueTypeData) issue_type = issueTypeData;
    const issueWithJoins = { ...issue, project, issue_type };

    const { data: creatorPmRow } = await supabaseAdmin
      .from('project_members')
      .select('project_role')
      .eq('project_id', issue.project_id)
      .eq('user_id', req.user.id)
      .maybeSingle();
    const created_by_client = isClientProjectMemberRole(creatorPmRow?.project_role);
    
    // Get user emails from profiles
    const userIds = [];
    if (issueWithJoins.assignee_id) userIds.push(issueWithJoins.assignee_id);
    if (issueWithJoins.reporter_id) userIds.push(issueWithJoins.reporter_id);
    
    let profiles = {};
    if (userIds.length > 0) {
      const { data: profilesData } = await supabaseAdmin
        .from('profiles')
        .select('id, email')
        .in('id', userIds);
      
      if (profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    // Get reporter email
    const { data: reporterProfile } = await supabaseAdmin
      .from('profiles')
      .select('id, email')
      .eq('id', req.user.id)
      .single();
    
    const issueWithUsers = {
      ...issueWithJoins,
      assignee: issueWithJoins.assignee_id ? profiles[issueWithJoins.assignee_id] || { id: issueWithJoins.assignee_id, email: 'Unknown' } : null,
      reporter: reporterProfile || { id: req.user.id, email: req.user.email || 'Unknown' },
      created_by_client,
    };

    // Create notification for assignee if different from reporter
    if (issueWithUsers.assignee_id && issueWithUsers.assignee_id !== req.user.id) {
      await createAssignmentNotification({
        organizationId: req.organizationId,
        userId: issueWithUsers.assignee_id,
        issue: issueWithUsers,
        actorEmail: reporterProfile?.email || req.user.email || null,
      });
    }

    res.status(201).json(issueWithUsers);
  } catch (error) {
    const msg = error?.message || '';
    if (msg.includes('schema cache') || msg.includes("Could not find the")) {
      return res.status(500).json({
        error: msg,
        fix: 'Run database/ensure_issues_columns.sql in your Supabase SQL Editor, then reload schema cache or restart the backend.'
      });
    }
    res.status(500).json({ error: error.message });
  }
});

router.put('/issues/:id', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    // Get current issue to check permissions
    const { data: currentIssue, error: fetchError } = await supabaseAdmin
      .from('issues')
      .select('*')
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .single();
    
    if (fetchError) throw fetchError;

    const canAccessIssueProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      currentIssue.project_id,
      userRole
    );
    if (!canAccessIssueProject) {
      return res.status(404).json({ error: 'Issue not found' });
    }

    const nextBoardStatus =
      req.body.status !== undefined ? req.body.status : currentIssue.status;
    if (req.body.workflow_status !== undefined) {
      const wv = validateWorkflowStatus(req.body.workflow_status, nextBoardStatus);
      if (!wv.ok) return res.status(400).json({ error: wv.error });
      req.body.workflow_status = wv.value;
    } else if (
      req.body.status !== undefined &&
      req.body.status !== currentIssue.status
    ) {
      req.body.workflow_status = coerceWorkflowForBoardStatus(
        currentIssue.workflow_status,
        nextBoardStatus
      );
    }

    // Permission checks
    // Clients can only update client_priority and description
    if (userRole === 'client') {
      const allowedFields = ['client_priority', 'description'];
      const updateData = {};
      allowedFields.forEach(field => {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      });
      await logIssueChanges(supabaseAdmin, req.params.id, currentIssue, updateData, req.user.id);

      const { data: issue, error } = await supabaseAdmin
        .from('issues')
        .update(updateData)
        .eq('id', req.params.id)
        .eq('organization_id', req.organizationId)
        .select(`
          *,
          project:projects(*),
          issue_type:issue_types(*)
        `)
        .single();
      
      if (error) throw error;
      
      // Get user emails
      const userIds = [];
      if (issue.assignee_id) userIds.push(issue.assignee_id);
      if (issue.reporter_id) userIds.push(issue.reporter_id);
      
      let profiles = {};
      if (userIds.length > 0) {
        const { data: profilesData } = await supabaseAdmin
          .from('profiles')
          .select('id, email')
          .in('id', userIds);
        
        if (profilesData) {
          profilesData.forEach(profile => {
            profiles[profile.id] = profile;
          });
        }
      }
      
      const issueWithUsers = {
        ...issue,
        assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
        reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
      };
      
      return res.json(issueWithUsers);
    }
    
    const normalizeAssigneeId = (id) =>
      id === undefined || id === null || id === '' ? null : String(id);

    const isAssignee = normalizeAssigneeId(currentIssue.assignee_id) === String(req.user.id);
    const isReporter = normalizeAssigneeId(currentIssue.reporter_id) === String(req.user.id);
    const canAssignOthers = canAssignIssuesToOthers(userRole);

    // Assignees/reporters without assign-to-others may update their tasks (status, details) but not reassign.
    if (!canAssignOthers && (isAssignee || isReporter)) {
      const allowedFields = [
        'status',
        'internal_priority',
        'workflow_status',
        'summary',
        'description',
        'story_points',
        'labels',
        'due_date',
        'estimated_days',
        'actual_days',
        'exposed_to_client',
        'milestone_id',
        'client_priority',
      ];
      const updateData = {};
      allowedFields.forEach((field) => {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      });

      await logIssueChanges(supabaseAdmin, req.params.id, currentIssue, updateData, req.user.id);

      const { data: issue, error } = await supabaseAdmin
        .from('issues')
        .update(updateData)
        .eq('id', req.params.id)
        .eq('organization_id', req.organizationId)
        .select(`
          *,
          project:projects(*),
          issue_type:issue_types(*)
        `)
        .single();

      if (error) throw error;

      const userIds = [];
      if (issue.assignee_id) userIds.push(issue.assignee_id);
      if (issue.reporter_id) userIds.push(issue.reporter_id);

      let profiles = {};
      if (userIds.length > 0) {
        const { data: profilesData } = await supabaseAdmin
          .from('profiles')
          .select('id, email')
          .in('id', userIds);

        if (profilesData) {
          profilesData.forEach((profile) => {
            profiles[profile.id] = profile;
          });
        }
      }

      const issueWithUsers = {
        ...issue,
        assignee: issue.assignee_id
          ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' }
          : null,
        reporter: issue.reporter_id
          ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' }
          : null,
      };

      return res.json(issueWithUsers);
    }

    // Assigning to someone other than yourself requires canAssignIssuesToOthers (only when assignee changes).
    if (req.body.assignee_id !== undefined) {
      const next = normalizeAssigneeId(req.body.assignee_id);
      const current = normalizeAssigneeId(currentIssue.assignee_id);
      if (next === current) {
        delete req.body.assignee_id;
      } else if (next && next !== String(req.user.id) && !canAssignOthers) {
        return res.status(403).json({ error: 'You do not have permission to assign issues to other users' });
      }
    }
    
    // Team leaders / admins / superadmins can update everything (no parent_issue join to avoid schema-cache errors)
    const priorityToLegacy = { P1: 'highest', P2: 'high', P3: 'medium', P4: 'low', P5: 'lowest' };
    const buildSafeUpdateBody = () => {
      const safe = {};
      const safeNextStatus =
        req.body.status !== undefined ? req.body.status : currentIssue.status;
      if (req.body.summary !== undefined) safe.summary = req.body.summary;
      if (req.body.description !== undefined) safe.description = req.body.description;
      if (req.body.status !== undefined) safe.status = req.body.status;
      if (req.body.workflow_status !== undefined) {
        const wv = validateWorkflowStatus(req.body.workflow_status, safeNextStatus);
        if (wv.ok) safe.workflow_status = wv.value;
      }
      if (req.body.story_points !== undefined) safe.story_points = req.body.story_points;
      if (req.body.labels !== undefined) safe.labels = req.body.labels;
      if (req.body.due_date !== undefined) safe.due_date = req.body.due_date;
      if (req.body.estimated_days !== undefined) safe.estimated_days = req.body.estimated_days == null ? null : parseInt(req.body.estimated_days, 10);
      if (req.body.actual_days !== undefined) safe.actual_days = req.body.actual_days == null ? null : parseInt(req.body.actual_days, 10);
      if (req.body.exposed_to_client !== undefined) safe.exposed_to_client = req.body.exposed_to_client === true || req.body.exposed_to_client === 'true';
      if (req.body.milestone_id !== undefined) safe.milestone_id = req.body.milestone_id || null;
      const pri = req.body.internal_priority || req.body.priority;
      if (pri !== undefined) safe.priority = priorityToLegacy[pri] || pri;
      return safe;
    };

    const updatesForLog = {};
    if (req.body.status !== undefined) updatesForLog.status = req.body.status;
    const pri = req.body.internal_priority || req.body.priority;
    if (pri !== undefined) updatesForLog.internal_priority = pri;
    if (req.body.client_priority !== undefined) updatesForLog.client_priority = req.body.client_priority;
    if (req.body.assignee_id !== undefined) updatesForLog.assignee_id = req.body.assignee_id;
    if (req.body.due_date !== undefined) updatesForLog.due_date = req.body.due_date;
    if (req.body.milestone_id !== undefined) updatesForLog.milestone_id = req.body.milestone_id || null;
    if (req.body.summary !== undefined) updatesForLog.summary = req.body.summary;
    if (req.body.description !== undefined) updatesForLog.description = req.body.description;
    if (req.body.workflow_status !== undefined) {
      updatesForLog.workflow_status = req.body.workflow_status;
    }
    await logIssueChanges(supabaseAdmin, req.params.id, currentIssue, updatesForLog, req.user.id);

    let result = await supabaseAdmin
      .from('issues')
      .update(req.body)
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*)
      `)
      .single();

    if (result.error && (result.error.message.includes('schema cache') || result.error.message.includes('client_priority') || result.error.message.includes('internal_priority') || result.error.message.includes('estimated_days') || result.error.message.includes('actual_days') || result.error.message.includes('exposed_to_client'))) {
      const safeBody = buildSafeUpdateBody();
      result = await supabaseAdmin
        .from('issues')
        .update(safeBody)
        .eq('id', req.params.id)
        .eq('organization_id', req.organizationId)
        .select(`
          *,
          project:projects(*),
          issue_type:issue_types(*)
        `)
        .single();
    }

    const { data: issue, error } = result;
    if (error) throw error;

    // Get user emails from profiles
    const userIds = [];
    if (issue.assignee_id) userIds.push(issue.assignee_id);
    if (issue.reporter_id) userIds.push(issue.reporter_id);
    
    let profiles = {};
    if (userIds.length > 0) {
      const { data: profilesData } = await supabaseAdmin
        .from('profiles')
        .select('id, email')
        .in('id', userIds);
      
      if (profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    const issueWithUsers = {
      ...issue,
      assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
      reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
    };

    // If the assignee changed, create a notification for the new assignee
    if (
      updatesForLog.assignee_id &&
      updatesForLog.assignee_id !== currentIssue.assignee_id
    ) {
      // Fetch actor email
      let actorEmail = req.user.email || null;
      if (!actorEmail) {
        const { data: actorProfile } = await supabaseAdmin
          .from('profiles')
          .select('email')
          .eq('id', req.user.id)
          .maybeSingle();
        actorEmail = actorProfile?.email || null;
      }
      await createAssignmentNotification({
        organizationId: req.organizationId,
        userId: updatesForLog.assignee_id,
        issue: issueWithUsers,
        actorEmail,
      });
    }

    res.json(issueWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/issues/:id', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    const { data: existing, error: fetchErr } = await supabaseAdmin
      .from('issues')
      .select('id, issue_key, summary, project_id')
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .single();
    if (fetchErr || !existing) {
      return res.status(404).json({ error: 'Issue not found' });
    }
    const okProject = await userHasProjectAccess(
      req.user.id,
      req.organizationId,
      existing.project_id,
      userRole
    );
    if (!okProject) {
      return res.status(404).json({ error: 'Issue not found' });
    }
    if (!(await resolveCanManageProjectMembers(req.user.id, existing.project_id, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to delete issues' });
    }
    await logActivity(supabaseAdmin, {
      entity_type: 'TASK',
      entity_id: req.params.id,
      action_type: 'DELETE',
      old_value: existing.issue_key || existing.summary,
      performed_by: req.user.id,
      organization_id: req.organizationId,
    });
    const { error } = await supabaseAdmin
      .from('issues')
      .delete()
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Issue deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== SPRINTS ==========
router.get('/sprints', requireOrgContext, async (req, res) => {
  try {
    const { project_id, state } = req.query;
    if (project_id) {
      const userRole = await getUserRole(req.user.id);
      const ok = await userHasProjectAccess(req.user.id, req.organizationId, project_id, userRole);
      if (!ok) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
    }
    let query = supabaseAdmin
      .from('sprints')
      .select('*, project:projects(*)');
    
    if (project_id) query = query.eq('project_id', project_id);
    if (state) query = query.eq('state', state);
    
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/sprints', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canManageMilestones(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to create sprints' });
    }
    const { project_id, name, goal, start_date, end_date, state } = req.body;
    if (project_id) {
      const { data: p } = await supabaseAdmin.from('projects').select('id, organization_id').eq('id', project_id).maybeSingle();
      if (!p || String(p.organization_id) !== String(req.organizationId)) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
      const okProj = await userHasProjectAccess(req.user.id, req.organizationId, project_id, userRole);
      if (!okProj) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
    }
    const { data, error } = await supabaseAdmin
      .from('sprints')
      .insert([{
        project_id,
        name,
        goal,
        start_date,
        end_date,
        state: state || 'future'
      }])
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== COMMENTS ==========
router.get('/issues/:issue_id/comments', requireOrgContext, attachOrgFromIssue, requireSameOrganizationForResource, async (req, res) => {
  try {
    const { data: comments, error } = await supabaseAdmin
      .from('issue_comments')
      .select('*')
      .eq('issue_id', req.params.issue_id)
      .order('created_at', { ascending: true });
    if (error) throw error;
    
    // Get author emails from profiles
    const authorIds = comments.map(c => c.author_id);
    let profiles = {};
    if (authorIds.length > 0) {
      const { data: profilesData } = await supabaseAdmin
        .from('profiles')
        .select('id, email')
        .in('id', authorIds);
      
      if (profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    const commentsWithAuthors = comments.map(comment => ({
      ...comment,
      author: profiles[comment.author_id] || { id: comment.author_id, email: 'Unknown' }
    }));
    
    res.json(commentsWithAuthors);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/issues/:issue_id/comments', requireOrgContext, attachOrgFromIssue, requireSameOrganizationForResource, async (req, res) => {
  try {
    const { body } = req.body;
    const { data: comment, error } = await supabaseAdmin
      .from('issue_comments')
      .insert([{
        issue_id: req.params.issue_id,
        author_id: req.user.id,
        body
      }])
      .select('*')
      .single();
    if (error) throw error;

    await logActivity(supabaseAdmin, { entity_type: 'TASK', entity_id: req.params.issue_id, action_type: 'COMMENT_ADDED', new_value: (body || '').slice(0, 200), performed_by: req.user.id, organization_id: req.organizationId });
    
    // Get author email from profiles
    const { data: authorProfile } = await supabaseAdmin
      .from('profiles')
      .select('id, email')
      .eq('id', req.user.id)
      .single();
    
    const commentWithAuthor = {
      ...comment,
      author: authorProfile || { id: req.user.id, email: req.user.email || 'Unknown' }
    };
    
    res.status(201).json(commentWithAuthor);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== CLIENTS ==========
router.get('/clients', requireOrgContext, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('clients')
      .select('*')
      .eq('organization_id', req.organizationId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/clients', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!(await canManageClientsResource(req.user.id, req.organizationId, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to manage clients' });
    }
    const { name, email, company, phone, address, notes } = req.body;
    const { data, error } = await supabaseAdmin
      .from('clients')
      .insert([{
        name,
        email,
        company,
        phone,
        address,
        notes,
        created_by: req.user.id,
        organization_id: req.organizationId,
      }])
      .select()
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== NOTIFICATIONS ==========
// Get notifications for current user (supports status filter: all | unread | read)
router.get('/notifications', requireOrgContext, async (req, res) => {
  try {
    const { status } = req.query || {};

    let query = supabaseAdmin
      .from('notifications')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('organization_id', req.organizationId);

    if (!status || status === 'unread') {
      query = query.eq('is_read', false);
    } else if (status === 'read') {
      query = query.eq('is_read', true);
    }

    const { data, error } = await query
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) throw error;

    let notifications = data || [];

    // Client: only show notifications for issues that are DONE and exposed_to_client.
    if (req.orgRole === 'client') {
      const issueIds = [
        ...new Set(
          notifications
            .filter((n) => n.related_type === 'issue' && n.related_id)
            .map((n) => n.related_id)
        ),
      ];

      if (issueIds.length === 0) {
        return res.json([]);
      }

      const { data: issues, error: issuesError } = await supabaseAdmin
        .from('issues')
        .select('id')
        .in('id', issueIds)
        .eq('organization_id', req.organizationId)
        .eq('exposed_to_client', true)
        .eq('status', 'done');

      if (issuesError) throw issuesError;

      const allowedIssueIdSet = new Set((issues || []).map((i) => i.id));
      notifications = notifications.filter((n) => allowedIssueIdSet.has(n.related_id));
    }

    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark notifications as read
router.post('/notifications/mark-read', requireOrgContext, async (req, res) => {
  try {
    const { ids } = req.body || {};
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'No notification IDs provided' });
    }

    const { data, error } = await supabaseAdmin
      .from('notifications')
      .update({ is_read: true })
      .in('id', ids)
      .eq('user_id', req.user.id)
      .eq('organization_id', req.organizationId)
      .select('id, is_read');

    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/clients/:id', requireOrgContext, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('clients')
      .select('*')
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/clients/:id', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!(await canManageClientsResource(req.user.id, req.organizationId, userRole))) {
      return res.status(403).json({ error: 'You do not have permission to manage clients' });
    }
    const { data, error } = await supabaseAdmin
      .from('clients')
      .update(req.body)
      .eq('id', req.params.id)
      .eq('organization_id', req.organizationId)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== RELEASES ==========
router.get('/releases', requireOrgContext, async (req, res) => {
  try {
    const { project_id, is_active } = req.query;
    if (project_id) {
      const { data: p } = await supabaseAdmin.from('projects').select('id, organization_id').eq('id', project_id).maybeSingle();
      if (!p || String(p.organization_id) !== String(req.organizationId)) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
    }
    let query = supabaseAdmin
      .from('releases')
      .select('*, project:projects(*)');
    
    if (project_id) query = query.eq('project_id', project_id);
    if (is_active !== undefined) query = query.eq('is_active', is_active === 'true');
    
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/releases', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canManageMilestones(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to create releases' });
    }
    const { project_id, name, description, version, start_date, end_date, is_active } = req.body;
    if (project_id) {
      const { data: p } = await supabaseAdmin.from('projects').select('id, organization_id').eq('id', project_id).maybeSingle();
      if (!p || String(p.organization_id) !== String(req.organizationId)) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
      const okProj = await userHasProjectAccess(req.user.id, req.organizationId, project_id, userRole);
      if (!okProj) {
        return res.status(403).json({ error: 'Project not found or access denied' });
      }
    }
    const { data, error } = await supabaseAdmin
      .from('releases')
      .insert([{
        project_id,
        name,
        description,
        version,
        start_date,
        end_date,
        is_active: is_active !== undefined ? is_active : true,
        created_by: req.user.id
      }])
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/releases/:id', requireOrgContext, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('releases')
      .select('*, project:projects(*)')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;
    if (data?.project_id) {
      const { data: p } = await supabaseAdmin.from('projects').select('id, organization_id').eq('id', data.project_id).maybeSingle();
      if (!p || String(p.organization_id) !== String(req.organizationId)) {
        return res.status(403).json({ error: 'Release not found or access denied' });
      }
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/releases/:id', requireOrgContext, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    if (!canManageMilestones(userRole)) {
      return res.status(403).json({ error: 'You do not have permission to update releases' });
    }
    const { data: existing, error: exErr } = await supabaseAdmin
      .from('releases')
      .select('id, project_id')
      .eq('id', req.params.id)
      .maybeSingle();
    if (exErr || !existing) return res.status(404).json({ error: 'Release not found' });
    if (existing.project_id) {
      const { data: p } = await supabaseAdmin.from('projects').select('id, organization_id').eq('id', existing.project_id).maybeSingle();
      if (!p || String(p.organization_id) !== String(req.organizationId)) {
        return res.status(403).json({ error: 'Release not found or access denied' });
      }
      const okProj = await userHasProjectAccess(req.user.id, req.organizationId, existing.project_id, userRole);
      if (!okProj) {
        return res.status(403).json({ error: 'Release not found or access denied' });
      }
    }

    const { data, error } = await supabaseAdmin
      .from('releases')
      .update(req.body)
      .eq('id', req.params.id)
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;

