import { supabaseAdmin } from '../supabaseAdmin.js';
import { userRoleFromInvitationOrgRole } from '../roleWorkspace.js';

/**
 * Multi-organization support:
 * - Load all organization_members for the user.
 * - If req.orgIdFromRoute is set (org admin routes), verify membership in that org.
 * - Else use X-Organization-Id header when user belongs to multiple orgs.
 * - Else single membership auto-selects.
 * - SuperAdmin: bypass (no req.organizationId unless set elsewhere).
 */
export async function requireOrgContext(req, res, next) {
  if (req.isSuperAdmin) return next();

  const { data: memberships, error } = await supabaseAdmin
    .from('organization_members')
    .select('organization_id, role, organizations:organization_id(id, name, status)')
    .eq('user_id', req.user.id);

  if (error) return res.status(500).json({ error: error.message });

  const activeMemberships = (memberships || []).filter(
    (m) => m.organizations && m.organizations.status === 'active'
  );

  const tryAcceptInvitation = async () => {
    const email = (req.user.email || '').trim().toLowerCase();
    if (!email) return null;

    const findInvitation = async (statuses) => {
      const q = supabaseAdmin
        .from('organization_invitations')
        .select('id, organization_id, role, status, expires_at, organizations:organization_id(id, status)')
        .eq('email', email);

      if (Array.isArray(statuses) && statuses.length > 0) {
        q.in('status', statuses);
      }

      return q
        .order('created_at', { ascending: false })
        .maybeSingle();
    };

    // First try pending invites; if none exists, recover from inconsistent states
    // where an invite is already accepted but organization_members row is missing.
    const { data: invite, error: inviteError } = await findInvitation(['pending']);

    if (inviteError) {
      console.error('Auto-link: error fetching pending invite', {
        user_id: req.user.id,
        email,
        error: inviteError?.message || inviteError,
      });
    }

    let chosen = invite;

    if (!chosen) {
      const { data: acceptedInvite, error: acceptedErr } = await findInvitation(['accepted']);
      if (acceptedErr) {
        console.error('Auto-link: error fetching accepted invite', {
          user_id: req.user.id,
          email,
          error: acceptedErr?.message || acceptedErr,
        });
      }
      chosen = acceptedInvite;
    }
    if (inviteError || !chosen) return null;
    if (chosen.expires_at != null && new Date(chosen.expires_at) <= new Date()) return null;
    if (chosen.organizations?.status !== 'active') return null;

    const { data: created, error: createError } = await supabaseAdmin
      .from('organization_members')
      .insert([{
        organization_id: chosen.organization_id,
        user_id: req.user.id,
        role: chosen.role,
      }])
      .select('organization_id, role, organizations:organization_id(id, name, status)')
      .single();

    if (createError || !created) {
      console.error('Auto-link: failed to insert organization_members', {
        user_id: req.user.id,
        email,
        invite_id: chosen.id,
        organization_id: chosen.organization_id,
        role: chosen.role,
        error: createError?.message || createError,
      });
      return null;
    }

    // Workspace user_roles: admin | user only
    await supabaseAdmin
      .from('user_roles')
      .upsert(
        { user_id: req.user.id, role: userRoleFromInvitationOrgRole(chosen.role), is_active: true },
        { onConflict: 'user_id' }
      );

    if (chosen.status === 'pending') {
      await supabaseAdmin
        .from('organization_invitations')
        .update({ status: 'accepted', accepted_at: new Date().toISOString() })
        .eq('id', chosen.id);
    }

    return created;
  };

  let working = [...activeMemberships];

  if (working.length === 0) {
    const fromInvite = await tryAcceptInvitation();
    if (fromInvite) {
      working = [fromInvite];
    } else {
      return res.status(403).json({ error: 'No organization assigned to this user' });
    }
  }

  const pickFromRoute = req.orgIdFromRoute != null && String(req.orgIdFromRoute).length > 0;
  if (pickFromRoute) {
    const m = working.find(
      (x) => String(x.organization_id) === String(req.orgIdFromRoute)
    );
    if (!m) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }
    req.organizationId = m.organization_id;
    req.orgRole = m.role;
    req.orgMemberships = working;
    return next();
  }

  const headerOrg = req.headers['x-organization-id'] || req.headers['X-Organization-Id'];
  if (headerOrg) {
    const m = working.find((x) => String(x.organization_id) === String(headerOrg));
    if (!m) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }
    req.organizationId = m.organization_id;
    req.orgRole = m.role;
    req.orgMemberships = working;
    return next();
  }

  if (working.length === 1) {
    req.organizationId = working[0].organization_id;
    req.orgRole = working[0].role;
    req.orgMemberships = working;
    return next();
  }

  return res.status(400).json({
    error: 'Select an organization',
    code: 'ORG_REQUIRED',
    organizations: working.map((m) => ({
      id: m.organization_id,
      name: m.organizations?.name || 'Organization',
      org_role: m.role,
    })),
  });
}

export async function attachOrgFromProject(req, res, next) {
  const projectId = req.params.id || req.params.projectId || req.query.project_id || req.body?.project_id;
  if (!projectId) return res.status(400).json({ error: 'project_id is required' });

  const { data: project, error } = await supabaseAdmin
    .from('projects')
    .select('id, organization_id')
    .eq('id', projectId)
    .maybeSingle();

  if (error || !project) return res.status(404).json({ error: 'Project not found' });
  req.resourceOrganizationId = project.organization_id;
  next();
}

export async function attachOrgFromIssue(req, res, next) {
  const issueId = req.params.id || req.params.issue_id || req.params.issueId || req.body?.issue_id || req.query.issue_id;
  if (!issueId) return res.status(400).json({ error: 'issue_id is required' });

  const { data: issue, error } = await supabaseAdmin
    .from('issues')
    .select('id, organization_id')
    .eq('id', issueId)
    .maybeSingle();

  if (error || !issue) return res.status(404).json({ error: 'Issue not found' });
  req.resourceOrganizationId = issue.organization_id;
  next();
}

export function requireSameOrganizationForResource(req, res, next) {
  if (req.isSuperAdmin) return next();
  if (!req.organizationId) return res.status(500).json({ error: 'organizationId missing (check middleware order)' });
  if (!req.resourceOrganizationId) return res.status(500).json({ error: 'resourceOrganizationId missing' });
  if (String(req.organizationId) !== String(req.resourceOrganizationId)) {
    return res.status(403).json({ error: 'Resource is outside your organization' });
  }
  next();
}
