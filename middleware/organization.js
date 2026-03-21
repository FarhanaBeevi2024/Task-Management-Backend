import { supabaseAdmin } from '../supabaseAdmin.js';

/**
 * Single-tenant-per-user org resolution.
 * - Normal users: organization_id is derived from organization_members(user_id).
 * - SuperAdmin: bypasses org restriction (can access all orgs); organizationId may be left null.
 */
export async function requireOrgContext(req, res, next) {
  if (req.isSuperAdmin) return next();

  const { data: membership, error } = await supabaseAdmin
    .from('organization_members')
    .select('organization_id, role, organizations:organization_id(id, status)')
    .eq('user_id', req.user.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  if (!membership) {
    // Auto-accept invitation on first login/signup.
    const email = (req.user.email || '').trim().toLowerCase();
    if (!email) return res.status(403).json({ error: 'No organization assigned to this user' });

    const { data: invite, error: inviteError } = await supabaseAdmin
      .from('organization_invitations')
      .select('id, organization_id, role, status, expires_at, organizations:organization_id(id, status)')
      .eq('email', email)
      .eq('status', 'pending')
      .order('created_at', { ascending: false })
      .maybeSingle();

    if (!inviteError && invite && (invite.expires_at == null || new Date(invite.expires_at) > new Date())) {
      if (invite.organizations?.status !== 'active') {
        return res.status(403).json({ error: 'Organization is inactive' });
      }

      const { data: created, error: createError } = await supabaseAdmin
        .from('organization_members')
        .insert([{
          organization_id: invite.organization_id,
          user_id: req.user.id,
          role: invite.role,
        }])
        .select('organization_id, role, organizations:organization_id(id, status)')
        .single();

      if (!createError && created) {
        await supabaseAdmin
          .from('organization_invitations')
          .update({ status: 'accepted', accepted_at: new Date().toISOString() })
          .eq('id', invite.id);

        req.organizationId = created.organization_id;
        req.orgRole = created.role;
        return next();
      }
    }

    return res.status(403).json({ error: 'No organization assigned to this user' });
  }

  const org = membership.organizations;
  if (!org) return res.status(403).json({ error: 'Organization not found for this user' });
  if (org.status !== 'active') return res.status(403).json({ error: 'Organization is inactive' });

  req.organizationId = membership.organization_id;
  req.orgRole = membership.role;
  next();
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

