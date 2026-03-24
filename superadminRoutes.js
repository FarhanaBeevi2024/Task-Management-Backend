import express from 'express';
import { supabaseAdmin } from './supabaseAdmin.js';
import { authenticate, loadGlobalRole } from './middleware/auth.js';
import { generateInviteToken, inviteSignupUrl } from './inviteHelpers.js';

const router = express.Router();

router.use(authenticate, loadGlobalRole);

function requireSuperAdmin(req, res, next) {
  if (!req.isSuperAdmin) return res.status(403).json({ error: 'Only superadmin can access this resource' });
  next();
}

// Organizations overview with counts for dashboard
router.get('/organizations-overview', requireSuperAdmin, async (_req, res) => {
  try {
    const { data: orgs, error } = await supabaseAdmin
      .from('organizations')
      .select('id, name, status, created_at, created_by')
      .order('created_at', { ascending: false });
    if (error) throw error;

    const orgIds = (orgs || []).map((o) => o.id);

    // Count members/projects/issues per org with grouped queries
    const [membersCount, projectsCount, issuesCount] = await Promise.all([
      supabaseAdmin
        .from('organization_members')
        .select('organization_id', { count: 'exact', head: false })
        .in('organization_id', orgIds),
      supabaseAdmin
        .from('projects')
        .select('organization_id', { count: 'exact', head: false })
        .in('organization_id', orgIds),
      supabaseAdmin
        .from('issues')
        .select('organization_id', { count: 'exact', head: false })
        .in('organization_id', orgIds),
    ]);

    // supabase-js doesn't return grouped counts directly; fetch rows and aggregate in JS
    const agg = (rows) => {
      const m = new Map();
      (rows || []).forEach((r) => {
        const k = r.organization_id;
        m.set(k, (m.get(k) || 0) + 1);
      });
      return m;
    };

    const memberByOrg = agg(membersCount.data);
    const projectsByOrg = agg(projectsCount.data);
    const issuesByOrg = agg(issuesCount.data);

    res.json((orgs || []).map((o) => ({
      ...o,
      members_count: memberByOrg.get(o.id) || 0,
      projects_count: projectsByOrg.get(o.id) || 0,
      issues_count: issuesByOrg.get(o.id) || 0,
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** Invite an organization admin: creates pending invite + signup link (org role org_admin, global admin). */
router.post('/organizations/:orgId/invite-admin', requireSuperAdmin, async (req, res) => {
  try {
    const { email } = req.body || {};
    const emailNorm = String(email || '').trim().toLowerCase();
    if (!emailNorm || !emailNorm.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const { data: org, error: orgErr } = await supabaseAdmin
      .from('organizations')
      .select('id, status')
      .eq('id', req.params.orgId)
      .maybeSingle();
    if (orgErr) throw orgErr;
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.status !== 'active') return res.status(400).json({ error: 'Organization is not active' });

    const token = generateInviteToken();
    const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

    await supabaseAdmin
      .from('organization_invitations')
      .delete()
      .eq('organization_id', req.params.orgId)
      .eq('email', emailNorm);

    const { data, error } = await supabaseAdmin
      .from('organization_invitations')
      .insert([{
        organization_id: req.params.orgId,
        email: emailNorm,
        role: 'admin',
        invitation_token: token,
        invited_by: req.user.id,
        status: 'pending',
        expires_at: expiresAt,
      }])
      .select('*')
      .single();

    if (error) throw error;

    // Send Supabase-managed invite email (user completes password on Supabase).
    let emailSendError = null;
    try {
      await supabaseAdmin.auth.admin.inviteUserByEmail(emailNorm, {
        redirectTo: inviteSignupUrl(token),
        data: { invitation_token: token, organization_id: req.params.orgId },
      });
    } catch (e) {
      console.error('Failed to send Supabase invite email:', e?.message || e);
      emailSendError = e?.message || String(e);
    }

    res.status(201).json({
      ...data,
      signup_url: inviteSignupUrl(token),
      email_send_error: emailSendError,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;

