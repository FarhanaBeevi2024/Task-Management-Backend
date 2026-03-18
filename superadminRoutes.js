import express from 'express';
import { supabaseAdmin } from './supabaseAdmin.js';
import { authenticate, loadGlobalRole } from './middleware/auth.js';

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

export default router;

