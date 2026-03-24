import express from 'express';
import { supabaseAdmin } from './supabaseAdmin.js';
import { supabaseAnon } from './supabaseAnon.js';
import { authenticate } from './middleware/auth.js';
import { inviteSignupUrl, escapeIlikeExact, normalizeInviteEmail } from './inviteHelpers.js';
import { invitationMatchesUser } from './orgMembershipHelpers.js';
import { userRoleFromInvitationOrgRole } from './roleWorkspace.js';
import { logger, isDebugEnabled } from './logger.js';

const router = express.Router();

/**
 * Passwordless magic-link sign-in is disabled: all users must sign in with email + password.
 * (Kept as a route so old clients get a clear error instead of a dead endpoint.)
 */
router.post('/auth/magiclink-action', async (_req, res) => {
  return res.status(403).json({
    error: 'Passwordless sign-in is disabled. Sign in with your email and password.',
  });
});

/**
 * Reset password (password-based login recovery).
 * This lets a user set a new password if they forgot it.
 *
 * Security note: this does not log the user in; it just starts the password reset flow.
 */
router.post('/auth/recovery-action', async (req, res) => {
  try {
    const emailRaw = req.body?.email;
    const email = String(emailRaw || '').trim().toLowerCase();
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const frontendBase = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');

    // LOG_LEVEL=debug: do NOT call resetPasswordForEmail — that hits Supabase email rate limits.
    // Only admin generateLink (no email); recovery URL is logged for local/testing use.
    if (isDebugEnabled()) {
      const { data, error } = await supabaseAdmin.auth.admin.generateLink({
        type: 'recovery',
        email,
        options: {
          redirectTo: frontendBase,
        },
      });
      if (error) throw error;
      const actionLink = data?.properties?.action_link || '';
      if (actionLink) {
        logger.debug('[auth/recovery-action] recovery action_link (debug only, no email sent)', {
          email,
          actionLink,
        });
      } else {
        logger.warn('[auth/recovery-action] debug: generateLink returned no action_link', { email });
      }
      return res.json({
        message:
          'Debug mode (LOG_LEVEL=debug): no reset email was sent. The recovery link is in the server logs only.',
      });
    }

    // Production: send reset email via public Auth API (requires SUPABASE_ANON_KEY on the backend).
    if (!supabaseAnon) {
      return res.status(503).json({
        error:
          'Password reset is not configured: set SUPABASE_ANON_KEY on the server, or set LOG_LEVEL=debug temporarily for link-in-logs only (no email).',
      });
    }

    const { error: recoverErr } = await supabaseAnon.auth.resetPasswordForEmail(email, {
      redirectTo: frontendBase,
    });
    if (recoverErr) throw recoverErr;
    logger.info('[auth/recovery-action] password reset email requested', { email });

    return res.json({
      message:
        'If an account exists for this email, you will receive password reset instructions shortly.',
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || String(e) });
  }
});

/**
 * Public: load invite for signup form (no auth).
 */
router.get('/invitations/:token', async (req, res) => {
  try {
    const token = (req.params.token || '').trim();
    if (!token) return res.status(400).json({ error: 'Invalid invitation' });

    const { data: inv, error } = await supabaseAdmin
      .from('organization_invitations')
      .select(`
        id,
        email,
        role,
        status,
        expires_at,
        created_at,
        organization_id,
        organizations:organization_id ( id, name, status )
      `)
      .eq('invitation_token', token)
      .maybeSingle();

    if (error) throw error;
    if (!inv || inv.status !== 'pending') {
      return res.status(404).json({ error: 'Invitation not found or already used' });
    }
    if (inv.expires_at && new Date(inv.expires_at) <= new Date()) {
      return res.status(410).json({ error: 'This invitation has expired' });
    }
    if (inv.organizations?.status !== 'active') {
      return res.status(400).json({ error: 'Organization is not active' });
    }

    // Existing account = profile for this email was created before this invitation.
    // (Avoids treating a brand-new signup as "existing" after they just created their profile.)
    let isExistingUser = false;
    const invEmail = normalizeInviteEmail(inv.email || '');
    const invCreated = inv.created_at ? new Date(inv.created_at).getTime() : null;
    if (invEmail && invCreated != null && !Number.isNaN(invCreated)) {
      const { data: prof, error: profErr } = await supabaseAdmin
        .from('profiles')
        .select('created_at')
        .ilike('email', escapeIlikeExact(invEmail))
        .maybeSingle();
      if (!profErr && prof?.created_at) {
        const profTs = new Date(prof.created_at).getTime();
        if (!Number.isNaN(profTs) && profTs < invCreated) {
          isExistingUser = true;
        }
      }
    }

    res.json({
      email: inv.email,
      organization_name: inv.organizations?.name || 'Organization',
      org_role: inv.role,
      // Backward-compatible name (previously "global_role", now merged = role)
      global_role: inv.role,
      is_existing_user: isExistingUser,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * If a user opened the invite link but isn't authenticated yet,
 * generate a Supabase invite/auth action link so they can complete
 * the Supabase auth flow themselves and then return to our app.
 */
router.post('/invitations/:token/supabase-action-link', async (req, res) => {
  try {
    const token = (req.params.token || '').trim();
    if (!token) return res.status(400).json({ error: 'Invalid invitation' });

    const { data: inv, error: invErr } = await supabaseAdmin
      .from('organization_invitations')
      .select('id, email, role, status, expires_at, organization_id, organizations:organization_id(id, status)')
      .eq('invitation_token', token)
      .maybeSingle();

    if (invErr) throw invErr;
    if (!inv || inv.status !== 'pending') {
      return res.status(404).json({ error: 'Invitation not found or already used' });
    }
    if (inv.expires_at && new Date(inv.expires_at) <= new Date()) {
      return res.status(410).json({ error: 'This invitation has expired' });
    }
    if (inv.organizations?.status !== 'active') {
      return res.status(400).json({ error: 'Organization is not active' });
    }

    const email = String(inv.email || '').trim().toLowerCase();

    // New accounts only: `invite` link (user sets password on Supabase). No magic-link fallback —
    // existing users must sign in with email + password on the app (no passwordless sign-in).
    try {
      const { data, error } = await supabaseAdmin.auth.admin.generateLink({
        type: 'invite',
        email,
        options: {
          redirectTo: inviteSignupUrl(token),
          data: { invitation_token: token, organization_id: inv.organization_id },
        },
      });
      if (error) throw error;
      const actionLink = data?.properties?.action_link;
      if (!actionLink) return res.status(500).json({ error: 'Failed to generate invite link' });
      return res.json({ action_link: actionLink });
    } catch (e) {
      const msg =
        e?.message ||
        e?.error_description ||
        e?.error ||
        JSON.stringify(e, null, 2) ||
        String(e);
      const alreadyRegistered =
        msg.toLowerCase().includes('already been registered') ||
        msg.toLowerCase().includes('already registered') ||
        msg.toLowerCase().includes('registered');

      if (!alreadyRegistered) throw e;

      return res.status(409).json({
        error:
          'An account with this email already exists. Sign in with your email and password on this page to join the organization.',
        code: 'USER_ALREADY_REGISTERED',
      });
    }
  } catch (e) {
    return res.status(500).json({ error: e?.message || String(e) });
  }
});

/**
 * Complete invite after Supabase-managed signup/password setup.
 * - User is already logged in (authenticate)
 * - We only collect first/last and attach org + roles from our invitation token.
 */
router.post('/invitations/:token/signup', authenticate, async (req, res) => {
  try {
    const token = (req.params.token || '').trim();
    if (!token) return res.status(400).json({ error: 'Invalid invitation' });

    const { first_name, last_name, password } = req.body || {};
    const fn = (first_name || '').toString().trim();
    const ln = (last_name || '').toString().trim();
    // Name fields are optional per requirements.
    // If empty, we'll persist null/empty values to the profile.
    const first = fn || null;
    const last = ln || null;

    const pass = (password || '').toString();
    const hasAnyPassword = Boolean(pass);
    if (hasAnyPassword && pass.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const { data: inv, error: invErr } = await supabaseAdmin
      .from('organization_invitations')
      .select('id, email, role, status, expires_at, organization_id, invitation_token')
      .eq('invitation_token', token)
      .maybeSingle();

    if (invErr) throw invErr;
    if (!inv || inv.status !== 'pending') {
      return res.status(404).json({ error: 'Invitation not found or already used' });
    }
    if (inv.expires_at && new Date(inv.expires_at) <= new Date()) {
      return res.status(410).json({ error: 'This invitation has expired' });
    }

    const expectedEmail = normalizeInviteEmail(inv.email || '');
    if (!expectedEmail) return res.status(400).json({ error: 'Invitation email missing' });

    const matches = await invitationMatchesUser(req.user.id, expectedEmail, req.user?.email);
    if (!matches) {
      return res.status(403).json({ error: 'This invitation does not match your account' });
    }

    const userId = req.user.id;
    if (!userId) return res.status(500).json({ error: 'User id missing' });

    // Optional: set password during invite completion so the user can log in via email+password later.
    if (hasAnyPassword) {
      const { error: pwErr } = await supabaseAdmin.auth.admin.updateUserById(userId, {
        password: pass,
      });
      if (pwErr) {
        return res.status(500).json({ error: pwErr.message || pwErr });
      }
    }

    // 1) Profile: always keep email in sync; only overwrite names when the user provided them
    //    (existing users joining another org should not clear first/last name).
    const profilePayload = { id: userId, email: expectedEmail };
    if (fn || ln) {
      profilePayload.first_name = first;
      profilePayload.last_name = last;
    }
    await supabaseAdmin.from('profiles').upsert(profilePayload, { onConflict: 'id' });

    const invOrg = String(inv.organization_id);
    const { data: memBefore, error: mbErr } = await supabaseAdmin
      .from('organization_members')
      .select('organization_id')
      .eq('user_id', userId);
    if (mbErr) throw mbErr;
    // Joining a second workspace must not overwrite global user_roles (e.g. admin in org A, user in org B).
    const shouldSyncGlobalRole =
      (memBefore || []).filter((m) => String(m.organization_id) !== invOrg).length === 0;

    // 2) Workspace user_roles: only when this is their first (or only) workspace context
    if (shouldSyncGlobalRole) {
      const mergedRole = userRoleFromInvitationOrgRole(inv.role);
      await supabaseAdmin
        .from('user_roles')
        .upsert(
          { user_id: userId, role: mergedRole, is_active: true },
          { onConflict: 'user_id' }
        );
    }

    // 3) Attach organization membership
    const { data: existingMember, error: memberLookupErr } = await supabaseAdmin
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', inv.organization_id)
      .eq('user_id', userId)
      .maybeSingle();
    if (memberLookupErr) throw memberLookupErr;

    if (existingMember) {
      const { error: updErr } = await supabaseAdmin
        .from('organization_members')
        .update({ role: inv.role })
        .eq('organization_id', inv.organization_id)
        .eq('user_id', userId);
      if (updErr) throw updErr;
    } else {
      const { error: insErr } = await supabaseAdmin
        .from('organization_members')
        .insert([
          {
            organization_id: inv.organization_id,
            user_id: userId,
            role: inv.role,
          },
        ]);
      if (insErr) throw insErr;
    }

    // 4) Mark invitation accepted
    await supabaseAdmin
      .from('organization_invitations')
      .update({ status: 'accepted', accepted_at: new Date().toISOString() })
      .eq('id', inv.id);

    res.status(201).json({ message: 'Invite completed', user_id: userId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;

