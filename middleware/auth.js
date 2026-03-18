import { supabaseAdmin } from '../supabaseAdmin.js';

export async function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid token' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Token verification failed' });
  }
}

export async function loadGlobalRole(req, _res, next) {
  try {
    const { data, error } = await supabaseAdmin
      .from('user_roles')
      .select('role, is_active')
      .eq('user_id', req.user.id)
      .maybeSingle();

    const role = data?.role || 'user';
    req.globalRole = role;
    req.isSuperAdmin = role === 'superadmin';
    req.isUserActive = data?.is_active !== false;
  } catch {
    req.globalRole = 'user';
    req.isSuperAdmin = false;
    req.isUserActive = true;
  }
  next();
}

