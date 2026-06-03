import { supabaseAdmin } from './supabaseAdmin.js';

/** In-memory copy of role_access_config; refreshed at startup and after admin updates */
let cachedRoles = null;

/** Built-in fallback if DB table is empty (run database/role_access_config.sql) */
export const DEFAULT_ROLE_ACCESS = {
  superadmin: {
    global: {
      canManageUsers: true,
      canViewAllUsers: true,
      canCreateProjects: true,
      canViewAllProjects: true,
      canDeleteProjects: true,
    },
    project: {
      autoMemberOnCreate: true,
      canManageMembers: true,
      canCreateIssues: true,
      canAssignIssuesToOthers: true,
      canManageMilestones: true,
      canDeleteIssues: true,
    },
  },
  admin: {
    global: {
      canManageUsers: true,
      canViewAllUsers: true,
      canCreateProjects: true,
      canViewAllProjects: true,
      canDeleteProjects: true,
    },
    project: {
      autoMemberOnCreate: true,
      canManageMembers: true,
      canCreateIssues: true,
      canAssignIssuesToOthers: true,
      canManageMilestones: true,
      canDeleteIssues: true,
    },
  },
  team_leader: {
    global: {
      canManageUsers: true,
      canViewAllUsers: true,
      canCreateProjects: true,
      canViewAllProjects: false,
      canDeleteProjects: true,
    },
    project: {
      autoMemberOnCreate: true,
      canManageMembers: true,
      canCreateIssues: true,
      canAssignIssuesToOthers: true,
      canManageMilestones: true,
      canDeleteIssues: true,
    },
  },
  team_member: {
    global: {
      canManageUsers: false,
      canViewAllUsers: false,
      canCreateProjects: false,
      canViewAllProjects: false,
      canDeleteProjects: false,
    },
    project: {
      autoMemberOnCreate: false,
      canManageMembers: false,
      canCreateIssues: true,
      canAssignIssuesToOthers: false,
      canManageMilestones: false,
      canDeleteIssues: false,
    },
  },
  client: {
    global: {
      canManageUsers: false,
      canViewAllUsers: false,
      canCreateProjects: false,
      canViewAllProjects: false,
      canDeleteProjects: false,
    },
    project: {
      autoMemberOnCreate: false,
      canManageMembers: false,
      canCreateIssues: false,
      canAssignIssuesToOthers: false,
      canManageMilestones: false,
      canDeleteIssues: false,
    },
  },
  user: {
    global: {
      canManageUsers: false,
      canViewAllUsers: false,
      canCreateProjects: false,
      canViewAllProjects: false,
      canDeleteProjects: false,
    },
    project: {
      autoMemberOnCreate: false,
      canManageMembers: false,
      canCreateIssues: true,
      canAssignIssuesToOthers: false,
      canManageMilestones: false,
      canDeleteIssues: false,
    },
  },
};

export const EDITABLE_ROLE_KEYS = [
  'superadmin',
  'admin',
  'team_leader',
  'team_member',
  'client',
  'user',
];

const GLOBAL_KEYS = new Set([
  'canManageUsers',
  'canViewAllUsers',
  'canCreateProjects',
  'canViewAllProjects',
  'canDeleteProjects',
]);

const PROJECT_KEYS = new Set([
  'autoMemberOnCreate',
  'canManageMembers',
  'canCreateIssues',
  'canAssignIssuesToOthers',
  'canManageMilestones',
  'canDeleteIssues',
]);

const GLOBAL_KEY_LIST = [...GLOBAL_KEYS];
const PROJECT_KEY_LIST = [...PROJECT_KEYS];

function mergeBoolSection(base, patch, keyList) {
  const out = { ...base };
  if (!patch || typeof patch !== 'object') return out;
  for (const k of keyList) {
    if (Object.prototype.hasOwnProperty.call(patch, k)) {
      out[k] = Boolean(patch[k]);
    }
  }
  return out;
}

function rowsToRoles(rows) {
  const roles = {};
  for (const row of rows || []) {
    roles[row.role_key] = {
      global: row.global_permissions && typeof row.global_permissions === 'object'
        ? row.global_permissions
        : {},
      project: row.project_permissions && typeof row.project_permissions === 'object'
        ? row.project_permissions
        : {},
    };
  }
  return roles;
}

/**
 * Load role matrix from DB into memory. Call at server startup and after PUT.
 */
export async function refreshRoleAccessCache() {
  const { data, error } = await supabaseAdmin
    .from('role_access_config')
    .select('role_key, global_permissions, project_permissions');

  if (error) {
    console.error('role_access_config read failed:', error.message);
    cachedRoles = { ...DEFAULT_ROLE_ACCESS };
    return;
  }

  if (!data?.length) {
    console.warn(
      '[role_access] Table empty — using built-in defaults. Run database/role_access_config.sql'
    );
    cachedRoles = { ...DEFAULT_ROLE_ACCESS };
    return;
  }

  cachedRoles = rowsToRoles(data);
}

export function getRoleAccessRoles() {
  return cachedRoles && Object.keys(cachedRoles).length
    ? cachedRoles
    : DEFAULT_ROLE_ACCESS;
}

/**
 * Full matrix for API/UI: every known role key merged with defaults (missing DB keys still work).
 */
export function getAccessConfigPayload() {
  const stored = getRoleAccessRoles();
  const out = {};
  for (const roleKey of EDITABLE_ROLE_KEYS) {
    const def = DEFAULT_ROLE_ACCESS[roleKey] || DEFAULT_ROLE_ACCESS.user;
    const row = stored[roleKey];
    out[roleKey] = {
      global: { ...def.global, ...(row?.global || {}) },
      project: { ...def.project, ...(row?.project || {}) },
    };
  }
  return { roles: out };
}

function getRoleConfig(globalRole) {
  const payload = getAccessConfigPayload().roles;
  return payload[globalRole] || payload.user;
}

/** Global: can access User Management and change other users' roles */
export function canManageUsers(globalRole) {
  return getRoleConfig(globalRole).global?.canManageUsers === true;
}

/** Global: can list all users (e.g. for task assignment or user management) */
export function canViewAllUsers(globalRole) {
  return getRoleConfig(globalRole).global?.canViewAllUsers === true;
}

/** Global: can create new projects */
export function canUserCreateProject(globalRole) {
  return getRoleConfig(globalRole).global?.canCreateProjects === true;
}

/** Global: can see all projects (otherwise only projects in project_members) */
export function canViewAllProjects(globalRole) {
  return getRoleConfig(globalRole).global?.canViewAllProjects === true;
}

/** Project: when this role creates a project, add them as a project_member */
export function shouldAutoAddAsProjectMemberOnCreate(globalRole) {
  return getRoleConfig(globalRole).project?.autoMemberOnCreate === true;
}

/** Project: can add/remove project members */
export function canManageProjectMembers(globalRole) {
  return getRoleConfig(globalRole).project?.canManageMembers === true;
}

/** Project: can create issues in a project */
export function canCreateIssues(globalRole) {
  return getRoleConfig(globalRole).project?.canCreateIssues === true;
}

/** Project: can assign issues to other users */
export function canAssignIssuesToOthers(globalRole) {
  return getRoleConfig(globalRole).project?.canAssignIssuesToOthers === true;
}

/** Project: can create and edit release milestones */
export function canManageMilestones(globalRole) {
  return getRoleConfig(globalRole).project?.canManageMilestones === true;
}

/** Global: can permanently delete projects */
export function canDeleteProjects(globalRole) {
  return getRoleConfig(globalRole).global?.canDeleteProjects === true;
}

/** Project: can delete issues / tasks */
export function canDeleteIssues(globalRole) {
  return getRoleConfig(globalRole).project?.canDeleteIssues === true;
}

/** Get full project permission object */
export function getProjectPermissions(globalRole) {
  return getRoleConfig(globalRole).project || {};
}

/**
 * Replace stored config for allowed roles (admin API).
 * @param {Record<string, { global?: object, project?: object }>} roles
 */
export async function upsertRoleAccessFromBody(roles) {
  if (!roles || typeof roles !== 'object') {
    throw new Error('Invalid body: expected an object shaped like { admin: { global, project }, ... }');
  }

  const rows = [];

  for (const roleKey of EDITABLE_ROLE_KEYS) {
    const def = DEFAULT_ROLE_ACCESS[roleKey] || DEFAULT_ROLE_ACCESS.user;
    const patch = roles[roleKey];
    rows.push({
      role_key: roleKey,
      global_permissions: mergeBoolSection(def.global, patch?.global, GLOBAL_KEY_LIST),
      project_permissions: mergeBoolSection(def.project, patch?.project, PROJECT_KEY_LIST),
      updated_at: new Date().toISOString(),
    });
  }

  const { error } = await supabaseAdmin
    .from('role_access_config')
    .upsert(rows, { onConflict: 'role_key' });

  if (error) throw error;
}
