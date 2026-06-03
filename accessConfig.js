/**
 * Role-based access flags — loaded from `role_access_config` (see roleAccessStore.js).
 * Re-exports keep existing imports (`./accessConfig.js`) working.
 */
export {
  refreshRoleAccessCache,
  getAccessConfigPayload,
  upsertRoleAccessFromBody,
  EDITABLE_ROLE_KEYS,
  DEFAULT_ROLE_ACCESS,
  canManageUsers,
  canViewAllUsers,
  canUserCreateProject,
  canViewAllProjects,
  shouldAutoAddAsProjectMemberOnCreate,
  canManageProjectMembers,
  canCreateIssues,
  canAssignIssuesToOthers,
  canManageMilestones,
  canDeleteProjects,
  canDeleteIssues,
  getProjectPermissions,
  getRoleAccessRoles,
} from './roleAccessStore.js';
