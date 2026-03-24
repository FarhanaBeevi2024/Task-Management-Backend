/**
 * Workspace (Users page) roles are only admin | user.
 * organization_members still uses admin | team_member (team_member = regular org user).
 * Project roles remain: admin | team_leader | team_member | client.
 */

export function workspaceRoleFromOrgMember(orgRole, globalRole) {
  if (globalRole === 'superadmin') return 'admin';
  if (orgRole === 'admin') return 'admin';
  return 'user';
}

/** API body / UI: admin | user → DB organization_members.role */
export function workspaceRoleToOrgMemberRole(workspaceRole) {
  return workspaceRole === 'admin' ? 'admin' : 'team_member';
}

/** organization_members.role → user_roles.role (admin | user only) */
export function userRoleFromOrgMemberRole(orgRole) {
  return orgRole === 'admin' ? 'admin' : 'user';
}

/** Invite / add-member body: admin | user */
export function inviteWorkspaceRoleToOrgRole(bodyRole) {
  const r = String(bodyRole || '').trim().toLowerCase();
  return r === 'admin' ? 'admin' : 'team_member';
}

/** After invite acceptance: invitation.role (org row) → user_roles.role */
export function userRoleFromInvitationOrgRole(invOrgRole) {
  const r = String(invOrgRole || '').trim().toLowerCase();
  return r === 'admin' ? 'admin' : 'user';
}
