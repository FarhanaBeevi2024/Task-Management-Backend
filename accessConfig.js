import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const config = JSON.parse(
  readFileSync(join(__dirname, 'accessConfig.json'), 'utf8')
);

const roles = config.roles || {};

function getRoleConfig(globalRole) {
  return roles[globalRole] || roles.user || {};
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

/** Get full role config for a given role (for future use) */
export function getProjectPermissions(globalRole) {
  return getRoleConfig(globalRole).project || {};
}
