/**
 * Activity logger for audit trail. Inserts into activity_logs table.
 * @param {object} supabase - Supabase client (service role)
 * @param {object} params
 * @param {'TASK'|'PROJECT'|'MILESTONE'} params.entity_type
 * @param {string} params.entity_id - UUID
 * @param {string} params.action_type - CREATE, UPDATE, DELETE, STATUS_CHANGE, etc.
 * @param {string} [params.field_name]
 * @param {string} [params.old_value]
 * @param {string} [params.new_value]
 * @param {string} params.performed_by - user UUID
 */
export async function logActivity(supabase, { entity_type, entity_id, action_type, field_name = null, old_value = null, new_value = null, performed_by }) {
  const row = {
    entity_type,
    entity_id,
    action_type,
    field_name,
    old_value: old_value != null ? String(old_value) : null,
    new_value: new_value != null ? String(new_value) : null,
    performed_by: performed_by || null,
  };
  const { error } = await supabase.from('activity_logs').insert([row]);
  if (error) console.error('Activity log insert failed:', error.message);
}

/**
 * Compare old vs new issue and log one row per changed field (for TASK).
 */
export async function logIssueChanges(supabase, issueId, oldIssue, updates, performedBy) {
  const actions = [];
  if (updates.status !== undefined && String(oldIssue?.status) !== String(updates.status)) {
    actions.push({ action_type: 'STATUS_CHANGE', field_name: 'status', old_value: oldIssue?.status, new_value: updates.status });
  }
  if (updates.internal_priority !== undefined && String(oldIssue?.internal_priority || oldIssue?.priority || '') !== String(updates.internal_priority)) {
    actions.push({ action_type: 'PRIORITY_CHANGE', field_name: 'internal_priority', old_value: oldIssue?.internal_priority || oldIssue?.priority, new_value: updates.internal_priority });
  }
  if (updates.client_priority !== undefined && String(oldIssue?.client_priority || '') !== String(updates.client_priority ?? '')) {
    actions.push({ action_type: 'PRIORITY_CHANGE', field_name: 'client_priority', old_value: oldIssue?.client_priority, new_value: updates.client_priority });
  }
  if (updates.assignee_id !== undefined && String(oldIssue?.assignee_id || '') !== String(updates.assignee_id ?? '')) {
    actions.push({ action_type: 'ASSIGNMENT_CHANGE', field_name: 'assignee_id', old_value: oldIssue?.assignee_id, new_value: updates.assignee_id });
  }
  if (updates.due_date !== undefined && String(oldIssue?.due_date || '') !== String(updates.due_date ?? '')) {
    actions.push({ action_type: 'DUE_DATE_CHANGE', field_name: 'due_date', old_value: oldIssue?.due_date, new_value: updates.due_date });
  }
  if (updates.milestone_id !== undefined && String(oldIssue?.milestone_id || '') !== String(updates.milestone_id ?? '')) {
    actions.push({ action_type: 'MILESTONE_CHANGE', field_name: 'milestone_id', old_value: oldIssue?.milestone_id, new_value: updates.milestone_id });
  }
  if (updates.summary !== undefined && String(oldIssue?.summary || '') !== String(updates.summary)) {
    actions.push({ action_type: 'SUMMARY_CHANGE', field_name: 'summary', old_value: oldIssue?.summary, new_value: updates.summary });
  }
  if (updates.description !== undefined && String(oldIssue?.description || '') !== String(updates.description ?? '')) {
    actions.push({ action_type: 'DESCRIPTION_CHANGE', field_name: 'description', old_value: oldIssue?.description, new_value: updates.description });
  }
  for (const { action_type, field_name, old_value, new_value } of actions) {
    await logActivity(supabase, {
      entity_type: 'TASK',
      entity_id: issueId,
      action_type,
      field_name,
      old_value,
      new_value,
      performed_by: performedBy,
    });
  }
}
