import express from 'express';

import { supabaseAdmin } from '../supabaseAdmin.js';
import { authenticate, loadGlobalRole } from '../middleware/auth.js';
import { getUserRole } from '../services/authz.js';

const router = express.Router();

// Get all tasks
router.get('/tasks', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);

    let query = supabaseAdmin.from('tasks').select('*');

    // Team members and users can only see tasks assigned to them
    if (userRole === 'user' || userRole === 'team_member') {
      query = query.or(`assigned_to.eq.${req.user.id},created_by.eq.${req.user.id}`);
    }
    // Team leaders, admins and superadmins can see all tasks

    const { data, error } = await query.order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single task
router.get('/tasks/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error) throw error;

    const userRole = await getUserRole(req.user.id);

    // Check access
    if (userRole === 'user' || userRole === 'team_member') {
      if (data.assigned_to !== req.user.id && data.created_by !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create task
router.post('/tasks', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);

    const isManager = userRole === 'team_leader' || userRole === 'admin' || userRole === 'superadmin';

    // Only managers can assign tasks to others
    if (req.body.assigned_to && req.body.assigned_to !== req.user.id && !isManager) {
      return res.status(403).json({ error: 'Only team leaders/admins can assign tasks to others' });
    }

    const taskData = {
      ...req.body,
      created_by: req.user.id,
      assigned_to: req.body.assigned_to || req.user.id,
      status: req.body.status || 'pending',
    };

    const { data, error } = await supabaseAdmin
      .from('tasks')
      .insert([taskData])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update task
router.put('/tasks/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    // Get current task
    const { data: task, error: taskError } = await supabaseAdmin
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (taskError) throw taskError;

    const userRole = await getUserRole(req.user.id);
    const isManager = userRole === 'team_leader' || userRole === 'admin' || userRole === 'superadmin';

    // Check permissions
    if (userRole === 'user') {
      // Users can only update their own tasks
      if (task.created_by !== req.user.id) {
        return res.status(403).json({ error: 'You can only update your own tasks' });
      }
    } else if (userRole === 'team_member') {
      // Team members can update status of assigned tasks
      if (task.assigned_to !== req.user.id && task.created_by !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
      }
      // Team members can only update status, not assign to others
      if (req.body.assigned_to && req.body.assigned_to !== task.assigned_to) {
        return res.status(403).json({ error: 'Team members cannot reassign tasks' });
      }
    }
    // Team leaders / admins / superadmins can update anything
    void isManager;

    const { data, error } = await supabaseAdmin
      .from('tasks')
      .update(req.body)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete task
router.delete('/tasks/:id', authenticate, loadGlobalRole, async (req, res) => {
  try {
    const { data: task, error: taskError } = await supabaseAdmin
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (taskError) throw taskError;

    const userRole = await getUserRole(req.user.id);
    const isManager = userRole === 'team_leader' || userRole === 'admin' || userRole === 'superadmin';

    // Only creator or manager can delete
    if (task.created_by !== req.user.id && !isManager) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { error } = await supabaseAdmin.from('tasks').delete().eq('id', req.params.id);

    if (error) throw error;
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;

