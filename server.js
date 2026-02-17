import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import jiraRouter from './jira_api.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware to verify Supabase token
const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token verification failed' });
  }
};

// Get user role
const getUserRole = async (userId) => {
  const { data, error } = await supabase
    .from('user_roles')
    .select('role')
    .eq('user_id', userId)
    .single();
  
  if (error || !data) return 'user';
  return data.role;
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// JIRA-like API routes
app.use('/api/jira', jiraRouter);

// Get all tasks
app.get('/api/tasks', verifyToken, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    let query = supabase.from('tasks').select('*');
    
    // Team members and users can only see tasks assigned to them
    if (userRole === 'user' || userRole === 'team_member') {
      query = query.or(`assigned_to.eq.${req.user.id},created_by.eq.${req.user.id}`);
    }
    // Team leaders can see all tasks
    
    const { data, error } = await query.order('created_at', { ascending: false });
    
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single task
app.get('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
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
app.post('/api/tasks', verifyToken, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    // Only team leaders can assign tasks to others
    if (req.body.assigned_to && req.body.assigned_to !== req.user.id && userRole !== 'team_leader') {
      return res.status(403).json({ error: 'Only team leaders can assign tasks to others' });
    }
    
    const taskData = {
      ...req.body,
      created_by: req.user.id,
      assigned_to: req.body.assigned_to || req.user.id,
      status: req.body.status || 'pending'
    };
    
    const { data, error } = await supabase
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
app.put('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    // Get current task
    const { data: task, error: taskError } = await supabase
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (taskError) throw taskError;
    
    const userRole = await getUserRole(req.user.id);
    
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
    // Team leaders can update anything
    
    const { data, error } = await supabase
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
app.delete('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    const { data: task, error: taskError } = await supabase
      .from('tasks')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (taskError) throw taskError;
    
    const userRole = await getUserRole(req.user.id);
    
    // Only creator or team leader can delete
    if (task.created_by !== req.user.id && userRole !== 'team_leader') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const { error } = await supabase
      .from('tasks')
      .delete()
      .eq('id', req.params.id);
    
    if (error) throw error;
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user info
app.get('/api/user', verifyToken, async (req, res) => {
  try {
    const role = await getUserRole(req.user.id);
    res.json({
      id: req.user.id,
      email: req.user.email,
      role: role
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all users (for team leaders to assign tasks)
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    if (userRole !== 'team_leader') {
      return res.status(403).json({ error: 'Only team leaders can view all users' });
    }
    
    // Get all users with their roles and profiles
    const { data: userRoles, error: rolesError } = await supabase
      .from('user_roles')
      .select('user_id, role');
    
    if (rolesError) throw rolesError;
    
    // Get user emails from auth.users via profiles
    const userIds = userRoles.map(ur => ur.user_id);
    const { data: profiles, error: profilesError } = await supabase
      .from('profiles')
      .select('id, email')
      .in('id', userIds);
    
    if (profilesError) throw profilesError;
    
    // Combine data
    const users = userRoles.map(ur => {
      const profile = profiles.find(p => p.id === ur.user_id);
      return {
        user_id: ur.user_id,
        role: ur.role,
        email: profile?.email || 'Unknown'
      };
    });
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

