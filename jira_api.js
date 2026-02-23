import express from 'express';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const router = express.Router();
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware to verify token
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

// Helper function to get user role
const getUserRole = async (userId) => {
  const { data, error } = await supabase
    .from('user_roles')
    .select('role')
    .eq('user_id', userId)
    .single();
  
  if (error || !data) return 'user';
  return data.role;
};

// ========== PROJECTS ==========
// Use select('*') so projects load even when clients table doesn't exist yet
router.get('/projects', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('projects')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/projects', verifyToken, async (req, res) => {
  try {
    const { key, name, description, lead_id, client_id } = req.body;
    const { data, error } = await supabase
      .from('projects')
      .insert([{
        key: key.toUpperCase(),
        name,
        description,
        lead_id: lead_id || req.user.id,
        client_id: client_id || null,
        created_by: req.user.id
      }])
      .select('*')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/projects/:id', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('projects')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ISSUE TYPES ==========
router.get('/issue-types', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('issue_types')
      .select('*')
      .order('name');
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ISSUES ==========
router.get('/issues', verifyToken, async (req, res) => {
  try {
    const { project_id, sprint_id, release_id, status, assignee_id } = req.query;
    let query = supabase
      .from('issues')
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*),
        sprint:sprints(*)
      `);
    
    if (project_id) query = query.eq('project_id', project_id);
    if (sprint_id) query = query.eq('sprint_id', sprint_id);
    if (release_id) query = query.eq('release_id', release_id);
    if (status) query = query.eq('status', status);
    if (assignee_id) query = query.eq('assignee_id', assignee_id);
    // Filter by parent_issue_id (null for top-level issues, or specific ID for subtasks)
    if (req.query.parent_issue_id !== undefined) {
      if (req.query.parent_issue_id === null || req.query.parent_issue_id === 'null') {
        query = query.is('parent_issue_id', null);
      } else {
        query = query.eq('parent_issue_id', req.query.parent_issue_id);
      }
    }
    
    const { data: issues, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    
    // Get user emails from profiles
    const userIds = new Set();
    issues.forEach(issue => {
      if (issue.assignee_id) userIds.add(issue.assignee_id);
      if (issue.reporter_id) userIds.add(issue.reporter_id);
    });
    
    const userIdsArray = Array.from(userIds);
    let profiles = {};
    if (userIdsArray.length > 0) {
      const { data: profilesData, error: profilesError } = await supabase
        .from('profiles')
        .select('id, email')
        .in('id', userIdsArray);
      
      if (!profilesError && profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    // Attach user info to issues
    const issuesWithUsers = issues.map(issue => ({
      ...issue,
      assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
      reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
    }));
    
    res.json(issuesWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/issues/:id', verifyToken, async (req, res) => {
  try {
    const { data: issue, error } = await supabase
      .from('issues')
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*),
        sprint:sprints(*)
      `)
      .eq('id', req.params.id)
      .single();
    if (error) throw error;

    // Load parent issue and subtasks with separate queries (avoid issues->issues schema cache error)
    let parent_issue = null;
    let subtasks = [];
    if (issue.parent_issue_id) {
      const { data: parent } = await supabase
        .from('issues')
        .select('id, issue_key, summary')
        .eq('id', issue.parent_issue_id)
        .single();
      parent_issue = parent;
    }
    const { data: subtasksData } = await supabase
      .from('issues')
      .select('id, issue_key, summary, status, internal_priority, client_priority')
      .eq('parent_issue_id', req.params.id);
    if (subtasksData) subtasks = subtasksData;

    // Get user emails from profiles
    const userIds = [];
    if (issue.assignee_id) userIds.push(issue.assignee_id);
    if (issue.reporter_id) userIds.push(issue.reporter_id);
    
    let profiles = {};
    if (userIds.length > 0) {
      const { data: profilesData, error: profilesError } = await supabase
        .from('profiles')
        .select('id, email')
        .in('id', userIds);
      
      if (!profilesError && profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    // Attach user info, parent, and subtasks
    const issueWithUsers = {
      ...issue,
      parent_issue,
      subtasks,
      assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
      reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
    };
    
    res.json(issueWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/issues', verifyToken, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    const {
      project_id,
      issue_type_id,
      summary,
      description,
      status,
      internal_priority,
      client_priority,
      priority, // backward compatibility
      assignee_id,
      sprint_id,
      release_id,
      parent_issue_id,
      story_points,
      labels,
      components,
      due_date,
      estimated_days,
      actual_days,
      exposed_to_client
    } = req.body;
    
    // Permission checks
    // Only team leaders can assign to others
    if (assignee_id && assignee_id !== req.user.id && userRole !== 'team_leader') {
      return res.status(403).json({ error: 'Only team leaders can assign issues to others' });
    }
    
    // Use priority for backward compatibility, but prefer internal_priority
    // Convert old priority values to P1-P5 if needed
    let finalInternalPriority = internal_priority || priority || 'P3';
    const priorityMap = {
      'highest': 'P1', 'high': 'P2', 'medium': 'P3', 'low': 'P4', 'lowest': 'P5'
    };
    if (priorityMap[finalInternalPriority]) {
      finalInternalPriority = priorityMap[finalInternalPriority];
    }
    
    const { data: issue, error } = await supabase
      .from('issues')
      .insert([{
        project_id,
        issue_type_id,
        summary,
        description,
        status: status || 'to_do',
        internal_priority: finalInternalPriority,
        client_priority: client_priority || null,
        assignee_id,
        reporter_id: req.user.id,
        sprint_id,
        release_id: release_id || null,
        parent_issue_id: parent_issue_id || null,
        story_points,
        labels: labels || [],
        components: components || [],
        due_date,
        estimated_days: estimated_days != null ? parseInt(estimated_days, 10) : null,
        actual_days: actual_days != null ? parseInt(actual_days, 10) : null,
        exposed_to_client: exposed_to_client === true || exposed_to_client === 'true'
      }])
      .select('*')
      .single();
    
    if (error) throw error;

    // Fetch project and issue_type with separate queries (avoids any schema cache issues)
    let project = null;
    let issue_type = null;
    const [{ data: projectData }, { data: issueTypeData }] = await Promise.all([
      supabase.from('projects').select('*').eq('id', issue.project_id).single(),
      supabase.from('issue_types').select('*').eq('id', issue.issue_type_id).single()
    ]);
    if (projectData) project = projectData;
    if (issueTypeData) issue_type = issueTypeData;
    const issueWithJoins = { ...issue, project, issue_type };
    
    // Get user emails from profiles
    const userIds = [];
    if (issueWithJoins.assignee_id) userIds.push(issueWithJoins.assignee_id);
    if (issueWithJoins.reporter_id) userIds.push(issueWithJoins.reporter_id);
    
    let profiles = {};
    if (userIds.length > 0) {
      const { data: profilesData } = await supabase
        .from('profiles')
        .select('id, email')
        .in('id', userIds);
      
      if (profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    // Get reporter email
    const { data: reporterProfile } = await supabase
      .from('profiles')
      .select('id, email')
      .eq('id', req.user.id)
      .single();
    
    const issueWithUsers = {
      ...issueWithJoins,
      assignee: issueWithJoins.assignee_id ? profiles[issueWithJoins.assignee_id] || { id: issueWithJoins.assignee_id, email: 'Unknown' } : null,
      reporter: reporterProfile || { id: req.user.id, email: req.user.email || 'Unknown' }
    };
    
    res.status(201).json(issueWithUsers);
  } catch (error) {
    const msg = error?.message || '';
    if (msg.includes('schema cache') || msg.includes("Could not find the")) {
      return res.status(500).json({
        error: msg,
        fix: 'Run database/ensure_issues_columns.sql in your Supabase SQL Editor, then reload schema cache or restart the backend.'
      });
    }
    res.status(500).json({ error: error.message });
  }
});

router.put('/issues/:id', verifyToken, async (req, res) => {
  try {
    const userRole = await getUserRole(req.user.id);
    
    // Get current issue to check permissions
    const { data: currentIssue, error: fetchError } = await supabase
      .from('issues')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (fetchError) throw fetchError;
    
    // Permission checks
    // Clients can only update client_priority and description
    if (userRole === 'client') {
      const allowedFields = ['client_priority', 'description'];
      const updateData = {};
      allowedFields.forEach(field => {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      });
      
      const { data: issue, error } = await supabase
        .from('issues')
        .update(updateData)
        .eq('id', req.params.id)
        .select(`
          *,
          project:projects(*),
          issue_type:issue_types(*)
        `)
        .single();
      
      if (error) throw error;
      
      // Get user emails
      const userIds = [];
      if (issue.assignee_id) userIds.push(issue.assignee_id);
      if (issue.reporter_id) userIds.push(issue.reporter_id);
      
      let profiles = {};
      if (userIds.length > 0) {
        const { data: profilesData } = await supabase
          .from('profiles')
          .select('id, email')
          .in('id', userIds);
        
        if (profilesData) {
          profilesData.forEach(profile => {
            profiles[profile.id] = profile;
          });
        }
      }
      
      const issueWithUsers = {
        ...issue,
        assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
        reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
      };
      
      return res.json(issueWithUsers);
    }
    
    // Team members can update internal_priority and status
    if (userRole === 'team_member') {
      const allowedFields = ['status', 'internal_priority'];
      const updateData = {};
      allowedFields.forEach(field => {
        if (req.body[field] !== undefined) {
          updateData[field] = req.body[field];
        }
      });
      
      // Can only update if assigned to them or created by them
      if (currentIssue.assignee_id !== req.user.id && currentIssue.reporter_id !== req.user.id) {
        return res.status(403).json({ error: 'You can only update issues assigned to you' });
      }
      
      const { data: issue, error } = await supabase
        .from('issues')
        .update(updateData)
        .eq('id', req.params.id)
        .select(`
          *,
          project:projects(*),
          issue_type:issue_types(*)
        `)
        .single();
      
      if (error) throw error;
      
      // Get user emails
      const userIds = [];
      if (issue.assignee_id) userIds.push(issue.assignee_id);
      if (issue.reporter_id) userIds.push(issue.reporter_id);
      
      let profiles = {};
      if (userIds.length > 0) {
        const { data: profilesData } = await supabase
          .from('profiles')
          .select('id, email')
          .in('id', userIds);
        
        if (profilesData) {
          profilesData.forEach(profile => {
            profiles[profile.id] = profile;
          });
        }
      }
      
      const issueWithUsers = {
        ...issue,
        assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
        reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
      };
      
      return res.json(issueWithUsers);
    }
    
    // Team leaders can update everything (no parent_issue join to avoid schema-cache errors)
    const priorityToLegacy = { P1: 'highest', P2: 'high', P3: 'medium', P4: 'low', P5: 'lowest' };
    const buildSafeUpdateBody = () => {
      const safe = {};
      if (req.body.summary !== undefined) safe.summary = req.body.summary;
      if (req.body.description !== undefined) safe.description = req.body.description;
      if (req.body.status !== undefined) safe.status = req.body.status;
      if (req.body.story_points !== undefined) safe.story_points = req.body.story_points;
      if (req.body.labels !== undefined) safe.labels = req.body.labels;
      if (req.body.due_date !== undefined) safe.due_date = req.body.due_date;
      if (req.body.estimated_days !== undefined) safe.estimated_days = req.body.estimated_days == null ? null : parseInt(req.body.estimated_days, 10);
      if (req.body.actual_days !== undefined) safe.actual_days = req.body.actual_days == null ? null : parseInt(req.body.actual_days, 10);
      if (req.body.exposed_to_client !== undefined) safe.exposed_to_client = req.body.exposed_to_client === true || req.body.exposed_to_client === 'true';
      const pri = req.body.internal_priority || req.body.priority;
      if (pri !== undefined) safe.priority = priorityToLegacy[pri] || pri;
      return safe;
    };

    let result = await supabase
      .from('issues')
      .update(req.body)
      .eq('id', req.params.id)
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*)
      `)
      .single();

    if (result.error && (result.error.message.includes('schema cache') || result.error.message.includes('client_priority') || result.error.message.includes('internal_priority') || result.error.message.includes('estimated_days') || result.error.message.includes('actual_days') || result.error.message.includes('exposed_to_client'))) {
      const safeBody = buildSafeUpdateBody();
      result = await supabase
        .from('issues')
        .update(safeBody)
        .eq('id', req.params.id)
        .select(`
          *,
          project:projects(*),
          issue_type:issue_types(*)
        `)
        .single();
    }

    const { data: issue, error } = result;
    if (error) throw error;

    // Get user emails from profiles
    const userIds = [];
    if (issue.assignee_id) userIds.push(issue.assignee_id);
    if (issue.reporter_id) userIds.push(issue.reporter_id);
    
    let profiles = {};
    if (userIds.length > 0) {
      const { data: profilesData } = await supabase
        .from('profiles')
        .select('id, email')
        .in('id', userIds);
      
      if (profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    const issueWithUsers = {
      ...issue,
      assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
      reporter: issue.reporter_id ? profiles[issue.reporter_id] || { id: issue.reporter_id, email: 'Unknown' } : null
    };
    
    res.json(issueWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.delete('/issues/:id', verifyToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('issues')
      .delete()
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Issue deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== SPRINTS ==========
router.get('/sprints', verifyToken, async (req, res) => {
  try {
    const { project_id, state } = req.query;
    let query = supabase
      .from('sprints')
      .select('*, project:projects(*)');
    
    if (project_id) query = query.eq('project_id', project_id);
    if (state) query = query.eq('state', state);
    
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== RELEASES ==========
router.get('/releases', verifyToken, async (req, res) => {
  try {
    const { project_id } = req.query;
    let query = supabase
      .from('releases')
      .select('*, project:projects(*)');
    
    if (project_id) query = query.eq('project_id', project_id);
    
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/releases', verifyToken, async (req, res) => {
  try {
    const { project_id, name, description, start_date, end_date, is_active } = req.body;
    const { data, error } = await supabase
      .from('releases')
      .insert([{
        project_id,
        name,
        description,
        start_date,
        end_date,
        is_active
      }])
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/sprints', verifyToken, async (req, res) => {
  try {
    const { project_id, name, goal, start_date, end_date, state } = req.body;
    const { data, error } = await supabase
      .from('sprints')
      .insert([{
        project_id,
        name,
        goal,
        start_date,
        end_date,
        state: state || 'future'
      }])
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== COMMENTS ==========
router.get('/issues/:issue_id/comments', verifyToken, async (req, res) => {
  try {
    const { data: comments, error } = await supabase
      .from('issue_comments')
      .select('*')
      .eq('issue_id', req.params.issue_id)
      .order('created_at', { ascending: true });
    if (error) throw error;
    
    // Get author emails from profiles
    const authorIds = comments.map(c => c.author_id);
    let profiles = {};
    if (authorIds.length > 0) {
      const { data: profilesData } = await supabase
        .from('profiles')
        .select('id, email')
        .in('id', authorIds);
      
      if (profilesData) {
        profilesData.forEach(profile => {
          profiles[profile.id] = profile;
        });
      }
    }
    
    const commentsWithAuthors = comments.map(comment => ({
      ...comment,
      author: profiles[comment.author_id] || { id: comment.author_id, email: 'Unknown' }
    }));
    
    res.json(commentsWithAuthors);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/issues/:issue_id/comments', verifyToken, async (req, res) => {
  try {
    const { body } = req.body;
    const { data: comment, error } = await supabase
      .from('issue_comments')
      .insert([{
        issue_id: req.params.issue_id,
        author_id: req.user.id,
        body
      }])
      .select('*')
      .single();
    if (error) throw error;
    
    // Get author email from profiles
    const { data: authorProfile } = await supabase
      .from('profiles')
      .select('id, email')
      .eq('id', req.user.id)
      .single();
    
    const commentWithAuthor = {
      ...comment,
      author: authorProfile || { id: req.user.id, email: req.user.email || 'Unknown' }
    };
    
    res.status(201).json(commentWithAuthor);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== CLIENTS ==========
router.get('/clients', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('clients')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/clients', verifyToken, async (req, res) => {
  try {
    const { name, email, company, phone, address, notes } = req.body;
    const { data, error } = await supabase
      .from('clients')
      .insert([{
        name,
        email,
        company,
        phone,
        address,
        notes,
        created_by: req.user.id
      }])
      .select()
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/clients/:id', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('clients')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/clients/:id', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('clients')
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

// ========== RELEASES ==========
router.get('/releases', verifyToken, async (req, res) => {
  try {
    const { project_id, is_active } = req.query;
    let query = supabase
      .from('releases')
      .select('*, project:projects(*)');
    
    if (project_id) query = query.eq('project_id', project_id);
    if (is_active !== undefined) query = query.eq('is_active', is_active === 'true');
    
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/releases', verifyToken, async (req, res) => {
  try {
    const { project_id, name, description, version, start_date, end_date, is_active } = req.body;
    const { data, error } = await supabase
      .from('releases')
      .insert([{
        project_id,
        name,
        description,
        version,
        start_date,
        end_date,
        is_active: is_active !== undefined ? is_active : true,
        created_by: req.user.id
      }])
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/releases/:id', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('releases')
      .select('*, project:projects(*)')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/releases/:id', verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('releases')
      .update(req.body)
      .eq('id', req.params.id)
      .select('*, project:projects(*)')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;

