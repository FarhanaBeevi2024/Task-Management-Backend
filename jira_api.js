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

// ========== PROJECTS ==========
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
    const { key, name, description, lead_id } = req.body;
    const { data, error } = await supabase
      .from('projects')
      .insert([{
        key: key.toUpperCase(),
        name,
        description,
        lead_id: lead_id || req.user.id,
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
    const { project_id, sprint_id, status, assignee_id } = req.query;
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
    if (status) query = query.eq('status', status);
    if (assignee_id) query = query.eq('assignee_id', assignee_id);
    
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
    
    // Attach user info
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

router.post('/issues', verifyToken, async (req, res) => {
  try {
    const {
      project_id,
      issue_type_id,
      summary,
      description,
      status,
      priority,
      assignee_id,
      sprint_id,
      story_points,
      labels,
      components,
      due_date
    } = req.body;
    
    const { data: issue, error } = await supabase
      .from('issues')
      .insert([{
        project_id,
        issue_type_id,
        summary,
        description,
        status: status || 'to_do',
        priority: priority || 'medium',
        assignee_id,
        reporter_id: req.user.id,
        sprint_id,
        story_points,
        labels: labels || [],
        components: components || [],
        due_date
      }])
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*)
      `)
      .single();
    
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
    
    // Get reporter email
    const { data: reporterProfile } = await supabase
      .from('profiles')
      .select('id, email')
      .eq('id', req.user.id)
      .single();
    
    const issueWithUsers = {
      ...issue,
      assignee: issue.assignee_id ? profiles[issue.assignee_id] || { id: issue.assignee_id, email: 'Unknown' } : null,
      reporter: reporterProfile || { id: req.user.id, email: req.user.email || 'Unknown' }
    };
    
    res.status(201).json(issueWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/issues/:id', verifyToken, async (req, res) => {
  try {
    const { data: issue, error } = await supabase
      .from('issues')
      .update(req.body)
      .eq('id', req.params.id)
      .select(`
        *,
        project:projects(*),
        issue_type:issue_types(*)
      `)
      .single();
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

export default router;

