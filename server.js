import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jiraRouter from './jira_api.js';
import superadminRouter from './superadminRoutes.js';
import publicInviteRouter from './publicInviteRoutes.js';
import healthRouter from './routes/health.js';
import tasksRouter from './routes/tasks.js';
import meRouter from './routes/me.js';
import organizationsRouter from './routes/organizations.js';
import usersRouter from './routes/users.js';
import {
  refreshRoleAccessCache,
} from './accessConfig.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/api/public', publicInviteRouter);

// Structured routes (migrated out of server.js)
app.use('/api', healthRouter);
app.use('/api', tasksRouter);
app.use('/api', meRouter);
app.use('/api', organizationsRouter);
app.use('/api', usersRouter);

// Routes

// JIRA-like API routes
app.use('/api/jira', jiraRouter);
app.use('/api/superadmin', superadminRouter);

// (Removed) GET /api/organizations: was used for workspace switching.
// SuperAdmin uses /api/superadmin/organizations-overview instead.

// Startup log
console.log('Backend starting...');

async function startServer() {
  try {
    await refreshRoleAccessCache();
  } catch (err) {
    console.error('Failed to load role_access_config (using defaults):', err?.message || err);
  }
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();

