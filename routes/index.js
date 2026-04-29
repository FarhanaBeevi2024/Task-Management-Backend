import express from 'express';

import healthRouter from './health.js';
import tasksRouter from './tasks.js';
import meRouter from './me.js';
import organizationsRouter from './organizations.js';
import usersRouter from './users.js';

const router = express.Router();

// Base API routes
router.use(healthRouter);
router.use(tasksRouter);
router.use(meRouter);
router.use(organizationsRouter);
router.use(usersRouter);

export default router;

