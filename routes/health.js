import express from 'express';

const router = express.Router();

router.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

router.get('/test-log', (_req, res) => {
  console.log('Test route hit');
  res.json({ status: 'ok', message: 'Logging works!' });
});

export default router;

