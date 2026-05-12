import { Router, Request, Response } from 'express';
import { readFileSync } from 'fs';
import { join } from 'path';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

// Parse the mock events file once at module load time.
// readFileSync is blocking — keeping it here (startup) rather than inside the
// route handler avoids blocking the event loop on every authenticated request.
// If the file is missing the server will fail loudly at startup, which is the
// correct behaviour (fail fast rather than serving silent 500s at runtime).
const events = JSON.parse(
  readFileSync(join(process.cwd(), 'data', 'mock_events.json'), 'utf-8')
);

// GET /api/events: Return the pre-loaded event list.
// Protected with requireAuth — all authenticated roles may view events.
router.get('/', requireAuth, (_req: Request, res: Response) => {
  res.json(events);
});

export default router;
