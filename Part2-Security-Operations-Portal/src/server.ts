import express, { type Request, type Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import authRoutes from './routes/auth.js';
import eventsRoutes from './routes/events.js';
import usersRoutes from './routes/users.js';

const app = express();

// Limit repeated requests to reduce brute-force and abuse.
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

app.use(globalLimiter);

// Secure HTTP headers help mitigate common web vulnerabilities.
app.use(helmet());

// Allow only the trusted frontend origin and include credentials for cookie auth.
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }),
);

// Limit body payload size to prevent large payload abuse.
app.use(express.json({ limit: '10kb' }));

// Parse cookies so authentication middleware can access HttpOnly cookies safely.
app.use(cookieParser());

// Mount authentication routes under /api/auth for organized API structure.
app.use('/api/auth', authRoutes);

// Mount events routes under /api/events.
app.use('/api/events', eventsRoutes);

// Mount users routes under /api/users.
app.use('/api/users', usersRoutes);

app.get('/health', (_req: Request, res: Response) => {
  return res.json({ status: 'ok' });
});

const PORT = Number(process.env.PORT ?? 4000);
app.listen(PORT, () => {
  // The server uses cookie-based auth and strict CORS for frontend access.
  console.log(`Backend running on http://localhost:${PORT}`);
});
