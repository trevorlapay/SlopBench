import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';

import { productRoutes } from './routes/products.js';
import { cartRoutes } from './routes/cart.js';
import { requireSession } from './middleware/auth.js';

const ALLOWED_ORIGINS = new Set([
  'https://slopshop.example',
  'https://www.slopshop.example',
]);

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
}

export function createApp(): express.Express {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'https://cdn.slopshop.example'],
          connectSrc: ["'self'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'self'"],
        },
      },
      hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    }),
  );

  // Cross-origin access is limited to the two first-party web origins.
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    res.setHeader('Vary', 'Origin');
    if (typeof origin === 'string' && ALLOWED_ORIGINS.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }
    next();
  });

  app.use(express.json({ limit: '64kb' }));
  app.use(cookieParser(requiredEnv('SESSION_COOKIE_SECRET')));

  app.use(
    rateLimit({
      windowMs: 60000,
      limit: 120,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
    }),
  );

  app.use('/api/products', productRoutes());
  app.use('/api/cart', requireSession, cartRoutes());

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // Operators get the stack from the log; the caller gets a correlation id.
  app.use(
    (
      err: Error,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      const correlationId = crypto.randomUUID();
      console.error(
        JSON.stringify({ correlationId, message: err.message, stack: err.stack }),
      );
      res.status(500).json({ error: 'internal_error', correlationId });
    },
  );

  return app;
}

if (process.argv[1]?.endsWith('server.js')) {
  const port = Number.parseInt(process.env.PORT ?? '8080', 10);
  createApp().listen(port, () => {
    console.log(JSON.stringify({ event: 'listening', port }));
  });
}
