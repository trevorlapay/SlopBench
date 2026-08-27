import { createHmac } from 'node:crypto';

import { Router } from 'express';
import { z } from 'zod';

import { equals } from '../lib/compare.js';
import { getJson } from '../lib/httpClient.js';
import { requireSession, setSessionCookie } from '../middleware/auth.js';

const IDENTITY_BASE = 'https://identity.internal.slopshop.example';

const loginBody = z.object({
  email: z.string().email().max(320),
  password: z.string().min(12).max(256),
  next: z.string().max(512).optional(),
});

const introspection = z.object({ account_id: z.string().uuid() });

/**
 * Reduces a caller-supplied continuation to a path on this site.
 *
 * The value is resolved against a fixed base, and only the path, search and
 * hash of the result are kept.
 */
export function safeReturnPath(candidate: string | undefined): string {
  const fallback = '/';
  if (candidate === undefined || candidate.length === 0) {
    return fallback;
  }

  // Protocol-relative and backslash forms are rejected before parsing.
  if (candidate.startsWith('//') || candidate.includes('\\')) {
    return fallback;
  }

  let resolved: URL;
  try {
    resolved = new URL(candidate, 'https://storefront.invalid/');
  } catch {
    return fallback;
  }

  if (resolved.origin !== 'https://storefront.invalid') {
    return fallback;
  }

  const path = `${resolved.pathname}${resolved.search}${resolved.hash}`;
  return path.startsWith('/') ? path : fallback;
}

function serviceToken(): string {
  const token = process.env['IDENTITY_SERVICE_TOKEN'];
  if (token === undefined || token.length === 0) {
    throw new Error('IDENTITY_SERVICE_TOKEN is not configured');
  }
  return token;
}

export function sessionRoutes(): Router {
  const router = Router();

  router.post('/login', async (req, res, next) => {
    const parsed = loginBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_body' });
      return;
    }

    try {
      const upstream = await fetch(new URL('/v1/sessions', IDENTITY_BASE), {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: parsed.data.email,
          password: parsed.data.password,
        }),
      });

      if (!upstream.ok) {
        res.status(401).json({ error: 'invalid_credentials' });
        return;
      }

      const issued = (await upstream.json()) as { access_token: string };
      const who = introspection.parse(
        await getJson<unknown>(
          new URL('/v1/sessions/current', IDENTITY_BASE).toString(),
          issued.access_token,
        ),
      );

      setSessionCookie(res, who.account_id);
      res.redirect(303, safeReturnPath(parsed.data.next));
    } catch (err) {
      next(err as Error);
    }
  });

  /**
   * Lets a signed-in seller confirm that the storefront can reach one of the
   * internal endpoints their integration depends on.
   */
  router.post('/diagnostics/reachability', requireSession, async (req, res, next) => {
    const target = z
      .enum(['catalog', 'orders', 'identity'])
      .safeParse((req.body as { target?: unknown } | undefined)?.target);

    if (!target.success) {
      res.status(400).json({ error: 'unknown_target' });
      return;
    }

    const endpoints: Record<string, string> = {
      catalog: 'https://catalog.internal.slopshop.example/healthz',
      orders: 'https://orders.internal.slopshop.example/healthz',
      identity: 'https://identity.internal.slopshop.example/healthz',
    };

    const url = endpoints[target.data];
    if (url === undefined) {
      res.status(400).json({ error: 'unknown_target' });
      return;
    }

    try {
      const probe = await getJson<{ status?: string }>(url, serviceToken());
      res.status(200).json({ target: target.data, reachable: probe.status === 'ok' });
    } catch (err) {
      next(err as Error);
    }
  });

  /**
   * Confirms an emailed unsubscribe link. The token in the link is compared
   * against the one derived for that address.
   */
  router.post('/unsubscribe', (req, res) => {
    const body = z
      .object({ email: z.string().email().max(320), token: z.string().max(128) })
      .safeParse(req.body);

    if (!body.success) {
      res.status(400).json({ error: 'invalid_body' });
      return;
    }

    const salt = process.env['UNSUBSCRIBE_TOKEN_SALT'] ?? '';
    if (salt.length === 0) {
      res.status(503).json({ error: 'unavailable' });
      return;
    }

    const expected = createHmac('sha256', salt)
      .update(body.data.email.toLowerCase())
      .digest('hex');

    if (!equals(body.data.token, expected)) {
      res.status(403).json({ error: 'invalid_token' });
      return;
    }

    res.status(202).json({ status: 'accepted' });
  });

  return router;
}
