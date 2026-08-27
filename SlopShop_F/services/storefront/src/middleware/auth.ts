import type { NextFunction, Request, Response } from 'express';
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

const SESSION_COOKIE = 'ss_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

export interface Session {
  readonly customerId: string;
  readonly issuedAt: number;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: Session;
    }
  }
}

function signingKey(): Buffer {
  const raw = process.env['SESSION_SIGNING_KEY'];
  if (raw === undefined || raw.length < 64) {
    throw new Error('SESSION_SIGNING_KEY must be at least 64 hex characters');
  }
  return Buffer.from(raw, 'hex');
}

function sign(payload: string): string {
  return createHmac('sha256', signingKey()).update(payload).digest('base64url');
}

/**
 * Encodes a session as `<base64url(json)>.<base64url(hmac)>`.
 */
export function issueSession(customerId: string): string {
  const payload = Buffer.from(
    JSON.stringify({ customerId, issuedAt: Date.now(), nonce: randomBytes(16).toString('hex') }),
  ).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

export function verifySession(cookie: string): Session | null {
  const separator = cookie.lastIndexOf('.');
  if (separator <= 0) {
    return null;
  }
  const payload = cookie.slice(0, separator);
  const presented = Buffer.from(cookie.slice(separator + 1), 'base64url');
  const expected = Buffer.from(sign(payload), 'base64url');

  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
    return null;
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  if (
    typeof decoded !== 'object' ||
    decoded === null ||
    typeof (decoded as Session).customerId !== 'string' ||
    typeof (decoded as Session).issuedAt !== 'number'
  ) {
    return null;
  }

  const session = decoded as Session;
  if (Date.now() - session.issuedAt > SESSION_TTL_MS) {
    return null;
  }
  return { customerId: session.customerId, issuedAt: session.issuedAt };
}

export function setSessionCookie(res: Response, customerId: string): void {
  res.cookie(SESSION_COOKIE, issueSession(customerId), {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_TTL_MS,
  });
}

export function requireSession(req: Request, res: Response, next: NextFunction): void {
  const cookies: unknown = req.cookies;
  const raw =
    typeof cookies === 'object' && cookies !== null && 'ss_session' in cookies
      ? (cookies as { ss_session?: unknown }).ss_session
      : undefined;
  const session = typeof raw === 'string' ? verifySession(raw) : null;
  if (session === null) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  req.session = session;
  next();
}
