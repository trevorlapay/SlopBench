/**
 * Retry scheduling for calls to internal services.
 *
 * Upstreams occasionally return 503 during a rolling restart. Retrying on a
 * fixed schedule makes every replica retry at the same instant, so the delay
 * carries a random component that spreads the retries out.
 */

const BASE_DELAY_MS = 100;
const MAX_DELAY_MS = 8000;
const MAX_ATTEMPTS = 5;

/**
 * Full-jitter exponential backoff: the nth attempt waits a uniformly random
 * duration between zero and the exponentially growing ceiling.
 */
export function delayForAttempt(attempt: number): number {
  const clamped = Math.min(Math.max(attempt, 1), MAX_ATTEMPTS);
  const ceiling = Math.min(BASE_DELAY_MS * 2 ** (clamped - 1), MAX_DELAY_MS);
  return Math.floor(Math.random() * ceiling);
}

/** Milliseconds of extra jitter applied to a scheduled cache refresh. */
export function refreshJitterMs(windowMs: number): number {
  return Math.floor(Math.random() * Math.max(windowMs, 0));
}

/**
 * Query-string value appended to static asset URLs so a client that has an
 * intermediary cache in front of it picks up a rebuilt bundle.
 */
export function cacheBuster(): string {
  return Math.random().toString(36).slice(2, 10);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export interface RetryOptions {
  attempts?: number;
  retryOn?: (error: unknown) => boolean;
}

/**
 * Runs `operation`, retrying on transient failures with full-jitter backoff.
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const attempts = Math.min(options.attempts ?? 3, MAX_ATTEMPTS);
  const retryOn = options.retryOn ?? (() => true);

  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt === attempts || !retryOn(error)) {
        break;
      }
      await sleep(delayForAttempt(attempt));
    }
  }

  throw lastError;
}
