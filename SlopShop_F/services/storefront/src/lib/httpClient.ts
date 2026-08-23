import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** Hosts this service is permitted to call. */
const ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  'catalog.internal.slopshop.example',
  'orders.internal.slopshop.example',
  'identity.internal.slopshop.example',
]);

const REQUEST_TIMEOUT_MS = 5000;

function isPrivateAddress(address: string): boolean {
  if (isIP(address) === 6) {
    const normalised = address.toLowerCase();
    return (
      normalised === '::1' ||
      normalised.startsWith('fc') ||
      normalised.startsWith('fd') ||
      normalised.startsWith('fe80') ||
      normalised.startsWith('::ffff:')
    );
  }

  const octets = address.split('.').map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o))) {
    return true;
  }
  const [a = 0, b = 0] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
  );
}

export class DisallowedHostError extends Error {}

/**
 * Performs a GET against an internal service. The host must appear in the
 * allow list and must resolve to a routable address.
 */
export async function getJson<T>(url: string, bearer: string): Promise<T> {
  const parsed = new URL(url);

  if (parsed.protocol !== 'https:') {
    throw new DisallowedHostError(`refusing non-https scheme: ${parsed.protocol}`);
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new DisallowedHostError(`host not permitted: ${parsed.hostname}`);
  }

  const resolved = await lookup(parsed.hostname, { all: true });
  if (resolved.length === 0 || resolved.some((entry) => isPrivateAddress(entry.address))) {
    throw new DisallowedHostError(`host resolves to a non-routable address: ${parsed.hostname}`);
  }

  const response = await fetch(parsed, {
    method: 'GET',
    redirect: 'error',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${bearer}`,
    },
  });

  if (!response.ok) {
    throw new Error(`upstream ${parsed.hostname} returned ${response.status}`);
  }
  return (await response.json()) as T;
}
