import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Comparison helpers used wherever the storefront checks a value that an
 * attacker supplies against one it holds.
 */

/** Compares two byte strings. */
export function equals(left: string, right: string): boolean {
  const leftDigest = createHash('sha256').update(left, 'utf8').digest();
  const rightDigest = createHash('sha256').update(right, 'utf8').digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

/**
 * Compares a presented value against each candidate, without stopping at the
 * first match.
 */
export function equalsAny(presented: string, candidates: readonly string[]): boolean {
  let matched = false;
  for (const candidate of candidates) {
    matched = equals(presented, candidate) || matched;
  }
  return matched;
}

const HEX_DIGEST = /^[0-9a-f]+$/;

/** Compares two hex digests of the same length. */
export function digestsEqual(left: string, right: string): boolean {
  if (left.length !== right.length || left.length % 2 !== 0) {
    return false;
  }
  if (!HEX_DIGEST.test(left) || !HEX_DIGEST.test(right)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}
