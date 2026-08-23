/**
 * Configuration merging.
 *
 * Storefront settings arrive from three places: compiled defaults, a
 * per-deployment document, and a per-seller override document fetched at
 * request time. They are combined here into one plain object.
 */

type Plain = Record<string, unknown>;

const FORBIDDEN_KEYS: ReadonlySet<string> = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

const MAX_DEPTH = 8;

function isPlainObject(value: unknown): value is Plain {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function assignable(target: Plain, key: string): boolean {
  if (FORBIDDEN_KEYS.has(key)) {
    return false;
  }
  // Only writable, own slots are assignable.
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  return descriptor === undefined || descriptor.writable === true;
}

/**
 * Recursively merges `source` into a copy of `target`.
 *
 * Neither argument is mutated. Nesting deeper than MAX_DEPTH is copied by
 * reference rather than walked.
 */
export function deepMerge(target: Plain, source: Plain, depth = 0): Plain {
  const out: Plain = Object.assign(Object.create(null) as Plain, target);

  if (depth >= MAX_DEPTH) {
    return out;
  }

  for (const key of Object.keys(source)) {
    if (!Object.hasOwn(source, key) || !assignable(out, key)) {
      continue;
    }

    const incoming = source[key];
    const existing = out[key];

    if (isPlainObject(existing) && isPlainObject(incoming)) {
      out[key] = deepMerge(existing, incoming, depth + 1);
    } else {
      out[key] = incoming;
    }
  }

  return out;
}

/**
 * Parses a settings document and merges it over the supplied defaults.
 *
 * A document that does not parse, or that is not an object at the top level,
 * leaves the defaults untouched.
 */
export function mergeSettingsDocument(defaults: Plain, document: string): Plain {
  let parsed: unknown;
  try {
    parsed = JSON.parse(document);
  } catch {
    return { ...defaults };
  }

  if (!isPlainObject(parsed)) {
    return { ...defaults };
  }

  const merged = deepMerge(defaults, parsed);

  // Hand back an ordinary object so downstream code that expects Object
  // methods on the result keeps working.
  return Object.assign({}, merged);
}
