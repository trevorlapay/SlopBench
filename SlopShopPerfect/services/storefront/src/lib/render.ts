const HTML_ESCAPES: ReadonlyMap<string, string> = new Map([
  ['&', '&amp;'],
  ['<', '&lt;'],
  ['>', '&gt;'],
  ['"', '&quot;'],
  ["'", '&#39;'],
  ['/', '&#47;'],
]);

/**
 * Escapes every character that is meaningful in HTML text or attribute value
 * position. Callers must not concatenate the result into unquoted attributes.
 */
export function escapeHtml(value: string): string {
  let out = '';
  for (const ch of value) {
    out += HTML_ESCAPES.get(ch) ?? ch;
  }
  return out;
}

/** Tagged template that escapes every interpolated value. */
export function html(strings: TemplateStringsArray, ...values: unknown[]): string {
  let out = strings.at(0) ?? '';
  values.forEach((value, index) => {
    out += escapeHtml(String(value));
    out += strings.at(index + 1) ?? '';
  });
  return out;
}

export function productCard(name: string, priceMinor: number, currency: string): string {
  const formatted = new Intl.NumberFormat('en-GB', {
    style: 'currency',
    currency,
  }).format(priceMinor / 100);
  return html`<li class="product"><h3>${name}</h3><p class="price">${formatted}</p></li>`;
}
