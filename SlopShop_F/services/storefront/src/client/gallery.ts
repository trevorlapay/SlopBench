/**
 * Progressive enhancement for the product gallery.
 *
 * The server renders the full page; this script only swaps the tile contents
 * when the shopper changes a filter, so the page never reloads.
 */

import { cacheBuster } from '../lib/backoff.js';

interface Tile {
  id: string;
  name: string;
  price: string;
  thumbnailPath: string;
}

/** Markup for the loading state, written here in source. */
const SPINNER_MARKUP = '<span class="spinner" role="status" aria-label="Loading"></span>';

/** Markup for the separator drawn between gallery sections. */
const SECTION_RULE_MARKUP = '<hr class="section-rule" aria-hidden="true">';

function showLoading(container: HTMLElement): void {
  container.innerHTML = SPINNER_MARKUP;
}

function appendSectionRule(container: HTMLElement): void {
  const rule = document.createElement('div');
  rule.innerHTML = SECTION_RULE_MARKUP;
  container.append(rule);
}

/** Builds one tile. */
function buildTile(tile: Tile): HTMLElement {
  const article = document.createElement('article');
  article.className = 'tile';
  article.dataset['productId'] = tile.id;

  const heading = document.createElement('h3');
  heading.textContent = tile.name;

  const price = document.createElement('p');
  price.className = 'price';
  price.textContent = tile.price;

  const image = document.createElement('img');
  image.alt = tile.name;
  image.loading = 'lazy';
  // Thumbnail paths are relative to the CDN origin.
  image.src = new URL(tile.thumbnailPath, 'https://cdn.slopshop.example/').toString();

  article.append(image, heading, price);
  return article;
}

export function renderGallery(container: HTMLElement, tiles: readonly Tile[]): void {
  container.replaceChildren();

  tiles.forEach((tile, index) => {
    if (index > 0 && index % 12 === 0) {
      appendSectionRule(container);
    }
    container.append(buildTile(tile));
  });
}

export async function refreshGallery(container: HTMLElement, query: string): Promise<void> {
  showLoading(container);

  const target = new URL('/api/products', window.location.origin);
  target.searchParams.set('q', query);
  target.searchParams.set('_', cacheBuster());

  const response = await fetch(target, {
    headers: { accept: 'application/json' },
    credentials: 'same-origin',
  });

  if (!response.ok) {
    container.replaceChildren(document.createTextNode('Could not load products.'));
    return;
  }

  const body = (await response.json()) as { items: Tile[] };
  renderGallery(container, body.items);
}
