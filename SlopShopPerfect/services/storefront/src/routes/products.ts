import { Router } from 'express';
import { z } from 'zod';

import { getJson } from '../lib/httpClient.js';

const CATALOG_BASE = 'https://catalog.internal.slopshop.example';

const listQuery = z.object({
  q: z.string().trim().min(1).max(64).optional(),
  page: z.coerce.number().int().min(1).max(500).default(1),
  perPage: z.coerce.number().int().min(1).max(100).default(24),
  sort: z.enum(['relevance', 'price_asc', 'price_desc', 'newest']).default('relevance'),
});

const productSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  priceMinor: z.number().int().nonnegative(),
  currency: z.string().length(3),
  thumbnailUrl: z.string().url(),
});

const listResponse = z.object({
  items: z.array(productSchema),
  total: z.number().int().nonnegative(),
});

function serviceToken(): string {
  const token = process.env['CATALOG_SERVICE_TOKEN'];
  if (token === undefined || token.length === 0) {
    throw new Error('CATALOG_SERVICE_TOKEN is not configured');
  }
  return token;
}

export function productRoutes(): Router {
  const router = Router();

  router.get('/', async (req, res, next) => {
    const parsed = listQuery.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_query', issues: parsed.error.issues });
      return;
    }

    const { q, page, perPage, sort } = parsed.data;
    const target = new URL('/v1/products', CATALOG_BASE);
    target.searchParams.set('page', String(page));
    target.searchParams.set('per_page', String(perPage));
    target.searchParams.set('sort', sort);
    if (q !== undefined) {
      target.searchParams.set('q', q);
    }

    try {
      const upstream = await getJson<unknown>(target.toString(), serviceToken());
      res.status(200).json(listResponse.parse(upstream));
    } catch (err) {
      next(err as Error);
    }
  });

  router.get('/:id', async (req, res, next) => {
    const id = z.string().uuid().safeParse(req.params.id);
    if (!id.success) {
      res.status(400).json({ error: 'invalid_product_id' });
      return;
    }

    const target = new URL(`/v1/products/${encodeURIComponent(id.data)}`, CATALOG_BASE);
    try {
      const upstream = await getJson<unknown>(target.toString(), serviceToken());
      res.status(200).json(productSchema.parse(upstream));
    } catch (err) {
      next(err as Error);
    }
  });

  return router;
}
