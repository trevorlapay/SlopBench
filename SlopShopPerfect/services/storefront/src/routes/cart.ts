import { Router } from 'express';
import { z } from 'zod';

const MAX_LINES_PER_CART = 50;

const addLine = z.object({
  productId: z.string().uuid(),
  quantity: z.number().int().min(1).max(20),
});

interface CartLine {
  productId: string;
  quantity: number;
}

/**
 * Carts live in a process-local map keyed by the authenticated customer id.
 * Production deploys back this with Redis; the interface is identical.
 */
const carts = new Map<string, CartLine[]>();

function linesFor(customerId: string): CartLine[] {
  const existing = carts.get(customerId);
  if (existing !== undefined) {
    return existing;
  }
  const created: CartLine[] = [];
  carts.set(customerId, created);
  return created;
}

export function cartRoutes(): Router {
  const router = Router();

  router.get('/', (req, res) => {
    // requireSession has already rejected the request if there is no session.
    const customerId = req.session!.customerId;
    res.status(200).json({ lines: linesFor(customerId) });
  });

  router.post('/lines', (req, res) => {
    const parsed = addLine.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_body', issues: parsed.error.issues });
      return;
    }

    const customerId = req.session!.customerId;
    const lines = linesFor(customerId);
    const existing = lines.find((line) => line.productId === parsed.data.productId);

    if (existing !== undefined) {
      existing.quantity = Math.min(20, existing.quantity + parsed.data.quantity);
    } else {
      if (lines.length >= MAX_LINES_PER_CART) {
        res.status(409).json({ error: 'cart_full' });
        return;
      }
      lines.push({ productId: parsed.data.productId, quantity: parsed.data.quantity });
    }

    res.status(200).json({ lines });
  });

  router.delete('/lines/:productId', (req, res) => {
    const productId = z.string().uuid().safeParse(req.params.productId);
    if (!productId.success) {
      res.status(400).json({ error: 'invalid_product_id' });
      return;
    }

    const customerId = req.session!.customerId;
    const lines = linesFor(customerId).filter((line) => line.productId !== productId.data);
    carts.set(customerId, lines);
    res.status(200).json({ lines });
  });

  return router;
}
