-- 0003_indexes.sql
-- Indexes supporting the access patterns the services actually issue.
--
-- Created CONCURRENTLY, so this migration runs outside a transaction block.

SET search_path = slopshop, pg_catalog;

-- Catalogue: full-text search over live listings only.
CREATE INDEX CONCURRENTLY IF NOT EXISTS products_search_vector_gin
    ON products USING gin (search_vector)
    WHERE deleted_at IS NULL;

-- Catalogue: the two price sorts the storefront offers.
CREATE INDEX CONCURRENTLY IF NOT EXISTS products_live_price_asc
    ON products (price_minor ASC, id ASC)
    WHERE deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS products_live_created_desc
    ON products (created_at DESC, id ASC)
    WHERE deleted_at IS NULL;

-- Catalogue: a seller's own listings.
CREATE INDEX CONCURRENTLY IF NOT EXISTS products_by_seller
    ON products (seller_id, created_at DESC)
    WHERE deleted_at IS NULL;

-- Identity: token lookup is by digest, which is already the primary key. What
-- is needed additionally is the expiry sweep and the per-account revocation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS access_tokens_live_by_account
    ON access_tokens (account_id)
    WHERE revoked = false;

CREATE INDEX CONCURRENTLY IF NOT EXISTS access_tokens_expiry
    ON access_tokens (expires_at)
    WHERE revoked = false;

-- Orders: every read is scoped to one customer, so the customer id leads.
CREATE INDEX CONCURRENTLY IF NOT EXISTS orders_by_customer_created
    ON orders (customer_id, created_at DESC, id ASC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS orders_by_customer_total
    ON orders (customer_id, total_minor DESC, id ASC);

-- Orders: the fulfilment queue looks at open orders by age.
CREATE INDEX CONCURRENTLY IF NOT EXISTS orders_open_by_age
    ON orders (created_at ASC)
    WHERE status IN ('PENDING', 'AUTHORISED', 'FULFILLING');

CREATE INDEX CONCURRENTLY IF NOT EXISTS order_lines_by_product
    ON order_lines (product_id);

-- Payments: reconciliation walks charges by order, and by day for reporting.
CREATE INDEX CONCURRENTLY IF NOT EXISTS charges_by_order
    ON charges (order_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS charges_by_customer_created
    ON charges (customer_id, created_at DESC);
