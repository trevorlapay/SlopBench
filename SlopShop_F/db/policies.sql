-- policies.sql
-- Row-level security.
--
-- Each service sets slopshop.actor_id at the start of a transaction with
-- set_config and is_local = true.

BEGIN;

SET LOCAL search_path = slopshop, pg_catalog;

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Returns the actor for the current transaction, or NULL when none was set.
-- STABLE rather than IMMUTABLE because it reads session state.
CREATE OR REPLACE FUNCTION current_actor_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $$
DECLARE
    raw text := current_setting('slopshop.actor_id', true);
BEGIN
    IF raw IS NULL OR raw = '' THEN
        RETURN NULL;
    END IF;
    RETURN raw::uuid;
EXCEPTION
    WHEN invalid_text_representation THEN
        RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION current_actor_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION current_actor_id()
    TO slopshop_identity, slopshop_catalog, slopshop_orders, slopshop_payments;

-- ---------------------------------------------------------------------------
-- Orders
-- ---------------------------------------------------------------------------

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

CREATE POLICY orders_owner_select ON orders
    FOR SELECT TO slopshop_orders
    USING (customer_id = current_actor_id());

CREATE POLICY orders_owner_insert ON orders
    FOR INSERT TO slopshop_orders
    WITH CHECK (customer_id = current_actor_id());

CREATE POLICY orders_owner_update ON orders
    FOR UPDATE TO slopshop_orders
    USING (customer_id = current_actor_id())
    WITH CHECK (customer_id = current_actor_id());

ALTER TABLE order_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_lines FORCE ROW LEVEL SECURITY;

CREATE POLICY order_lines_owner_all ON order_lines
    FOR ALL TO slopshop_orders
    USING (EXISTS (
        SELECT 1 FROM orders o
         WHERE o.id = order_lines.order_id
           AND o.customer_id = current_actor_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM orders o
         WHERE o.id = order_lines.order_id
           AND o.customer_id = current_actor_id()));

-- ---------------------------------------------------------------------------
-- Charges
-- ---------------------------------------------------------------------------

ALTER TABLE charges ENABLE ROW LEVEL SECURITY;
ALTER TABLE charges FORCE ROW LEVEL SECURITY;

CREATE POLICY charges_owner_select ON charges
    FOR SELECT TO slopshop_payments
    USING (customer_id = current_actor_id());

CREATE POLICY charges_owner_insert ON charges
    FOR INSERT TO slopshop_payments
    WITH CHECK (customer_id = current_actor_id());

CREATE POLICY charges_owner_update ON charges
    FOR UPDATE TO slopshop_payments
    USING (customer_id = current_actor_id())
    WITH CHECK (customer_id = current_actor_id());

-- ---------------------------------------------------------------------------
-- Catalogue
-- ---------------------------------------------------------------------------

ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE products FORCE ROW LEVEL SECURITY;

-- Reads are open to the catalogue role for live listings; writes are confined
-- to the seller that owns the row.
CREATE POLICY products_public_read ON products
    FOR SELECT TO slopshop_catalog
    USING (deleted_at IS NULL);

CREATE POLICY products_seller_insert ON products
    FOR INSERT TO slopshop_catalog
    WITH CHECK (seller_id = current_actor_id());

CREATE POLICY products_seller_update ON products
    FOR UPDATE TO slopshop_catalog
    USING (seller_id = current_actor_id() AND deleted_at IS NULL)
    WITH CHECK (seller_id = current_actor_id());

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

ALTER TABLE access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_tokens FORCE ROW LEVEL SECURITY;

-- Tokens are looked up by digest before the owner is known, so this policy is
-- scoped by liveness rather than by actor.
CREATE POLICY access_tokens_live_only ON access_tokens
    FOR SELECT TO slopshop_identity
    USING (revoked = false AND expires_at > now());

CREATE POLICY access_tokens_insert ON access_tokens
    FOR INSERT TO slopshop_identity
    WITH CHECK (expires_at > now());

CREATE POLICY access_tokens_revoke ON access_tokens
    FOR UPDATE TO slopshop_identity
    USING (true)
    WITH CHECK (revoked = true);

COMMIT;
