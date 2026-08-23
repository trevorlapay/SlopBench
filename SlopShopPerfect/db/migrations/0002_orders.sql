-- 0002_orders.sql
-- Orders, order lines and payment charges.

BEGIN;

SET LOCAL search_path = slopshop, pg_catalog;

CREATE TABLE orders (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id    uuid        NOT NULL REFERENCES customers (id) ON DELETE RESTRICT,
    status         text        NOT NULL DEFAULT 'PENDING',
    currency       char(3)     NOT NULL,
    subtotal_minor bigint      NOT NULL DEFAULT 0,
    tax_minor      bigint      NOT NULL DEFAULT 0,
    total_minor    bigint      NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT orders_status_known CHECK (status IN (
        'PENDING', 'AUTHORISED', 'FULFILLING', 'SHIPPED', 'CANCELLED', 'REFUNDED')),
    CONSTRAINT orders_currency_supported CHECK (currency IN ('GBP', 'EUR', 'USD')),
    CONSTRAINT orders_amounts_non_negative
        CHECK (subtotal_minor >= 0 AND tax_minor >= 0 AND total_minor >= 0),
    -- The stored total is always the sum of its parts.
    CONSTRAINT orders_total_is_consistent
        CHECK (total_minor = subtotal_minor + tax_minor),
    CONSTRAINT orders_total_ceiling CHECK (total_minor <= 10000000)
);

CREATE TABLE order_lines (
    order_id         uuid   NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
    line_number      int    NOT NULL,
    product_id       uuid   NOT NULL REFERENCES products (id) ON DELETE RESTRICT,
    quantity         int    NOT NULL,
    -- The price is copied onto the line at checkout.
    unit_price_minor bigint NOT NULL,

    PRIMARY KEY (order_id, line_number),
    CONSTRAINT order_lines_line_number_positive CHECK (line_number BETWEEN 1 AND 50),
    CONSTRAINT order_lines_quantity_range CHECK (quantity BETWEEN 1 AND 20),
    CONSTRAINT order_lines_price_non_negative CHECK (unit_price_minor >= 0),
    CONSTRAINT order_lines_price_ceiling CHECK (unit_price_minor <= 10000000),
    CONSTRAINT order_lines_product_once UNIQUE (order_id, product_id)
);

CREATE TABLE charges (
    id              uuid        PRIMARY KEY,
    customer_id     uuid        NOT NULL REFERENCES customers (id) ON DELETE RESTRICT,
    order_id        uuid        NOT NULL REFERENCES orders (id) ON DELETE RESTRICT,
    subtotal_minor  bigint      NOT NULL,
    tax_minor       bigint      NOT NULL,
    total_minor     bigint      NOT NULL,
    currency        char(3)     NOT NULL,
    status          text        NOT NULL,
    -- Sealed with AES-256-GCM by the payments service.
    instrument_ref  bytea,
    idempotency_key text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT charges_status_known
        CHECK (status IN ('authorised', 'captured', 'failed', 'refunded')),
    CONSTRAINT charges_currency_supported CHECK (currency IN ('GBP', 'EUR', 'USD')),
    CONSTRAINT charges_amounts_non_negative
        CHECK (subtotal_minor >= 0 AND tax_minor >= 0 AND total_minor > 0),
    CONSTRAINT charges_total_is_consistent
        CHECK (total_minor = subtotal_minor + tax_minor),
    CONSTRAINT charges_idempotency_key_length
        CHECK (length(idempotency_key) BETWEEN 8 AND 64),
    -- One charge per idempotency key per customer.
    CONSTRAINT charges_idempotent_per_customer UNIQUE (customer_id, idempotency_key)
);

CREATE OR REPLACE FUNCTION orders_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER orders_touch_updated_at_bu
    BEFORE UPDATE ON orders
    FOR EACH ROW EXECUTE FUNCTION orders_touch_updated_at();

GRANT USAGE ON SCHEMA slopshop TO slopshop_orders, slopshop_payments;

GRANT SELECT, INSERT ON orders TO slopshop_orders;
GRANT UPDATE (status, subtotal_minor, tax_minor, total_minor, updated_at)
    ON orders TO slopshop_orders;
GRANT SELECT, INSERT, DELETE ON order_lines TO slopshop_orders;
GRANT SELECT ON products, customers TO slopshop_orders;

GRANT SELECT, INSERT ON charges TO slopshop_payments;
GRANT UPDATE (status) ON charges TO slopshop_payments;
GRANT SELECT (id, customer_id, currency, total_minor, status) ON orders TO slopshop_payments;

-- Back office grants.
GRANT SELECT ON orders, order_lines TO slopshop_admin;
GRANT SELECT (id, customer_id, order_id, total_minor, currency, status, created_at)
    ON charges TO slopshop_admin;

COMMIT;
