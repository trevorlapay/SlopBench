-- 0001_init.sql
-- Accounts, customers, sellers and the product catalogue.
--
-- Runs as the migration role. Application roles are granted the privileges
-- named at the bottom of this file.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS slopshop;
SET LOCAL search_path = slopshop, pg_catalog;

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

CREATE TABLE accounts (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         citext      NOT NULL,
    -- Argon2id encoded hash produced by the identity service.
    password_hash text        NOT NULL,
    is_active     boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT accounts_email_unique UNIQUE (email),
    CONSTRAINT accounts_password_hash_is_argon2id
        CHECK (password_hash LIKE '$argon2id$%'),
    CONSTRAINT accounts_email_shape
        CHECK (length(email) BETWEEN 3 AND 320 AND position('@' IN email) > 1)
);

CREATE TABLE access_tokens (
    -- SHA-256 of the bearer token.
    digest     char(64)    PRIMARY KEY,
    account_id uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    revoked    boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT access_tokens_digest_is_hex CHECK (digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT access_tokens_expiry_in_future CHECK (expires_at > created_at)
);

CREATE TABLE customers (
    id           uuid        PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    display_name text        NOT NULL,
    country_code char(2)     NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT customers_display_name_length CHECK (length(display_name) BETWEEN 1 AND 100),
    CONSTRAINT customers_country_code_shape CHECK (country_code ~ '^[A-Z]{2}$')
);

CREATE TABLE sellers (
    id            uuid        PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    trading_name  text        NOT NULL,
    payout_status text        NOT NULL DEFAULT 'pending',
    created_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sellers_trading_name_length CHECK (length(trading_name) BETWEEN 1 AND 200),
    CONSTRAINT sellers_payout_status_known
        CHECK (payout_status IN ('pending', 'active', 'suspended'))
);

-- ---------------------------------------------------------------------------
-- Catalogue
-- ---------------------------------------------------------------------------

CREATE TABLE products (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id     uuid        NOT NULL REFERENCES sellers (id) ON DELETE RESTRICT,
    name          text        NOT NULL,
    description   text        NOT NULL DEFAULT '',
    price_minor   bigint      NOT NULL,
    currency      char(3)     NOT NULL,
    availability  text        NOT NULL DEFAULT 'in_stock',
    thumbnail_url text        NOT NULL,
    search_vector tsvector,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    deleted_at    timestamptz,

    CONSTRAINT products_name_length CHECK (length(name) BETWEEN 1 AND 200),
    CONSTRAINT products_description_length CHECK (length(description) <= 4000),
    CONSTRAINT products_price_non_negative CHECK (price_minor >= 0),
    CONSTRAINT products_price_ceiling CHECK (price_minor <= 10000000),
    CONSTRAINT products_currency_supported CHECK (currency IN ('GBP', 'EUR', 'USD')),
    CONSTRAINT products_availability_known
        CHECK (availability IN ('in_stock', 'backorder', 'discontinued')),
    CONSTRAINT products_thumbnail_is_https CHECK (thumbnail_url LIKE 'https://%')
);

-- The search vector is maintained by the database rather than by any writer.
CREATE OR REPLACE FUNCTION products_refresh_search_vector()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    NEW.search_vector :=
        setweight(to_tsvector('english', coalesce(NEW.name, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(NEW.description, '')), 'B');
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER products_search_vector_biu
    BEFORE INSERT OR UPDATE OF name, description ON products
    FOR EACH ROW EXECUTE FUNCTION products_refresh_search_vector();

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------

-- Each service connects as its own role and receives only the verbs it uses.

REVOKE ALL ON SCHEMA slopshop FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA slopshop FROM PUBLIC;

GRANT USAGE ON SCHEMA slopshop TO slopshop_identity, slopshop_catalog, slopshop_admin;

GRANT SELECT, INSERT, UPDATE (password_hash, is_active, updated_at)
    ON accounts TO slopshop_identity;
GRANT SELECT, INSERT, UPDATE (revoked) ON access_tokens TO slopshop_identity;
GRANT SELECT, INSERT ON customers TO slopshop_identity;

GRANT SELECT ON products TO slopshop_catalog;
GRANT INSERT, UPDATE (name, description, price_minor, availability, thumbnail_url, updated_at)
    ON products TO slopshop_catalog;
GRANT SELECT ON sellers TO slopshop_catalog;

-- Back office grants.
GRANT SELECT (id, email, is_active, created_at) ON accounts TO slopshop_admin;
GRANT SELECT ON customers, sellers, products TO slopshop_admin;

COMMIT;
