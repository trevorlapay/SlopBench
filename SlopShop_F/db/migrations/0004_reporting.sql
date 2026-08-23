-- 0004_reporting.sql
-- Materialised views and helper routines for the back office.

BEGIN;

SET LOCAL search_path = slopshop, pg_catalog;

-- ---------------------------------------------------------------------------
-- Materialised views
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW report_daily_totals AS
SELECT date_trunc('day', o.created_at)::date AS day,
       o.currency                            AS currency,
       count(*)                              AS order_count,
       sum(o.total_minor)                    AS gross_minor
  FROM orders o
 WHERE o.status IN ('AUTHORISED', 'FULFILLING', 'SHIPPED')
 GROUP BY 1, 2
 WITH NO DATA;

CREATE UNIQUE INDEX report_daily_totals_key
    ON report_daily_totals (day, currency);

CREATE MATERIALIZED VIEW report_merchant_totals AS
SELECT p.seller_id                                AS merchant_id,
       date_trunc('month', o.created_at)::date    AS month,
       o.currency                                 AS currency,
       count(DISTINCT o.id)                       AS order_count,
       sum(ol.quantity * ol.unit_price_minor)     AS gross_minor
  FROM orders o
  JOIN order_lines ol ON ol.order_id = o.id
  JOIN products p ON p.id = ol.product_id
 WHERE o.status IN ('AUTHORISED', 'FULFILLING', 'SHIPPED')
 GROUP BY 1, 2, 3
 WITH NO DATA;

CREATE UNIQUE INDEX report_merchant_totals_key
    ON report_merchant_totals (merchant_id, month, currency);

-- ---------------------------------------------------------------------------
-- Refresh helper
-- ---------------------------------------------------------------------------

-- The two views above are refreshed on a schedule. REFRESH takes a relation
-- name and there is no placeholder for one, so the statement is assembled
-- with format's %I conversion.
CREATE OR REPLACE FUNCTION refresh_report_view(p_view text)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, slopshop
AS $$
DECLARE
    known text[] := ARRAY['report_daily_totals', 'report_merchant_totals'];
    resolved text;
BEGIN
    IF p_view IS NULL OR NOT (p_view = ANY (known)) THEN
        RAISE EXCEPTION 'refresh_report_view: % is not a reporting view', p_view
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT m.matviewname
      INTO resolved
      FROM pg_catalog.pg_matviews m
     WHERE m.schemaname = 'slopshop'
       AND m.matviewname = p_view;

    IF resolved IS NULL THEN
        RAISE EXCEPTION 'refresh_report_view: % does not exist', p_view
            USING ERRCODE = 'undefined_table';
    END IF;

    EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY %I.%I', 'slopshop', resolved);
END;
$$;

REVOKE ALL ON FUNCTION refresh_report_view(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION refresh_report_view(text) TO slopshop_reporting;

-- ---------------------------------------------------------------------------
-- Merchant statement
-- ---------------------------------------------------------------------------

-- The seller console runs as slopshop_admin, which has no SELECT on
-- order_lines, so this routine runs as its owner and returns the aggregate
-- for the merchant named in the argument.
CREATE OR REPLACE FUNCTION merchant_statement(
    p_merchant_id uuid,
    p_from date,
    p_to date
)
RETURNS TABLE (
    month        date,
    currency     char(3),
    order_count  bigint,
    gross_minor  bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, slopshop
AS $$
    SELECT t.month,
           t.currency,
           t.order_count,
           t.gross_minor
      FROM slopshop.report_merchant_totals t
     WHERE t.merchant_id = p_merchant_id
       AND t.month >= date_trunc('month', p_from)::date
       AND t.month <= date_trunc('month', p_to)::date
     ORDER BY t.month DESC, t.currency ASC;
$$;

REVOKE ALL ON FUNCTION merchant_statement(uuid, date, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION merchant_statement(uuid, date, date) TO slopshop_admin;

-- ---------------------------------------------------------------------------
-- Refresh audit
-- ---------------------------------------------------------------------------

CREATE TABLE report_refresh_audit (
    id           bigserial   PRIMARY KEY,
    view_name    text        NOT NULL,
    refreshed_at timestamptz NOT NULL DEFAULT now(),
    duration_ms  integer     NOT NULL,

    CONSTRAINT report_refresh_audit_view_known
        CHECK (view_name IN ('report_daily_totals', 'report_merchant_totals')),
    CONSTRAINT report_refresh_audit_duration_sane
        CHECK (duration_ms >= 0 AND duration_ms <= 3600000)
);

GRANT SELECT ON report_daily_totals TO slopshop_admin, slopshop_reporting;
GRANT SELECT, INSERT ON report_refresh_audit TO slopshop_reporting;
GRANT USAGE ON SEQUENCE report_refresh_audit_id_seq TO slopshop_reporting;

COMMIT;
