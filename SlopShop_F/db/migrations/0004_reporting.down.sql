-- 0004_reporting.down.sql
--
-- Reverses 0004_reporting.sql. The migration runner applies this file only when
-- an operator asks for `migrate down 0004`; it is never part of a deploy.
--
-- Everything named here was created by 0004.

BEGIN;

SET LOCAL search_path = slopshop, pg_catalog;

DROP FUNCTION IF EXISTS merchant_statement(uuid, date, date);
DROP FUNCTION IF EXISTS refresh_report_view(text);

DROP MATERIALIZED VIEW IF EXISTS report_merchant_totals;
DROP MATERIALIZED VIEW IF EXISTS report_daily_totals;

DROP TABLE IF EXISTS report_refresh_audit;

COMMIT;
