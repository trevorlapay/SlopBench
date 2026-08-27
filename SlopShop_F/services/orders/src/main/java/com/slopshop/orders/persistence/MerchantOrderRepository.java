package com.slopshop.orders.persistence;

import com.slopshop.orders.domain.Order;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads used by the seller console.
 *
 * <p>An order can contain lines from several sellers. A merchant sees the order
 * reference, its status and the value of their own lines; the customer and the
 * whole-order totals belong to the other parties on the order and are not part
 * of the projection.
 */
@Repository
public class MerchantOrderRepository {

    /**
     * Columns a merchant may see, with the money column restricted to the lines
     * that merchant actually supplied.
     */
    private static final String MERCHANT_COLUMNS =
            "o.id, o.status, o.currency, o.created_at, o.updated_at, "
            + "(SELECT coalesce(sum(ol.quantity * ol.unit_price_minor), 0) "
            + "   FROM order_lines ol "
            + "   JOIN products p ON p.id = ol.product_id "
            + "  WHERE ol.order_id = o.id AND p.seller_id = :merchantId) AS merchant_gross_minor";

    private static final String MERCHANT_SCOPE =
            " FROM orders o "
            + " WHERE EXISTS (SELECT 1 FROM order_lines ol "
            + "                 JOIN products p ON p.id = ol.product_id "
            + "                WHERE ol.order_id = o.id AND p.seller_id = :merchantId) ";

    private static final int MAX_PAGE_SIZE = 100;

    /** Deep paging past this point is refused rather than scanned. */
    private static final long MAX_OFFSET = 10_000L;

    private final NamedParameterJdbcTemplate jdbc;

    public MerchantOrderRepository(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** What the seller console is allowed to render for one order. */
    public record MerchantOrderSummary(
            UUID orderId,
            Order.Status status,
            String currency,
            long merchantGrossMinor,
            Instant createdAt,
            Instant updatedAt) {
    }

    private static final RowMapper<MerchantOrderSummary> SUMMARY_MAPPER =
            (ResultSet rs, int rowNum) -> new MerchantOrderSummary(
                    UUID.fromString(rs.getString("id")),
                    Order.Status.valueOf(rs.getString("status")),
                    rs.getString("currency"),
                    rs.getLong("merchant_gross_minor"),
                    rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("updated_at").toInstant());

    /**
     * Loads one order, provided it contains a listing belonging to this
     * merchant.
     */
    @Transactional(readOnly = true)
    public Optional<MerchantOrderSummary> findForMerchant(UUID orderId, UUID merchantId) {
        var params = new MapSqlParameterSource()
                .addValue("orderId", orderId)
                .addValue("merchantId", merchantId);

        List<MerchantOrderSummary> found = jdbc.query(
                "SELECT " + MERCHANT_COLUMNS + MERCHANT_SCOPE + " AND o.id = :orderId",
                params, SUMMARY_MAPPER);

        return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
    }

    /** Lists the orders visible to this merchant, newest first. */
    @Transactional(readOnly = true)
    public List<MerchantOrderSummary> listForMerchant(UUID merchantId, int limit, int offset) {
        var params = new MapSqlParameterSource()
                .addValue("merchantId", merchantId)
                .addValue("limit", Math.clamp(limit, 1, MAX_PAGE_SIZE))
                .addValue("offset", Math.clamp((long) offset, 0L, MAX_OFFSET));

        return jdbc.query(
                "SELECT " + MERCHANT_COLUMNS + MERCHANT_SCOPE
                        + " ORDER BY o.created_at DESC, o.id ASC LIMIT :limit OFFSET :offset",
                params, SUMMARY_MAPPER);
    }

    /** Counts the orders visible to this merchant in a status. */
    @Transactional(readOnly = true)
    public long countForMerchant(UUID merchantId, Order.Status status) {
        var params = new MapSqlParameterSource()
                .addValue("merchantId", merchantId)
                .addValue("status", status.name());

        Long count = jdbc.queryForObject(
                "SELECT count(*)" + MERCHANT_SCOPE + " AND o.status = :status",
                params, Long.class);

        return count == null ? 0L : count;
    }
}
