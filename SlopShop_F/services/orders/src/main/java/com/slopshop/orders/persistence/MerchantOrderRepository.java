package com.slopshop.orders.persistence;

import com.slopshop.orders.domain.Order;
import java.sql.ResultSet;
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
 * <p>A merchant operator sees the orders that contain one of their own
 * listings. Every statement below joins through order_lines to products.
 */
@Repository
public class MerchantOrderRepository {

    private static final String ORDER_COLUMNS =
            "o.id, o.customer_id, o.status, o.currency, o.subtotal_minor, o.tax_minor, "
            + "o.total_minor, o.created_at, o.updated_at";

    private static final String MERCHANT_SCOPE =
            " FROM orders o "
            + " WHERE EXISTS (SELECT 1 FROM order_lines ol "
            + "                 JOIN products p ON p.id = ol.product_id "
            + "                WHERE ol.order_id = o.id AND p.seller_id = :merchantId) ";

    private static final int MAX_PAGE_SIZE = 100;

    private final NamedParameterJdbcTemplate jdbc;

    public MerchantOrderRepository(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private static final RowMapper<Order> ORDER_MAPPER = (ResultSet rs, int rowNum) -> new Order(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("customer_id")),
            Order.Status.valueOf(rs.getString("status")),
            rs.getString("currency"),
            rs.getLong("subtotal_minor"),
            rs.getLong("tax_minor"),
            rs.getLong("total_minor"),
            List.of(),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant());

    /**
     * Loads one order, provided it contains a listing belonging to this
     * merchant.
     */
    @Transactional(readOnly = true)
    public Optional<Order> findForMerchant(UUID orderId, UUID merchantId) {
        var params = new MapSqlParameterSource()
                .addValue("orderId", orderId)
                .addValue("merchantId", merchantId);

        List<Order> found = jdbc.query(
                "SELECT " + ORDER_COLUMNS + MERCHANT_SCOPE + " AND o.id = :orderId",
                params, ORDER_MAPPER);

        return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
    }

    /** Lists the orders visible to this merchant, newest first. */
    @Transactional(readOnly = true)
    public List<Order> listForMerchant(UUID merchantId, int limit, int offset) {
        var params = new MapSqlParameterSource()
                .addValue("merchantId", merchantId)
                .addValue("limit", Math.clamp(limit, 1, MAX_PAGE_SIZE))
                .addValue("offset", Math.max(offset, 0));

        return jdbc.query(
                "SELECT " + ORDER_COLUMNS + MERCHANT_SCOPE
                        + " ORDER BY o.created_at DESC, o.id ASC LIMIT :limit OFFSET :offset",
                params, ORDER_MAPPER);
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
