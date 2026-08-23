package com.slopshop.orders.persistence;

import com.slopshop.orders.domain.Order;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Order persistence. Reads carry the owning customer id in their predicate.
 */
@Repository
public class OrderRepository {

    private static final String ORDER_COLUMNS =
            "id, customer_id, status, currency, subtotal_minor, tax_minor, total_minor, "
            + "created_at, updated_at";

    /**
     * Sort keys accepted on the wire, mapped to the ORDER BY fragment each one
     * stands for.
     */
    private static final Map<String, String> SORTS = Map.of(
            "newest", "created_at DESC, id ASC",
            "oldest", "created_at ASC, id ASC",
            "total_desc", "total_minor DESC, id ASC",
            "total_asc", "total_minor ASC, id ASC");

    private static final int MAX_PAGE_SIZE = 100;

    private final NamedParameterJdbcTemplate jdbc;

    public OrderRepository(NamedParameterJdbcTemplate jdbc) {
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

    private static final RowMapper<Order.Line> LINE_MAPPER = (ResultSet rs, int rowNum) ->
            new Order.Line(
                    UUID.fromString(rs.getString("product_id")),
                    rs.getInt("quantity"),
                    rs.getLong("unit_price_minor"));

    /** Loads an order together with its lines, scoped to the owning customer. */
    @Transactional(readOnly = true)
    public Optional<Order> findForCustomer(UUID orderId, UUID customerId) {
        var params = new MapSqlParameterSource()
                .addValue("orderId", orderId)
                .addValue("customerId", customerId);

        List<Order> found = jdbc.query(
                "SELECT " + ORDER_COLUMNS
                        + " FROM orders WHERE id = :orderId AND customer_id = :customerId",
                params, ORDER_MAPPER);

        if (found.isEmpty()) {
            return Optional.empty();
        }

        List<Order.Line> lines = jdbc.query(
                "SELECT product_id, quantity, unit_price_minor FROM order_lines "
                        + "WHERE order_id = :orderId ORDER BY line_number",
                params, LINE_MAPPER);

        Order header = found.get(0);
        return Optional.of(new Order(header.id(), header.customerId(), header.status(),
                header.currency(), header.subtotalMinor(), header.taxMinor(),
                header.totalMinor(), lines, header.createdAt(), header.updatedAt()));
    }

    /**
     * Lists the orders belonging to one customer. The sort key is translated
     * through SORTS.
     */
    @Transactional(readOnly = true)
    public List<Order> listForCustomer(UUID customerId, String sortKey, int limit, int offset) {
        String orderBy = SORTS.get(sortKey);
        if (orderBy == null) {
            throw new IllegalArgumentException("unsupported sort key");
        }

        var params = new MapSqlParameterSource()
                .addValue("customerId", customerId)
                .addValue("limit", Math.clamp(limit, 1, MAX_PAGE_SIZE))
                .addValue("offset", Math.max(offset, 0));

        return new ArrayList<>(jdbc.query(
                "SELECT " + ORDER_COLUMNS + " FROM orders WHERE customer_id = :customerId "
                        + "ORDER BY " + orderBy + " LIMIT :limit OFFSET :offset",
                params, ORDER_MAPPER));
    }

    /**
     * Moves an order to a new status. The row is locked for the duration of the
     * transaction, so two concurrent transitions cannot both observe the old
     * status and both succeed.
     */
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public Order.Status transition(UUID orderId, UUID customerId, Order.Status next) {
        var params = new MapSqlParameterSource()
                .addValue("orderId", orderId)
                .addValue("customerId", customerId);

        Order.Status current;
        try {
            current = Order.Status.valueOf(jdbc.queryForObject(
                    "SELECT status FROM orders WHERE id = :orderId "
                            + "AND customer_id = :customerId FOR UPDATE",
                    params, String.class));
        } catch (EmptyResultDataAccessException notFound) {
            throw new OrderNotFoundException(orderId);
        }

        if (!current.canTransitionTo(next)) {
            throw new IllegalStateTransitionException(current, next);
        }

        jdbc.update(
                "UPDATE orders SET status = :next, updated_at = now() "
                        + "WHERE id = :orderId AND customer_id = :customerId",
                params.addValue("next", next.name()));

        return next;
    }

    public static class OrderNotFoundException extends RuntimeException {
        public OrderNotFoundException(UUID orderId) {
            super("order not found: " + orderId);
        }
    }

    public static class IllegalStateTransitionException extends RuntimeException {
        public IllegalStateTransitionException(Order.Status from, Order.Status to) {
            super("cannot move order from " + from + " to " + to);
        }
    }
}
