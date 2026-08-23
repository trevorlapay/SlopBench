package com.slopshop.orders.domain;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * An order and its lines. Monetary amounts are held in minor units as a long so
 * that no arithmetic in this service ever touches a binary floating point type.
 */
public record Order(
        UUID id,
        UUID customerId,
        Status status,
        String currency,
        long subtotalMinor,
        long taxMinor,
        long totalMinor,
        List<Line> lines,
        Instant createdAt,
        Instant updatedAt) {

    public Order {
        lines = List.copyOf(lines);
    }

    public enum Status {
        PENDING,
        AUTHORISED,
        FULFILLING,
        SHIPPED,
        CANCELLED,
        REFUNDED;

        /** The order state machine. Any transition not listed here is refused. */
        public boolean canTransitionTo(Status next) {
            return switch (this) {
                case PENDING -> next == AUTHORISED || next == CANCELLED;
                case AUTHORISED -> next == FULFILLING || next == CANCELLED;
                case FULFILLING -> next == SHIPPED || next == CANCELLED;
                case SHIPPED -> next == REFUNDED;
                case CANCELLED, REFUNDED -> false;
            };
        }
    }

    public record Line(UUID productId, int quantity, long unitPriceMinor) {

        public static final int MAX_QUANTITY = 20;

        public Line {
            if (quantity < 1 || quantity > MAX_QUANTITY) {
                throw new IllegalArgumentException("quantity must be 1.." + MAX_QUANTITY);
            }
            if (unitPriceMinor < 0) {
                throw new IllegalArgumentException("unitPriceMinor must not be negative");
            }
        }

        /** Line total, throwing rather than wrapping if the product overflows. */
        public long extendedMinor() {
            return Math.multiplyExact(unitPriceMinor, quantity);
        }
    }

    /** Recomputes the subtotal from the lines, failing loudly on overflow. */
    public long recomputedSubtotalMinor() {
        long sum = 0L;
        for (Line line : lines) {
            sum = Math.addExact(sum, line.extendedMinor());
        }
        return sum;
    }
}
