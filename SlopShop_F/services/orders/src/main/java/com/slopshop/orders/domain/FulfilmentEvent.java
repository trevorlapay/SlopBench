package com.slopshop.orders.domain;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.time.Instant;
import java.util.UUID;

/**
 * An event posted by the fulfilment partner.
 *
 * <p>The wire format carries a discriminator so one endpoint can accept several
 * shapes. The four names below are what the partner sends.
 */
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "type",
        visible = true)
@JsonSubTypes({
        @JsonSubTypes.Type(value = FulfilmentEvent.Picked.class, name = "picked"),
        @JsonSubTypes.Type(value = FulfilmentEvent.Packed.class, name = "packed"),
        @JsonSubTypes.Type(value = FulfilmentEvent.Despatched.class, name = "despatched"),
        @JsonSubTypes.Type(value = FulfilmentEvent.Delivered.class, name = "delivered"),
})
public sealed interface FulfilmentEvent
        permits FulfilmentEvent.Picked,
                FulfilmentEvent.Packed,
                FulfilmentEvent.Despatched,
                FulfilmentEvent.Delivered {

    UUID orderId();

    Instant occurredAt();

    /** The order status this event moves the order to, if any. */
    Order.Status impliedStatus();

    record Picked(UUID orderId, Instant occurredAt, String pickerReference)
            implements FulfilmentEvent {

        public Picked {
            requireReference(pickerReference);
        }

        @Override
        public Order.Status impliedStatus() {
            return Order.Status.FULFILLING;
        }
    }

    record Packed(UUID orderId, Instant occurredAt, int parcelCount)
            implements FulfilmentEvent {

        public Packed {
            if (parcelCount < 1 || parcelCount > 50) {
                throw new IllegalArgumentException("parcelCount must be 1..50");
            }
        }

        @Override
        public Order.Status impliedStatus() {
            return Order.Status.FULFILLING;
        }
    }

    record Despatched(UUID orderId, Instant occurredAt, String carrier, String trackingReference)
            implements FulfilmentEvent {

        public Despatched {
            requireReference(carrier);
            requireReference(trackingReference);
        }

        @Override
        public Order.Status impliedStatus() {
            return Order.Status.SHIPPED;
        }
    }

    record Delivered(UUID orderId, Instant occurredAt, String signedFor)
            implements FulfilmentEvent {

        public Delivered {
            requireReference(signedFor);
        }

        @Override
        public Order.Status impliedStatus() {
            return Order.Status.SHIPPED;
        }
    }

    private static void requireReference(String value) {
        if (value == null || value.isBlank() || value.length() > 128) {
            throw new IllegalArgumentException("reference must be 1..128 characters");
        }
        if (!value.chars().allMatch(c -> c >= 0x20 && c != 0x7f)) {
            throw new IllegalArgumentException("reference contains a control character");
        }
    }
}
