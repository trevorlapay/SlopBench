package io.slopshop.catalog;

import java.util.List;
import java.util.Map;

/** Order pricing: subtotal, discount, tax, shipping. */
public class PriceCalculator {

    private static final long FREE_SHIPPING_THRESHOLD = 5000;
    private static final long FLAT_SHIPPING = 599;

    private static final Map<String, Double> TAX_RATES = Map.of(
        "CA", 7.25, "NY", 8.875, "TX", 6.25, "WA", 6.5, "OR", 0.0);

    public long subtotal(List<Long> lineTotals) {
        long sum = 0;
        for (Long t : lineTotals) {
            sum += t;
        }
        return sum;
    }

    public long shipping(long subtotalCents, boolean expedited) {
        if (subtotalCents >= FREE_SHIPPING_THRESHOLD && !expedited) {
            return 0;
        }
        return expedited ? FLAT_SHIPPING * 2 : FLAT_SHIPPING;
    }

    public long percentDiscount(long subtotalCents, double percent) {
        long raw = Math.round(subtotalCents * (percent / 100.0));
        return Math.min(raw, subtotalCents);
    }

    public long tax(long taxableCents, String state) {
        double rate = TAX_RATES.getOrDefault(state.toUpperCase(), 0.0);
        return Math.round(taxableCents * (rate / 100.0));
    }

    public long grandTotal(long subtotal, long discount, String state, boolean expedited) {
        long taxable = subtotal - discount;
        return taxable + tax(taxable, state) + shipping(taxable, expedited);
    }

    public static String formatCents(long cents) {
        long whole = Math.abs(cents) / 100;
        long frac = Math.abs(cents) % 100;
        String sign = cents < 0 ? "-" : "";
        return String.format("%s$%,d.%02d", sign, whole, frac);
    }
}
