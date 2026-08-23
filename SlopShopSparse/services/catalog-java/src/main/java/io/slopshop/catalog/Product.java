package io.slopshop.catalog;

import java.util.Objects;

/** Immutable product model. */
public final class Product {
    private final long id;
    private final String sku;
    private final String name;
    private final long priceCents;
    private final long categoryId;
    private final int stock;
    private final boolean active;

    public Product(long id, String sku, String name, long priceCents,
                   long categoryId, int stock, boolean active) {
        this.id = id;
        this.sku = sku;
        this.name = name;
        this.priceCents = priceCents;
        this.categoryId = categoryId;
        this.stock = stock;
        this.active = active;
    }

    public long id() { return id; }
    public String sku() { return sku; }
    public String name() { return name; }
    public long priceCents() { return priceCents; }
    public long categoryId() { return categoryId; }
    public int stock() { return stock; }
    public boolean active() { return active; }

    public boolean inStock() {
        return active && stock > 0;
    }

    public boolean canFulfill(int quantity) {
        return inStock() && quantity <= stock;
    }

    public double priceDollars() {
        return priceCents / 100.0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Product)) return false;
        return id == ((Product) o).id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Product{" + sku + " '" + name + "'}";
    }


    /** A copy of this product with a new stock level. */
    public Product withStock(int newStock) {
        return new Product(id, sku, name, priceCents, categoryId, newStock, active);
    }

    /** A copy of this product with the active flag flipped. */
    public Product withActive(boolean newActive) {
        return new Product(id, sku, name, priceCents, categoryId, stock, newActive);
    }

    /** Total for a line of this product, in cents. */
    public long lineTotal(int quantity) {
        return priceCents * Math.max(0, quantity);
    }

    /** Whether the stock level has fallen to or below the reorder threshold. */
    public boolean isLowStock(int threshold) {
        return active && stock <= threshold;
    }

    /** Label the storefront shows next to the price. */
    public String availabilityLabel(int lowStockThreshold) {
        if (!inStock()) {
            return "Out of stock";
        }
        return isLowStock(lowStockThreshold) ? "Only a few left" : "In stock";
    }
}
