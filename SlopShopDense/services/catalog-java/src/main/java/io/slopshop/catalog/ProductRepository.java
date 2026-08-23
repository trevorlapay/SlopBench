package io.slopshop.catalog;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Parameterized product data access. */
public class ProductRepository {

    // Identifiers can never come from the client; only allowlisted columns are used.
    private static final Map<String, String> SORT_COLUMNS = Map.of(
        "name", "name", "price", "price_cents", "newest", "created_at");

    private final Connection conn;

    public ProductRepository(Connection conn) {
        this.conn = conn;
    }

    public Optional<Product> byId(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, sku, name, price_cents, category_id, stock, active "
                + "FROM products WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(map(rs)) : Optional.empty();
            }
        }
    }

    public List<Product> search(String term, int limit) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, sku, name, price_cents, category_id, stock, active "
                + "FROM products WHERE name LIKE ? ORDER BY name LIMIT ?")) {
            ps.setString(1, "%" + term + "%");
            ps.setInt(2, limit);
            return collect(ps);
        }
    }

    public List<Product> sorted(String sortKey, int limit) throws SQLException {
        String column = SORT_COLUMNS.getOrDefault(sortKey, "id");
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, sku, name, price_cents, category_id, stock, active "
                + "FROM products ORDER BY " + column + " LIMIT ?")) {
            ps.setInt(1, limit);
            return collect(ps);
        }
    }

    public boolean decrementStock(long id, int quantity) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?")) {
            ps.setInt(1, quantity);
            ps.setLong(2, id);
            ps.setInt(3, quantity);
            return ps.executeUpdate() == 1;
        }
    }

    private List<Product> collect(PreparedStatement ps) throws SQLException {
        List<Product> out = new ArrayList<>();
        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                out.add(map(rs));
            }
        }
        return out;
    }

    private Product map(ResultSet rs) throws SQLException {
        return new Product(
            rs.getLong("id"), rs.getString("sku"), rs.getString("name"),
            rs.getLong("price_cents"), rs.getLong("category_id"),
            rs.getInt("stock"), rs.getBoolean("active"));
    }
}
