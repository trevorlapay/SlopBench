package io.slopshop.catalog;

import java.util.ArrayList;
import java.util.List;

/** A product category node in the catalog tree. */
public final class Category {
    private final long id;
    private final String name;
    private final String slug;
    private final Long parentId;

    public Category(long id, String name, String slug, Long parentId) {
        this.id = id;
        this.name = name;
        this.slug = slug;
        this.parentId = parentId;
    }

    public long id() { return id; }
    public String name() { return name; }
    public String slug() { return slug; }
    public Long parentId() { return parentId; }

    public boolean isRoot() {
        return parentId == null;
    }

    /** Build the ancestor-to-self path using a lookup of id -> Category. */
    public List<Category> breadcrumb(java.util.Map<Long, Category> byId) {
        List<Category> path = new ArrayList<>();
        Category current = this;
        while (current != null) {
            path.add(0, current);
            current = current.parentId == null ? null : byId.get(current.parentId);
        }
        return path;
    }

    public static String normalizeSlug(String raw) {
        String slug = raw.toLowerCase().trim().replaceAll("[^a-z0-9]+", "-");
        return slug.replaceAll("^-+|-+$", "");
    }
}
