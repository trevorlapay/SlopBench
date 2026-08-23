package io.slopshop.catalog;

import java.util.Collections;
import java.util.List;

/** Immutable pagination window. */
public final class Pagination<T> {
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    private final List<T> items;
    private final int page;
    private final int size;
    private final int total;

    private Pagination(List<T> items, int page, int size, int total) {
        this.items = items;
        this.page = page;
        this.size = size;
        this.total = total;
    }

    public static int normalizeSize(int requested) {
        if (requested <= 0) return DEFAULT_SIZE;
        return Math.min(requested, MAX_SIZE);
    }

    public static int normalizePage(int requested) {
        return Math.max(1, requested);
    }

    public static <T> Pagination<T> of(List<T> all, int page, int size) {
        page = normalizePage(page);
        size = normalizeSize(size);
        int from = Math.min((page - 1) * size, all.size());
        int to = Math.min(from + size, all.size());
        return new Pagination<>(all.subList(from, to), page, size, all.size());
    }

    public List<T> items() {
        return Collections.unmodifiableList(items);
    }

    public int page() { return page; }

    public int size() { return size; }

    public int total() { return total; }

    public int pages() {
        return size == 0 ? 0 : (total + size - 1) / size;
    }

    public boolean hasNext() {
        return page < pages();
    }
}
