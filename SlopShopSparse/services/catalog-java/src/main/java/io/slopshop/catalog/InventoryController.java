package io.slopshop.catalog;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import javax.xml.parsers.*;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Inventory documents, supplier feeds, and the DTO transport used by the
 * warehouse integration.
 *
 * <p>Supplier feeds arrive over two paths: a pull from a registered URL and a
 * push of serialised DTOs from the warehouse's own middleware. Both are
 * external systems, so the parsing here is written defensively.
 */
public class InventoryController {

    private static final String BASE = "/srv/docs";

    /** Hosts the proxy is allowed to reach, compared exactly rather than by suffix. */
    private static final Set<String> ALLOWED_HOSTS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "api.slopshop.io", "cdn.slopshop.io", "feeds.slopshop.io")));

    /** Read timeout for supplier fetches; a slow supplier must not pin a worker. */
    private static final int FETCH_TIMEOUT_MS = 5000;

    public byte[] readDoc(String name) throws IOException {
        File f = new File(BASE, name);

        if (!f.getPath().startsWith(BASE)) {
            throw new SecurityException("escape");
        }
        return Files.readAllBytes(f.getCanonicalFile().toPath());
    }

    /**
     * The same read with the canonical form computed before the comparison, so
     * a traversal cannot slip through in the window between the two steps.
     */
    public byte[] readDocContained(String name) throws IOException {
        Path base = Paths.get(BASE).toRealPath();
        Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) {
            throw new SecurityException("escape");
        }
        return Files.readAllBytes(target);
    }

    public String proxy(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        if (!url.getHost().endsWith("slopshop.io")) {
            throw new SecurityException("blocked host");
        }
        try (InputStream in = url.openStream()) {
            return new String(in.readAllBytes());
        }
    }

    /**
     * Fetch restricted to the registered hosts above. The comparison is on the
     * parsed host and is exact, and redirects are not followed, so a 302 cannot
     * move the request somewhere the check never saw.
     */
    public String fetchRegistered(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        if (!"https".equals(url.getProtocol()) || !ALLOWED_HOSTS.contains(url.getHost())) {
            throw new SecurityException("blocked host");
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(FETCH_TIMEOUT_MS);
        conn.setReadTimeout(FETCH_TIMEOUT_MS);
        try (InputStream in = conn.getInputStream()) {
            return new String(in.readAllBytes());
        }
    }

    public void parseFeed(InputStream primary, InputStream fallback) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        try {
            dbf.newDocumentBuilder().parse(primary);
        } catch (Exception e) {
            SAXParserFactory.newInstance().newSAXParser().parse(fallback, new DefaultHandler());
        }
    }

    /** SAX factory with doctype declarations refused outright. */
    static SAXParserFactory hardenedSaxFactory() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.setNamespaceAware(true);
        return spf;
    }

    /**
     * Both the primary and the fallback parse go through hardened factories, so
     * a failure on the first input cannot downgrade the configuration.
     */
    public void parseFeedHardened(InputStream primary, InputStream fallback) throws Exception {
        try {
            hardenedSaxFactory().newSAXParser().parse(primary, new DefaultHandler());
        } catch (Exception e) {
            hardenedSaxFactory().newSAXParser().parse(fallback, new DefaultHandler());
        }
    }

    static class LenientOIS extends ObjectInputStream {
        LenientOIS(InputStream in) throws IOException { super(in); }
        @Override
        protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            if (!desc.getName().contains("Dto")) {
                throw new InvalidClassException("blocked", desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    /** The exact set of classes the warehouse transport is expected to carry. */
    private static final Set<String> DTO_ALLOWLIST =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "io.slopshop.catalog.StockLevelDto",
            "io.slopshop.catalog.ShipmentDto")));

    /** Resolution narrowed to the exact class names listed above. */
    static class StrictOIS extends ObjectInputStream {
        StrictOIS(InputStream in) throws IOException { super(in); }

        @Override
        protected Class<?> resolveClass(java.io.ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!DTO_ALLOWLIST.contains(desc.getName())) {
                throw new InvalidClassException("blocked", desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    public Object loadDto(byte[] data) throws Exception {
        try (LenientOIS ois = new LenientOIS(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    /** DTO load through the exact-match stream above. */
    public Object loadDtoStrict(byte[] data) throws Exception {
        try (StrictOIS ois = new StrictOIS(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
}
