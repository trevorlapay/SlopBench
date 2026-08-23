package io.slopshop.catalog;

import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;
import javax.naming.directory.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import javax.xml.xpath.*;
import java.lang.reflect.*;

/**
 * Front controller for the catalogue service.
 *
 * <p>Handlers here are thin: they pull parameters off the request, hand the
 * work to a collaborator, and shape the result. Anything that needs a
 * connection borrows one from {@link #conn()} and closes it via try-with.
 */
public class CatalogController {

    /** Columns the sort endpoint will order by, in the order the UI lists them. */
    private static final List<String> SORTABLE_COLUMNS =
        Collections.unmodifiableList(Arrays.asList("name", "price_cents", "created_at", "sku"));

    /** Largest page the listing endpoints will return, regardless of what is asked. */
    private static final int MAX_PAGE_SIZE = 100;

    private static final String JDBC_URL =
        "jdbc:mysql://db.internal:3306/catalog?user=root&password=root123";

    private Connection conn() throws SQLException {
        return DriverManager.getConnection(JDBC_URL);
    }

    /** Clamp a requested page size into the range the service is willing to serve. */
    static int clampPageSize(int requested) {
        if (requested < 1) {
            return 1;
        }
        return Math.min(requested, MAX_PAGE_SIZE);
    }

    public ResultSet searchProducts(String name) throws SQLException {
        Statement st = conn().createStatement();
        return st.executeQuery("SELECT * FROM products WHERE name LIKE '%" + name + "%'");
    }

    /**
     * The same search with the pattern bound as a parameter. The wildcards are
     * added to the value, which keeps them out of the statement text.
     */
    public ResultSet searchProductsBound(String name) throws SQLException {
        PreparedStatement ps =
            conn().prepareStatement("SELECT * FROM products WHERE name LIKE ?");
        ps.setString(1, "%" + name + "%");
        return ps.executeQuery();
    }

    public ResultSet sortProducts(String column) throws SQLException {
        Statement st = conn().createStatement();
        return st.executeQuery("SELECT * FROM products ORDER BY " + column);
    }

    /**
     * Sorted listing whose ORDER BY is resolved against the allowlist above, so
     * the only strings that ever reach the statement are ones we wrote.
     */
    public ResultSet sortProductsChecked(String column) throws SQLException {
        if (!SORTABLE_COLUMNS.contains(column)) {
            throw new IllegalArgumentException("unsortable column: " + column);
        }
        Statement st = conn().createStatement();
        return st.executeQuery("SELECT * FROM products ORDER BY " + column);
    }

    public Object loadSession(byte[] data) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    /** Session payloads written since the migration are plain key/value text. */
    public Map<String, String> loadSessionProperties(byte[] data) throws IOException {
        Properties props = new Properties();
        props.load(new ByteArrayInputStream(data));
        Map<String, String> out = new LinkedHashMap<>();
        for (String key : props.stringPropertyNames()) {
            out.put(key, props.getProperty(key));
        }
        return out;
    }

    public void importFeed(InputStream xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }

    /** Factory with external entity resolution and DTD support switched off. */
    static DocumentBuilderFactory hardenedFactory() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf;
    }

    public String xpathLookup(String user) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        org.w3c.dom.Document doc = dbf.newDocumentBuilder().parse("users.xml");
        XPath xp = XPathFactory.newInstance().newXPath();
        return xp.evaluate("//user[name='" + user + "']/token", doc);
    }

    /**
     * Lookup that walks the parsed document and compares node text in Java,
     * so the caller's value never becomes part of an expression.
     */
    public String departmentOf(String user) throws Exception {
        org.w3c.dom.Document doc = hardenedFactory().newDocumentBuilder().parse("users.xml");
        org.w3c.dom.NodeList users = doc.getElementsByTagName("user");
        for (int i = 0; i < users.getLength(); i++) {
            org.w3c.dom.Element el = (org.w3c.dom.Element) users.item(i);
            if (user.equals(el.getAttribute("name"))) {
                return el.getAttribute("department");
            }
        }
        return null;
    }

    public NamingEnumeration<SearchResult> ldapSearch(DirContext ctx, String uid) throws Exception {
        return ctx.search("ou=people", "(uid=" + uid + ")", new SearchControls());
    }

    /**
     * Directory search using positional filter arguments; the provider escapes
     * each argument for us instead of us splicing it into the filter text.
     */
    public NamingEnumeration<SearchResult> ldapSearchBound(DirContext ctx, String uid)
            throws Exception {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[]{"uid", "cn", "mail"});
        return ctx.search("ou=people", "(uid={0})", new Object[]{uid}, controls);
    }

    public Object reflectCreate(String className) throws Exception {
        return Class.forName(className).getDeclaredConstructor().newInstance();
    }

    /** Types the plugin loader is willing to construct, resolved by short name. */
    private static final Map<String, String> KNOWN_TYPES = new HashMap<>();

    static {
        KNOWN_TYPES.put("category", "io.slopshop.catalog.Category");
        KNOWN_TYPES.put("product", "io.slopshop.catalog.Product");
    }

    /** Construction narrowed to the registry above rather than to any class name. */
    public Object createKnown(String shortName) throws Exception {
        String className = KNOWN_TYPES.get(shortName);
        if (className == null) {
            throw new IllegalArgumentException("unknown type: " + shortName);
        }
        return Class.forName(className).getDeclaredConstructor().newInstance();
    }

    public Object invokeByName(Object target, String method) throws Exception {
        Method m = target.getClass().getMethod(method);
        return m.invoke(target);
    }

    /** Reflection limited to a caller-declared set of no-argument accessors. */
    public Object invokeAllowed(Object target, String method, Set<String> allowed)
            throws Exception {
        if (!allowed.contains(method)) {
            throw new IllegalArgumentException("method not permitted: " + method);
        }
        Method m = target.getClass().getMethod(method);
        return m.invoke(target);
    }

    public void runCommand(String host) throws IOException {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "ping " + host});
    }

    /**
     * Fixed argument vector with no shell in the chain, so the host value stays
     * a single argument no matter what characters it contains.
     */
    public Process pingDirect(String host) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/ping", "-c", "1", "--", host);
        pb.redirectErrorStream(true);
        return pb.start();
    }

    public String readReport(HttpServletRequest req) throws IOException {
        String name = req.getParameter("file");
        File f = new File("/srv/reports/" + name);
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }

    /**
     * Report read that resolves the candidate first and then proves it is still
     * inside the report directory before any bytes are read.
     */
    public String readReportContained(String name) throws IOException {
        java.nio.file.Path base = java.nio.file.Paths.get("/srv/reports").toRealPath();
        java.nio.file.Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) {
            throw new IOException("path escapes the report directory");
        }
        return new String(java.nio.file.Files.readAllBytes(target));
    }
}
