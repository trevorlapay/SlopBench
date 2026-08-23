package io.slopshop.catalog;

import java.io.*;
import java.util.*;
import javax.xml.parsers.*;
import javax.xml.validation.*;
import javax.xml.transform.sax.SAXSource;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;

/**
 * XML handling for supplier feeds, order documents, and the partner import.
 *
 * <p>Two shapes of document flow through here: order XML the service emits,
 * and feed XML it consumes. The emitting side has to escape; the consuming
 * side has to bound what the parser is willing to do.
 */
public class XmlProcessing {

    /** Elements the order document is built from, in schema order. */
    private static final List<String> ORDER_ELEMENTS =
        Collections.unmodifiableList(Arrays.asList("sku", "qty", "note"));

    /** Largest feed the SAX helpers will accept before refusing to parse. */
    private static final long MAX_FEED_BYTES = 16L * 1024 * 1024;

    public String buildOrderXml(String qty, String sku) {
        return "<order><sku>" + sku + "</sku><qty>" + qty + "</qty></order>";
    }

    /** Escape the five characters that carry structural meaning in XML text. */
    static String escapeXml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&apos;");
    }

    /** Order document whose text nodes are escaped as they are written. */
    public String buildOrderXmlEscaped(String qty, String sku) {
        StringBuilder sb = new StringBuilder("<order>");
        sb.append("<sku>").append(escapeXml(sku)).append("</sku>");
        sb.append("<qty>").append(escapeXml(qty)).append("</qty>");
        return sb.append("</order>").toString();
    }

    public Document parseNoValidation(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(in);
    }

    /**
     * Factory used by every hardened path below: doctype declarations are
     * refused, external entities are off, and XInclude is disabled.
     */
    static DocumentBuilderFactory hardened() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf;
    }

    public Document parseMisconfigured(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
        dbf.setExpandEntityReferences(true);
        return dbf.newDocumentBuilder().parse(in);
    }

    /** Parse through the hardened factory above. */
    public Document parseHardened(InputStream in) throws Exception {
        return hardened().newDocumentBuilder().parse(in);
    }

    /** Count the direct children of the root, for the import summary line. */
    public int childCount(Document doc) {
        org.w3c.dom.NodeList children = doc.getDocumentElement().getChildNodes();
        int count = 0;
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                count++;
            }
        }
        return count;
    }

    public boolean validateLoose(SAXSource src, Validator validator) {
        try {
            validator.validate(src);
        } catch (Exception e) {

        }
        return true;
    }

    /**
     * Validation whose result actually depends on whether the document
     * validated: a schema failure is reported rather than swallowed.
     */
    public boolean validateStrict(SAXSource src, Validator validator) throws IOException {
        try {
            validator.validate(src);
            return true;
        } catch (org.xml.sax.SAXException e) {
            return false;
        }
    }

    public void parseUnbounded(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
    }

    /**
     * Bounded SAX parse: the stream is capped before it reaches the parser and
     * the factory refuses doctype declarations outright.
     */
    public void parseBounded(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setNamespaceAware(true);
        InputStream capped = new BoundedInputStream(in, MAX_FEED_BYTES);
        spf.newSAXParser().parse(capped, new org.xml.sax.helpers.DefaultHandler());
    }

    public Document importFeed(String feedUrl) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(feedUrl);
    }

    /** Feed import from an already-fetched stream, parsed with entities off. */
    public Document importFeedStream(InputStream feed) throws Exception {
        return hardened().newDocumentBuilder().parse(new InputSource(feed));
    }

    public Object parseByClientType(String contentType, byte[] body) throws Exception {
        if (contentType.contains("xml")) {
            return parseNoValidation(new ByteArrayInputStream(body));
        }

        return new ObjectInputStream(new ByteArrayInputStream(body)).readObject();
    }

    /**
     * Content-type dispatch with an explicit default: an unrecognised type is
     * rejected rather than falling through to a different parser.
     */
    public Document parseByDeclaredType(String contentType, byte[] body) throws Exception {
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (!type.startsWith("application/xml") && !type.startsWith("text/xml")) {
            throw new IllegalArgumentException("unsupported content type: " + contentType);
        }
        return parseHardened(new ByteArrayInputStream(body));
    }

    /** Stream wrapper that stops once the configured byte budget is spent. */
    static final class BoundedInputStream extends FilterInputStream {
        private final long limit;
        private long seen;

        BoundedInputStream(InputStream in, long limit) {
            super(in);
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0 && ++seen > limit) {
                throw new IOException("feed exceeds " + limit + " bytes");
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            if (n > 0) {
                seen += n;
            }
            if (seen > limit) {
                throw new IOException("feed exceeds " + limit + " bytes");
            }
            return n;
        }
    }
}
