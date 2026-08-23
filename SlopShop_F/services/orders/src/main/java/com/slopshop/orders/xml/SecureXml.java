package com.slopshop.orders.xml;

import java.io.IOException;
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * The one place this service constructs an XML parser.
 *
 * <p>Logistics partners still exchange despatch notes as XML. The factories
 * handed out here are configured once, in this file, and used everywhere.
 */
public final class SecureXml {

    private SecureXml() {
    }

    private static final String DISALLOW_DOCTYPE =
            "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL_ENTITIES =
            "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER_ENTITIES =
            "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD =
            "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    /** Resolves every external reference to an empty document. */
    private static final EntityResolver EMPTY_RESOLVER =
            (publicId, systemId) -> new InputSource(new java.io.StringReader(""));

    /**
     * Returns a document builder configured to refuse doctypes and external
     * references.
     */
    public static DocumentBuilder documentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        factory.setFeature(DISALLOW_DOCTYPE, true);
        factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
        factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
        factory.setFeature(LOAD_EXTERNAL_DTD, false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(true);
        factory.setValidating(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver(EMPTY_RESOLVER);
        return builder;
    }

    /** Parses one despatch note. */
    public static Document parse(InputStream input)
            throws ParserConfigurationException, SAXException, IOException {
        return documentBuilder().parse(input);
    }

    /** Returns a transformer that will not load an external stylesheet. */
    public static Transformer transformer() throws TransformerConfigurationException {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        return factory.newTransformer();
    }
}
