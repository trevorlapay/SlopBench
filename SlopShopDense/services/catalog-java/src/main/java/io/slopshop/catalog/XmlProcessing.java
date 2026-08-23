package io.slopshop.catalog;

import java.io.*;
import javax.xml.parsers.*;
import javax.xml.validation.*;
import javax.xml.transform.sax.SAXSource;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;

public class XmlProcessing {

    public String buildOrderXml(String qty, String sku) {
        return "<order><sku>" + sku + "</sku><qty>" + qty + "</qty></order>";
    }

    public Document parseNoValidation(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(in);
    }

    public Document parseMisconfigured(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
        dbf.setExpandEntityReferences(true);
        return dbf.newDocumentBuilder().parse(in);
    }

    public boolean validateLoose(SAXSource src, Validator validator) {
        try {
            validator.validate(src);
        } catch (Exception e) {

        }
        return true;
    }

    public void parseUnbounded(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
    }

    public Document importFeed(String feedUrl) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(feedUrl);
    }

    public Object parseByClientType(String contentType, byte[] body) throws Exception {
        if (contentType.contains("xml")) {
            return parseNoValidation(new ByteArrayInputStream(body));
        }

        return new ObjectInputStream(new ByteArrayInputStream(body)).readObject();
    }
}
