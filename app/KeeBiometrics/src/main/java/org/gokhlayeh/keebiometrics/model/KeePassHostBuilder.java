package org.gokhlayeh.keebiometrics.model;

import android.databinding.BaseObservable;
import android.databinding.Bindable;
import android.util.Base64;

import org.apache.commons.lang3.Validate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class KeePassHostBuilder extends BaseObservable {

    private static final String ROOT_TAG_NAME = "keepass_host";
    private static final String HOSTNAME_TAG_NAME = "host_name";
    private static final String DISPLAYNAME_TAG_NAME = "display_name";
    private static final String DATABASENAME_TAG_NAME = "database_name";
    private static final String PUBLICKEY_TAG_NAME = "public_key";

    public static final String DEFAULT_HOSTNAME = "Unnamed Host";

    private String hostName;
    private String forcedDisplayName;
    private String databaseName;

    private PublicKey publicKey;

    public KeePassHostBuilder() {
    }

    private String getContentOfSingleElement(Element parent, String name) throws SAXException {
        NodeList nodes = parent.getElementsByTagName(name);
        if (nodes.getLength() == 1) {
            return nodes.item(0).getTextContent().trim();
        } else {
            throw new SAXException("Invalid number of " + name + " tags (" + nodes.getLength() + ")");
        }
    }

    private String getContentOfSingleElement(Element parent, String name, String defaultContent) throws SAXException {
        NodeList nodes = parent.getElementsByTagName(name);
        if (nodes.getLength() == 1) {
            return nodes.item(0).getTextContent().trim();
        } else if (nodes.getLength() == 0) {
            return defaultContent;
        } else {
            throw new SAXException("Invalid number of " + name + " tags (" + nodes.getLength() + ")");
        }
    }

    public void importXml(String text, boolean strict) throws IOException, SAXException, ParserConfigurationException, NoSuchAlgorithmException, InvalidKeySpecException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setIgnoringElementContentWhitespace(true);
        DocumentBuilder builder = factory.newDocumentBuilder();

        try (StringReader sr = new StringReader(text)) {
            Document doc = builder.parse(new InputSource(sr));

            Element root = doc.getDocumentElement();
            if (ROOT_TAG_NAME.equalsIgnoreCase(root.getTagName())) {
                if (strict) {
                    setHostName(getContentOfSingleElement(root, HOSTNAME_TAG_NAME));
                } else {
                    String content = getContentOfSingleElement(root, HOSTNAME_TAG_NAME, null);
                    if (!content.isEmpty()) {
                        setHostName(content);
                    }
                }

                if (strict) {
                    setDatabaseName(getContentOfSingleElement(root, DATABASENAME_TAG_NAME));
                } else {
                    setDatabaseName(getContentOfSingleElement(root, DATABASENAME_TAG_NAME, null));
                }

                if (strict) {
                    setForcedDisplayName(getContentOfSingleElement(root, DISPLAYNAME_TAG_NAME));
                } else {
                    setForcedDisplayName(getContentOfSingleElement(root, DISPLAYNAME_TAG_NAME, null));
                }

                String publicKeyBase64;
                if (strict) {
                    publicKeyBase64 = getContentOfSingleElement(root, PUBLICKEY_TAG_NAME);
                } else {
                    publicKeyBase64 = getContentOfSingleElement(root, PUBLICKEY_TAG_NAME, null);
                }

                if (publicKeyBase64 != null) {
                    byte[] keyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT);
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    setPublicKey(kf.generatePublic(spec));
                }
            } else {
                throw new SAXException("Invalid root element '" + root.getTagName() + "'");
            }
        }
    }

    public KeePassHost build() {
        return new KeePassHost(
                hostName != null && !hostName.isEmpty() ? hostName : DEFAULT_HOSTNAME,
                databaseName,
                publicKey,
                forcedDisplayName,
                new Date());
    }

    @Bindable
    public String getForcedDisplayName() {
        return forcedDisplayName;
    }

    public void setForcedDisplayName(String forcedDisplayName) {
        this.forcedDisplayName = forcedDisplayName;
        notifyChange();
    }

    @Bindable
    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        Validate.notEmpty(hostName);
        this.hostName = hostName;
        notifyChange();
    }

    @Bindable
    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
        notifyChange();
    }

    @Bindable
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        notifyChange();
    }
}
