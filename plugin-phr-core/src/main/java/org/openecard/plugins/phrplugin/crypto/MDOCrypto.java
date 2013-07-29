/****************************************************************************
 * Copyright (C) 2013 HS Coburg.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file is part of the Open eCard App.
 *
 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 * Other Usage
 * Alternatively, this file may be used in accordance with the terms
 * and conditions contained in a signed written agreement between
 * you and ecsec GmbH.
 *
 ***************************************************************************/

package org.openecard.plugins.phrplugin.crypto;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Iterator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherInput;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.openecard.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 * This class was provided in its original form by Fraunhofer FOKUS.
 * Adaptations were made to integrate it properly into the Open eCard App.
 * 
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class MDOCrypto {

    private static final Logger logger = LoggerFactory.getLogger(MDOCrypto.class);
    private static final String SYMETRICKEY_KEYALGORITHM = "AES";
    private static final String SYMMETRICKEY_ALGORITHM = XMLCipher.AES_128_GCM;
    private static final int SYMETRICKEY_KEYSIZE = 128;
    private static final String RECORD_KEYALGORITHM = "RSA";
    public static final String ASYMMETRICKEY_ALGORITHM = XMLCipher.RSA_v1dot5;
    private static final String SKI_OID = "2.5.29.14";

    static {
	org.apache.xml.security.Init.init();
	Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * hybrides Verschlüsseln eines MDO mittels eines symmetrischen Key und dem publicKey Akte.
     * 
     * @param mdo
     *            Medizinisches Datenobjekt als DOM Document
     * @param recordPublicKey
     *            Öffentlicher Schlüssel der Akte
     * @return hybrid verschlüsseltes MDO
     * @throws EncryptionException
     */
    public Document encryptMDO(Document mdo, Key recordPublicKey) throws EncryptionException {
	// Symmetrischen Schlüssel erstellen
	Key symmetricKey = generateDataEncryptionKey(SYMETRICKEY_KEYALGORITHM, SYMETRICKEY_KEYSIZE);

	// MDO mit symmetrischen Schlüssel verschlüsseln
	Document encryptedMDO = encryptDocHybrid(mdo, symmetricKey, recordPublicKey);

	// *** nur zum Test *** //
	// XMLUtil.print(encryptedMDO.getDocumentElement());

	logger.info("Verschlüsselung des MDO erfolgreich.");

	return encryptedMDO;
    }

    /**
     * Verschlüsseln des privateKey Akte (durch eGK); ACHTUNG: Der privateKey Akte wurde als DOM-Document verschlüsselt
     * und muss auch dementsprechend entschlüsselt werden!
     * 
     * @param recordPrivateKey
     *            privater Schlüssel der Akte
     * @param publicKey
     *            öffentlicher Schlüssel (der eGK)
     * @param subjectKeyIdentifier
     *            SKI des Zertifikats (der eGK)
     * @return den (mit der eGK) verschlüsselten privateKey Akte
     * @throws EncryptionException
     */
    public Document encryptPrivateKeyRecord(PrivateKey recordPrivateKey, PublicKey publicKey,
	    byte[] subjectKeyIdentifier) throws EncryptionException {
	String ski = ByteUtils.toHexString(subjectKeyIdentifier);

	// Symmetrischen Schlüssel erstellen
	Key symmetricKey = generateDataEncryptionKey(SYMETRICKEY_KEYALGORITHM, SYMETRICKEY_KEYSIZE);

	// TODO Ver- und Entschlüsselung des reinen Key, ohne die DOM Struktur!

	// privateKey der Akte in XML-Dokument einfügen
	Document document = MDOCrypto.generateNewDocument();
	Element elem = document.createElement("PrivKey");
	String privateKeyRecord = ByteUtils.toHexString(recordPrivateKey.getEncoded());
	elem.setTextContent(privateKeyRecord);
	document.appendChild(elem);

	// privateKey der Akte mit hybrid mit publicKey (der eGK) verschlüsseln
	// + SKI hinzufügen
	Document encryptedPrivKeyRecord = encryptDocHybrid(document, symmetricKey, publicKey);
	encryptedPrivKeyRecord = addSkiToDocument(encryptedPrivKeyRecord, ski);

	return encryptedPrivKeyRecord;
    }

    /**
     * Hybride Verschlüsselung eines XML-Documents
     * 
     * @param document
     *            DOM-Document welches hybrid verschlüsselt werden soll
     * @param symmetricKey
     *            Schlüssel mit dem symmetrisch verschlüsselt wird
     * @param kek
     *            Schlüssel mit dem der symmetricKey asymmetrisch verschlüsselt wird
     * @return hybrid verschlüsseltes DOM-Ducument
     * @throws EncryptionException
     */
    private Document encryptDocHybrid(Document document, Key symmetricKey, Key kek) throws EncryptionException {
	XMLCipher keyCipher;
	Document encryptedDoc;
	try {
	    keyCipher = XMLCipher.getInstance(ASYMMETRICKEY_ALGORITHM);
	    keyCipher.init(XMLCipher.WRAP_MODE, kek);
	    EncryptedKey encryptedKey = keyCipher.encryptKey(document, symmetricKey);

	    XMLCipher xmlCipher = XMLCipher.getInstance(SYMMETRICKEY_ALGORITHM);
	    xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

	    // Setting keyinfo inside the encrypted data being prepared.
	    EncryptedData encryptedData = xmlCipher.getEncryptedData();
	    KeyInfo keyInfo = new KeyInfo(document);
	    keyInfo.add(encryptedKey);
	    encryptedData.setKeyInfo(keyInfo);

	    /*
	     * doFinal - "true" below indicates that we want to encrypt element's content and not the element itself.
	     * Also, the doFinal method would modify the document by replacing the EncrypteData element for the data to
	     * be encrypted.
	     */
	    encryptedDoc = xmlCipher.doFinal(document, document);
	} catch (XMLEncryptionException e) {
	    throw new EncryptionException("Probleme bei Vorbereitung zur Verschlüsselung des MDO.", e);
	} catch (Exception e) {
	    throw new EncryptionException("Probleme bei Verschlüsselung des MDO.", e);
	}

	return encryptedDoc;
    }

    /**
     * merge hybrid-verschlüsseltes MDO mit hybrid-verschlüsseltem privaten Aktenschlüssel zu DOM-Document (nach
     * XML-Encryption).
     * 
     * @param doc
     *            hybrid verschlüsseltes MDO
     * @param encryptedPrivKey
     *            hybrid verschlüsselter privateKey
     * @return superencrypted MDO nach XMLEncryption Standard
     * @throws EncryptionException
     *             bei Problemen im Zusammenfügen der beiden Dokumente
     */
    public Document mergeDocuments(Document doc, Document encryptedPrivKey) throws EncryptionException {
	// Rootelement definieren
	Document document = MDOCrypto.generateNewDocument();
	Element elem = document.createElementNS("http://ws.gematik.de/fa/cds/CDocumentPayload/v1.0", "ContentPackage");
	elem.setPrefix("cdp");
	document.appendChild(elem);
	Element docElement = doc.getDocumentElement();
	document.getDocumentElement().appendChild(document.importNode(docElement, true));

	// richtige Stelle für Einfügen des verschlüsselten PrivateKey finden
	NodeList encKeyList = document.getElementsByTagName("xenc:EncryptedKey");
	if (encKeyList.getLength() != 1) {
	    throw new EncryptionException(
		    "Probleme bei Zusammenführen der XML-Dokumente (MDO und private key der Akte) - "
			    + "falsche Anzahl von EncryptedKey-Elementen im verschlüsselten XML-Dokument (MDO).");
	}

	Node encKeyNode = encKeyList.item(0);
	Node cipherDataNode = encKeyNode.getLastChild();

	// KeyInfo Element aufbauen und einfügen
	Element keyInfoElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
	keyInfoElement.setPrefix("ds");

	Element encryptedKeyElement = document.createElementNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey");
	encryptedKeyElement.setPrefix("xenc");
	keyInfoElement.appendChild(encryptedKeyElement);

	NodeList childNodeList = encryptedPrivKey.getFirstChild().getChildNodes();
	for (int i = 0; i < childNodeList.getLength(); i++) {
	    encryptedKeyElement.appendChild(document.importNode(childNodeList.item(i), true));
	}

	// Node keyInfoNode =
	encKeyNode.insertBefore(keyInfoElement, cipherDataNode);

	return document;
    }

    /**
     * Enschlüsseln des privateKey Akte durch den symmetrischen Key über die Key Specification, da symmetrischer Key als
     * byte Array vorliegt.
     * 
     * @param doc
     *            DOM-Document mit dem verschlüsselten privateKey Akte
     * @param decryptedSymmetricKey
     *            symmetrischer Key zur Entschlüsselung des privateKey Akte
     * @return privateKey Akte als byte Array
     * @throws EncryptionException
     *             bei Problemen in der Entschlüsselung.
     */
    public byte[] decryptPrivateKeyRecord(Document doc, byte[] decryptedSymmetricKey) throws EncryptionException {
	Security.addProvider(new BouncyCastleProvider());
	SecretKeySpec skeySpec = new SecretKeySpec(decryptedSymmetricKey, "AES");
	XMLCipher decryptCipher;
	Document privateKeyRecordDoc = null;

	Element encryptedDataElement = (Element) doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
		EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

	try {
	    decryptCipher = XMLCipher.getProviderInstance(SYMMETRICKEY_ALGORITHM, "BC");
	    decryptCipher.init(XMLCipher.DECRYPT_MODE, skeySpec);
	    // TODO Ver- und Entschlüsselung des reinen Key, ohne die DOM
	    // Struktur!
	    privateKeyRecordDoc = decryptCipher.doFinal(doc, encryptedDataElement);
	} catch (XMLEncryptionException e) {
	    throw new EncryptionException(
		    "Probleme beim Instanziieren bzw. Initialisieren des Entschlüsselungs-Cipher.", e);
	} catch (Exception e) {
	    throw new EncryptionException("Probleme beim Entschlüsseln (doFinal-Methode) des privateKey Akte.", e);
	}

	String privKeyRecord = privateKeyRecordDoc.getDocumentElement().getTextContent();

	return StringUtils.toByteArray(privKeyRecord);
    }

    /**
     * Entschlüsselt MDO hybrid mit dem privateKey Akte über die Key Specification, da privateKey Akte als byte Array
     * vorliegt.
     * 
     * @param encryptedMDO
     *            hybrid Verschlüsseltes MDO
     * @param privKeyRecord
     *            privateKey Akte als byte-Array
     * @return MDO als DOM-Document
     * @throws EncryptionException
     *             bei Problemen in der Entschlüsselung
     * @throws XPathExpressionException
     */
    public Document decryptMDO(Document encryptedMDO, byte[] privKeyRecord) throws EncryptionException {
	// bei der Verschlüsselung hinzugefügtes Rootelement entfernen
	Document doc = MDOCrypto.generateNewDocument();

	NodeList nodes = encryptedMDO.getElementsByTagNameNS("http://ws.gematik.de/fa/cds/CDocumentPayload/v1.0",
		"ContentPackage");
	// wenn superencrypted MDO
	if (nodes.getLength() > 0) {
	    doc.appendChild(doc.importNode(nodes.item(0).getChildNodes().item(0), true));
	} else { // wenn encryptedMDO
	    doc.appendChild(doc.importNode(encryptedMDO.getDocumentElement(), true));
	}

	// TODO SKI nutzen
	// byte[] ski = getSki(encryptedMDO);

	Key privateKeyRecord;
	try {
	    privateKeyRecord = KeyFactory.getInstance(RECORD_KEYALGORITHM, "BC").generatePrivate(
		    new PKCS8EncodedKeySpec(privKeyRecord));

	} catch (InvalidKeySpecException e) {
	    throw new EncryptionException("KeySpecification passt nicht zu privateKey-Bytes.", e);
	} catch (NoSuchAlgorithmException e) {
	    throw new EncryptionException("Entschlüsselungsalgorithmus nicht bekannt.", e);
	} catch (NoSuchProviderException e) {
	    throw new EncryptionException("Entschlüsselungsalgorithmus nicht bekannt.", e);
	}

	return decryptDocHybrid(doc, privateKeyRecord);
    }

    /**
     * Entschlüsselung eines hybrid verschlüsselten XML-Dokuments.
     * 
     * @param encryptedDoc
     *            hybrid verchlüsseltes Document
     * @param decryptionKey
     *            Schlüssel zur Entschlüsselung (privateKey)
     * @return entschlüsseltes Document
     * @throws EncryptionException
     *             bei Problemen in der Entschlüsselung
     */
    public Document decryptDocHybrid(Document encryptedDoc, Key decryptionKey)
    // private Document decryptDocHybrid(Document encryptedDoc, Key
    // decryptionKey)

	    throws EncryptionException {
	Document decryptedMDO = null;

	Element encryptedDataElement = (Element) encryptedDoc.getElementsByTagNameNS(
		EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

	try {
	    XMLCipher xmlCipher = XMLCipher.getInstance();
	    xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
	    xmlCipher.setKEK(decryptionKey);
	    decryptedMDO = xmlCipher.doFinal(encryptedDoc, encryptedDataElement);
	} catch (XMLEncryptionException e) {
	    throw new EncryptionException("Provider für die KeyFactory ist nicht bekannt.", e);
	} catch (Exception e) {
	    throw new EncryptionException("Probleme beim Entschlüsseln (doFinal-Methode) des MDO.", e);
	}

	return decryptedMDO;
    }

    /**
     * Symmetrischen Schlüssel erstellen.
     * 
     * @param jceAlgorithmName
     *            Beschreibt, welche Art Schlüssel erstellt wird.
     * @param keysize
     *            Gibt die Länge des zu generierenden Schlüssel an.
     * @return den erstellten symmetrischen Key.
     * @throws EncryptionException
     *             wenn der Algorithmus für die Schlüsselgenerierung nicht bekannt ist.
     */
    // private static SecretKey generateDataEncryptionKey(String
    // jceAlgorithmName, int keysize)
    public SecretKey generateDataEncryptionKey(String jceAlgorithmName, int keysize) throws EncryptionException {
	KeyGenerator keyGenerator = null;
	try {
	    keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
	} catch (NoSuchAlgorithmException e) {
	    throw new EncryptionException(
		    "Algorithmus für das Erstellen des symmetrischen Schlüssel (AES) des wird nicht gefunden.", e);
	}
	keyGenerator.init(keysize);
	SecretKey secKey = keyGenerator.generateKey();

	return secKey;
    }

    /**
     * SKI des Zertifikats hinzufügen
     * 
     * @param document
     *            Document mit hybrid verschlüsseltem privateKey Akte, dem der SKI hinzugefügt werden soll.
     * @param ski
     *            Subject Key Identifier, der dem Document hinzugefügt wird.
     * @return Document mit hybrid verschlüsseltem privateKey Akte incl. dem SKI nach XMLEncryption
     * @throws EncryptionException
     *             wenn nicht genau ein EncryptedKey-Element im Eingabe-Document vorhanden ist.
     */
    private Document addSkiToDocument(Document document, String ski) throws EncryptionException {
	// zusätzliche KeyInfo einfügen
	NodeList encKeyList = document.getElementsByTagName("xenc:EncryptedKey");
	if (encKeyList.getLength() != 1) {
	    throw new EncryptionException("Probleme bei Aufbau des XML-Dokuments (mit verschlüsseltem MDO) - "
		    + "falsche Anzahl von EncryptedKey-Elementen im verschlüsselten XML-Dokument.");
	}

	Node encKeyNode = encKeyList.item(0);
	Node cipherDataNode = encKeyNode.getLastChild();

	// KeyInfo Element aufbauen und einfügen
	Element keyInfoElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
	keyInfoElement.setPrefix("ds");

	Element retrievalMethodElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#",
		"RetrievalMethod");
	retrievalMethodElement.setPrefix("ds");
	retrievalMethodElement.setAttribute("Type", "http://www.w3.org/2000/09/xmldsig#X509Data");
	keyInfoElement.appendChild(retrievalMethodElement);

	Element x509DataElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", "X509Data");
	x509DataElement.setPrefix("ds");
	keyInfoElement.appendChild(x509DataElement);

	Element x509SKIElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", "X509SKI");
	x509SKIElement.setPrefix("ds");
	x509SKIElement.setTextContent(ski);
	x509DataElement.appendChild(x509SKIElement);

	// Node keyInfoNode =
	encKeyNode.insertBefore(keyInfoElement, cipherDataNode);

	return document;
    }

    /**
     * Extrahieren des privateKey der Akte aus dem superencrypted XML-Dokument mit dem MDO; Erstellen eines
     * XML-Dokuments, welches hybrid entschlüsselt werden kann.
     * 
     * @param superencryptedMDO
     *            superencrypted MDO
     * @return DOM-Document mit hybrid verschlüsselten PrivateKey Akte
     * @throws EncryptionException
     *             wenn X-Path Probleme beim auslesen des PrivateKey Akte auftreten.
     */
    public Document extractEncryptedPrivateKeyRecord(Document superencryptedMDO) throws EncryptionException {
	XPath xpath = initXpathNsSettings();
	XPathExpression expr;
	NodeList encryptedKeyElems = null;
	Document doc = MDOCrypto.generateNewDocument();

	Element elem = doc.createElementNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
	elem.setPrefix("xenc");
	elem.setAttribute("Type", "http://www.w3.org/2001/04/xmlenc#Element");
	doc.appendChild(elem);
	Element docElement = doc.getDocumentElement();

	try {
	    expr = xpath.compile("//*[local-name()='EncryptedKey']");
	    encryptedKeyElems = (NodeList) expr.evaluate(superencryptedMDO, XPathConstants.NODESET);
	} catch (XPathExpressionException e) {
	    throw new EncryptionException("XPath-Probleme bei extrahieren des verschlüsselten privateKey der Akte.", e);
	}

	int a;
	if (encryptedKeyElems.getLength() == 1) {
	    a = 0;
	} else {
	    a = 1;
	}
	NodeList childNodeList = encryptedKeyElems.item(a).getChildNodes();
	for (int i = 0; i < childNodeList.getLength(); i++) {
	    docElement.appendChild(doc.importNode(childNodeList.item(i), true));
	}

	return doc;
    }

    /**
     * verschlüsselten symmetrischen Schlüssel (zur Entschlüsselung des privateKey Akte) aus superencrypted MDO
     * extrahieren.
     * 
     * @param doc
     *            superencrypted MDO
     * @return verschlüsselten symmetrischen Schlüssel (zur Entschlüsselung des privateKey Akte)
     * @throws EncryptionException
     *             wenn EncryptedKey-Element aus superencrypted MDO bzw. verschlüsselter symmetrischer Key aus
     *             EncryptedKey-Element nicht extrahiert werden kann
     */
    public byte[] extractEncSymmetricKey(Document doc) throws EncryptionException {
	byte[] encSymmetricKey;
	try {
	    XPath xpath = initXpathNsSettings();
	    XPathExpression expr = xpath.compile("//*[(local-name()='EncryptedKey')]");

	    Object result = expr.evaluate(doc, XPathConstants.NODESET);
	    NodeList nodes = (NodeList) result;
	    Node encNode = nodes.item(0);

	    XMLCipher xmlCipher = XMLCipher.getInstance(ASYMMETRICKEY_ALGORITHM);
	    xmlCipher.init(XMLCipher.UNWRAP_MODE, null);

	    EncryptedKey encryptedKey = xmlCipher.loadEncryptedKey((Element) encNode);

	    XMLCipherInput cipherInput = new XMLCipherInput(encryptedKey);
	    encSymmetricKey = cipherInput.getBytes();
	} catch (XPathExpressionException e) {
	    throw new EncryptionException("XPath-Probleme beim extrahieren des verschlüsselten symmetischen Key.", e);
	} catch (XMLEncryptionException e) {
	    throw new EncryptionException("Probleme beim extrahieren des verschlüsselten symmetischen Key.", e);
	}

	return encSymmetricKey;
    }

    /**
     * setzen der XPath-Einstellungen incl. Namespaces
     * 
     * @return inizialisiertes XPath Element
     */
    private XPath initXpathNsSettings() {
	XPathFactory factory = XPathFactory.newInstance();
	XPath xpath = factory.newXPath();

	xpath.setNamespaceContext(new NamespaceContext() {
	    public String getNamespaceURI(String prefix) {
		if (prefix.equals("epa-ps")) {
		    return "urn:fue:epa:xml:ns:patientsummary";
		} else {
		    if (prefix.equals("ds")) {
			return "http://www.w3.org/2000/09/xmldsig#";
		    }
		    if (prefix.equals("xenc")) {
			return "http://www.w3.org/2001/04/xmlenc#";
		    }
		}
		return XMLConstants.NULL_NS_URI;
	    }

	    public String getPrefix(String namespaceURI) {
		if (namespaceURI.equals("urn:fue:epa:xml:ns:patientsummary")) {
		    return "epa-ps";
		}
		if (namespaceURI.equals("http://www.w3.org/2000/09/xmldsig#")) {
		    return "ds";
		}
		if (namespaceURI.equals("http://www.w3.org/2001/04/xmlenc#")) {
		    return "xenc";
		}
		// return "ns";
		return XMLConstants.NULL_NS_URI;
	    }

	    public Iterator getPrefixes(String namespaceURI) {
		ArrayList list = new ArrayList();
		if (namespaceURI.equals("urn:hl7-org:v3")) {
		    list.add("ns");
		}
		return list.iterator();
	    }
	});

	return xpath;
    }

    /**
     * erstellt ein neues Document
     * 
     * @return
     * @throws EncryptionException
     */
    private static Document generateNewDocument() throws EncryptionException {
	javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
	dbf.setNamespaceAware(true);
	javax.xml.parsers.DocumentBuilder db = null;
	try {
	    db = dbf.newDocumentBuilder();
	} catch (ParserConfigurationException e) {
	    throw new EncryptionException("Probleme bei erstellen des XML-Dokuments mit DocumentBuilder.");
	}
	Document document = db.newDocument();

	return document;
    }

    /**
     * Generates a (RSA) key pair usgin the given
     * encryption algorithm and key size.
     * 
     * @param algorithm the algorithm to use for generating the key pair
     * @param keySize the keysize
     * @return generated KeyPair
     * @throws EncryptionException if the requested algorithm is not available in the environment
     */
    public KeyPair generateKeyPair(String algorithm, int keySize) throws EncryptionException {
	SecureRandom random = new SecureRandom();
	KeyPairGenerator generator = null;
	try {
	    generator = KeyPairGenerator.getInstance(algorithm);
	    generator.initialize(keySize, random);
	} catch (NoSuchAlgorithmException e) {
	    throw new EncryptionException("Verschlüsselungsalgorithmus: " + algorithm
		    + " für die Erstellung von Schlüsselpaaren wird nicht unterstützt.", e);
	} 

	return generator.generateKeyPair();
    }

    /**
     * Get the DER-encoded SubjectKeyIdentifier.
     *
     * @param certificate {@link X509Certificate}
     * @return the DER-encoded SubjectKeyIdentifier or null if it is not present.
     */
    public static byte[] getSubjectKeyIdentifier(X509Certificate certificate) {
	return certificate.getExtensionValue(SKI_OID);
    }

}
