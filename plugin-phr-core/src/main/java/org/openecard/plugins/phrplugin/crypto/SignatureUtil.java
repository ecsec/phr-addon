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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.IdResolver;
import org.openecard.crypto.common.sal.CredentialPermissionDenied;
import org.openecard.crypto.common.sal.GenericCryptoSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 * This class provides XML signature generation and validation functions that can be used with a softare or a hardware
 * certificate. This class was provided in its original form by Fraunhofer FOKUS. It has been completely reworked to not
 * use any javax.xml.crypto.dsig** classes because they are not available on Android. Support for smartcards has been
 * added.
 * 
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class SignatureUtil {

    private static Logger logger = LoggerFactory.getLogger(SignatureUtil.class);

    /**
     * Create a signature for the document using the given certificate and private key. The signature will be inserted
     * into the document.
     * 
     * @param document {@link Document} that should be signed
     * @param cert {@link X509Certificate} will be placed as KeyInfo element into the signature and can later be used to
     *            validate it
     * @param privateKey {@link PrivateKey} is used to do the actual signing
     * @return {@code true} if signature generation succeeded, otherwise {@code false}
     */
    public static synchronized boolean sign(final Document document, X509Certificate cert, PrivateKey privateKey) {
	org.apache.xml.security.Init.init();
	return sign(document, document.getDocumentElement(), cert, privateKey);
    }

    /**
     * Create a signature for the document using the signer. The signature will be inserted
     * into the document.
     * 
     * @param document {@link Document} that should be inserted
     * @param signer {@link GenericCryptoSigner} that provides the X509Certificate and does the actual signing
     * @return {@code true} if signature generation succeeded, otherwise {@code false}
     */
    public static synchronized boolean sign(final Document document, GenericCryptoSigner signer) {
	org.apache.xml.security.Init.init();
	return sign(document, document.getDocumentElement(), signer);
    }

    /**
     * Create a signature for the element using the given certificate and private key. The signature will be inserted
     * into the document.
     * 
     * @param document {@link Document} where the signature should be inserted
     * @param element {@link Element} for which a signature should be created
     * @param cert {@link X509Certificate} belonging to the private key
     * @param privateKey {@link PrivateKey} is used to do the actual signing
     * @return {@code true} if signature generation succeeded, otherwise {@code false}
     */
    public static synchronized boolean sign(final Document document, final Element element, X509Certificate cert, 
	    PrivateKey privateKey) {
	org.apache.xml.security.Init.init();
	return applySignature(cert, privateKey, document, element);
    }

    /**
     * Create a signature for the element using the signer. The signature will be inserted
     * into the document.
     * 
     * @param document {@link Document} where the signature should be inserted
     * @param element {@link Element} for which a signature should be created
     * @param signer {@link GenericCryptoSigner} that provides the X509Certificate and does the actual signing
     * @return {@code true} if signature generation succeeded, otherwise {@code false}
     */
    public static synchronized boolean sign(final Document document, final Element element, GenericCryptoSigner signer) {
	org.apache.xml.security.Init.init();
	return applySignature(signer, document, element);
    }

    /**
     * Apply a signature for the given element to the given document. 
     * The signature will be created using the private key.
     * @param cert {@link X509Certificate} belonging to the private key
     * @param privateKey {@link PrivateKey} with which the signature is computed
     * @param doc {@link Document} where the signature should be inserted
     * @param element {@link Element} for which a signature should be created
     * @return {@code true} if the signing succeeded, otherwise {@code false}
     */
    private static boolean applySignature(X509Certificate cert, PrivateKey privateKey, Document doc, Element element) {
	try {
	    XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA,
		    Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
	    doc.getDocumentElement().appendChild(sig.getElement());
	    setId(doc);
	    Transforms transforms = new Transforms(doc);
	    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
	    String attribute = element.getAttribute("Id");
	    if (attribute == null) {
		attribute = element.getAttribute("ID");
	    }
	    sig.addDocument("#" + attribute, transforms, Constants.ALGO_ID_DIGEST_SHA1);

	    sig.addKeyInfo(cert);
	    sig.addKeyInfo(cert.getPublicKey());

	    sig.sign(privateKey);
	} catch (XMLSecurityException e) {
	    logger.error("An error occurred during signature creation.", e);
	    return false;
	}
	return true;
    }

    /**
     * Apply a signature for the given element to the given document. 
     * The signature will be created using the signer.
     * 
     * @param signer {@link GenericCryptoSigner} that provides the X509Certificate and does the actual signing
     * @param doc {@link Document} where the signature should be inserted
     * @param element {@link Element} for which a signature should be created
     * @return {@code true} if the signing succeeded, otherwise {@code false}
     */
    private static boolean applySignature(GenericCryptoSigner signer, Document doc, Element element) {
	try {
	    SmartCardXMLSignature sig = new SmartCardXMLSignature(
		    doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA, Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

	    doc.getDocumentElement().appendChild(sig.getElement());
	    Transforms transforms = new Transforms(doc);
	    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

	    sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

	    X509Certificate cert = (X509Certificate) signer.getJavaSecCertificateChain()[0];
	    sig.addKeyInfo(cert);
	    sig.addKeyInfo(cert.getPublicKey());

	    sig.sign(signer);
	} catch (XMLSecurityException e) {
	    logger.error("An error occurred during signature creation.", e);
	    return false;
	} catch (CertificateException e) {
	    logger.error("An error occurred while reading the certificate.", e);
	    return false;
	} catch (CredentialPermissionDenied e) {
	    logger.error("An error occurred while reading the certificate.", e);
	    return false;
	} catch (IOException e) {
	    logger.error("An error occurred while reading the certificate.", e);
	    return false;
	}
	return true;
    }

    /**
     * Validate the signature for the given document.
     * The signature has to be enveloped.
     * 
     * @param doc {@link Document} whose signature should be validated
     * @return {@code true} if signature validation succeeded, otherwise {@code false}
     */
    public static synchronized boolean validate(Document doc) {
	org.apache.xml.security.Init.init();
	try {
	    // Find Signature element
	    NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
	    if (nl.getLength() == 0) {
		logger.error("Cannot find Signature element.");
		return false;
	    }

	    Element sigElement = (Element) nl.item(0);
	    // Set up required ID attribute
	    setId(doc.getDocumentElement());

	    XMLSignature signature = new XMLSignature(sigElement, "");
	    for (int i = 0; i < signature.getSignedInfo().getLength(); i++) {
		org.apache.xml.security.signature.Reference r = signature.getSignedInfo().item(i);
		logger.debug("Found a reference for URI: '" + r.getURI() + "'");
	    }

	    // Validate the XMLSignature
	    KeyInfo ki = signature.getKeyInfo();
	    if (ki == null) {
		logger.error("No KeyInfo found in Signature.");
		return false;
	    }
	    boolean coreValidity = false;
	    X509Certificate cert = ki.getX509Certificate();
	    if (cert == null) {
		PublicKey pk = ki.getPublicKey();
		if (pk == null) {
		    logger.error("Found neither a Certificate nor a public key.");
		    return false;
		}
		coreValidity = signature.checkSignatureValue(pk);
	    } else {
		coreValidity = signature.checkSignatureValue(cert);
	    }

	    // Check core validation status
	    if (coreValidity == false) {
		logger.error("Signature failed core validation");
		// check the validation status of each Reference
		for (int j = 0; j < signature.getSignedInfo().getLength(); j++) {
		    Reference reference = signature.getSignedInfo().item(j);
		    boolean refValid = reference.verify();
		    logger.error("reference[" + j + "] " + reference.getURI() + " validity status: " + refValid);
		}
	    } else {
		logger.debug("Signature passed core validation");
	    }

	    return coreValidity;
	} catch (XMLSecurityException e) {
	    logger.error("An error occurred during signature validation." , e);
	    return false;
	}
    }

    /**
     * Validate the signature for the given element.
     * The signature has to be enveloped.
     * 
     * @param element {@link Element} whose signature should be validated
     * @return {@code true} if signature validation succeeded, otherwise {@code false}
     */
    public static synchronized boolean validate(Element element) {
	try {
	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    Document doc = dbf.newDocumentBuilder().newDocument();
	    doc.appendChild(doc.importNode(element, true));

	    return validate(doc);
	} catch (ParserConfigurationException e) {
	    logger.error("Could not create document from element.", e);
	    return false;
	}
    }

    /**
     * Ensure the element Ids are set correctly or else the dereferencing will fail.
     * 
     * @param n {@link Node} to start checking the Ids
     */
    static void setId(Node n) {
	if (n instanceof Element) {
	    NamedNodeMap attributes = n.getAttributes();
	    if (attributes != null) {
		Node namedItem = attributes.getNamedItem("Id");
		if (namedItem == null) {
		    namedItem = attributes.getNamedItem("ID");
		}
		if (namedItem != null) {
		    Attr id = (Attr) namedItem;
		    IdResolver.registerElementById((Element) n, id);
		}
	    }
	    for (int i = 0; i < n.getChildNodes().getLength(); i++) {
		setId(n.getChildNodes().item(i));
	    }
	} else if(n instanceof Document) {
	    setId(((Document) n).getDocumentElement());
	}
    }

}
