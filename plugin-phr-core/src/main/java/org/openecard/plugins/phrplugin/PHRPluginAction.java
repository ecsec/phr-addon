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

package org.openecard.plugins.phrplugin;

import fue_epa.capabilitylist.CapabilityList;
import fue_epa.recordkey.RecordKey;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.hl7.v3.II;
import org.omg.spec.rlus._201012.rlusgeneric.InitializeRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericResponse;
import org.omg.spec.rlus._201012.rlusgeneric.PutRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlustypes.RLUSStatusCode;
import org.omg.spec.rlus._201012.rlustypes.RLUSsemanticSignifier;
import org.openecard.addon.Context;
import org.openecard.addon.bind.AppPluginAction;
import org.openecard.addon.bind.Attachment;
import org.openecard.addon.bind.BindingResult;
import org.openecard.addon.bind.BindingResultCode;
import org.openecard.addon.bind.Body;
import org.openecard.bouncycastle.crypto.tls.ProtocolVersion;
import org.openecard.bouncycastle.crypto.tls.TlsAuthentication;
import org.openecard.bouncycastle.util.encoders.Base64;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.sal.util.InsertCardDialog;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.FileUtils;
import org.openecard.common.util.Pair;
import org.openecard.common.util.StringUtils;
import org.openecard.crypto.common.keystore.KeyStoreSigner;
import org.openecard.crypto.common.sal.GenericCryptoSigner;
import org.openecard.crypto.tls.ClientCertDefaultTlsClient;
import org.openecard.crypto.tls.ClientCertTlsClient;
import org.openecard.crypto.tls.auth.CredentialFactory;
import org.openecard.crypto.tls.auth.DynamicAuthentication;
import org.openecard.crypto.tls.auth.SimpleKeyStoreCredentialFactory;
import org.openecard.crypto.tls.auth.SimpleSmartCardCredentialFactory;
import org.openecard.gui.UserConsent;
import org.openecard.plugins.phrplugin.crypto.CardCrypto;
import org.openecard.plugins.phrplugin.crypto.EncryptionException;
import org.openecard.plugins.phrplugin.crypto.IssueAccessAssertionContract;
import org.openecard.plugins.phrplugin.crypto.MDOCrypto;
import org.openecard.plugins.phrplugin.crypto.SignatureUtil;
import org.openecard.plugins.phrplugin.soap.SOAP;
import org.openecard.plugins.ws.PHRMarshaller;
import org.openecard.recognition.CardRecognition;
import org.openecard.ws.marshal.MarshallingTypeException;
import org.openecard.ws.marshal.WSMarshallerException;
import org.openecard.ws.soap.SOAPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2002._03.xkms.KeyBindingType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


/**
 * Main class of the PHR Plugin.
 * It gets called when a request for a resource this plugin can handle arrives through a binding.
 * The internal processing mainly takes place according to the requests action parameter.
 * 
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class PHRPluginAction implements AppPluginAction {

    private static final Logger logger = LoggerFactory.getLogger(PHRPluginAction.class);
    private static final String DSI_NAME_EF_VERWEIS = "EF.Verweis";
    private static final String CARD_TYPE_GERMAN_HEALTH_CARE_CARD = "http://ws.gematik.de/egk/1.0.0";
    private static final byte[] CARD_APP_HEALTH_CARE = StringUtils.toByteArray("D27600000102");
    private static final byte[] CARD_APP_ESIGN = StringUtils.toByteArray("A000000167455349474E");
    private static final int KEYSIZE = 2048;
    private static final String KEYALGORITHM = "RSA";
    private static final String XSLT_STYLESHEET = "medplan2xhtml.xsl";
    private static final String XHTML = "xhtml";
    private static final String TEXT_XML = "text/xml";
    private static final String TEXT_HTML = "text/html";

    private Dispatcher dispatcher;
    private CardRecognition rec;
    private UserConsent gui;
    private CardStateMap map;
    private PHRMarshaller m;
    private Document assertion;

    @Override
    public void init(Context ctx) {
	dispatcher = ctx.getDispatcher();
	gui = ctx.getUserConsent();
	rec = ctx.getRecognition();
	map = ctx.getCardStates();
	m = new PHRMarshaller();
    }

    @Override
    public void destroy() {
	// nothing to do
    }

    @Override
    public BindingResult execute(Body requestBody, Map<String, String> parameters, List<Attachment> attachments) {
	String actionParm = parameters.get("action");
	if (actionParm == null) {
	    BindingResult bindingResult = new BindingResult(BindingResultCode.MISSING_PARAMETER);
	    bindingResult.setResultMessage("Mandatory parameter 'action' is missing.");
	    return bindingResult;
	} 
	ActionEnum action;
	try {
	    action = ActionEnum.get(actionParm);
	    logger.debug("Action is: {}", action);
	} catch (IllegalArgumentException e) {
	    BindingResult bindingResult = new BindingResult(BindingResultCode.WRONG_PARAMETER);
	    bindingResult.setResultMessage("Value for parameter 'action' is unknown.");
	    return bindingResult;
	}

	ConnectionHandleType cHandle = waitForCardType(CARD_TYPE_GERMAN_HEALTH_CARE_CARD);
	if (cHandle == null) {
	    String msg = "User cancelled card insertion.";
	    logger.debug(msg);
	    return createInternalErrorResult(msg);
	}
	Pair<EFVerweis, ConnectionHandleType> efVerweis = readEFVerweis(cHandle);
	switch (action) {
	    case LOCATE:
		return locate(cHandle, efVerweis);
	    case INITIALIZE:
		return initialize(parameters, cHandle);
	    case GETPD:
		return getPD(cHandle);
	    case GETINFORMATIONOBJECT:
		if ((parameters.get("issuedTokenTimeout") != null) && (parameters.get("policyIdReference") != null)) {
		    createSignedSAMLAssertion(parameters, cHandle, efVerweis);
		}
		return getInformationObject(cHandle, parameters);
	    case PUTINFORMATIONOBJECT:
		if ((parameters.get("issuedTokenTimeout") != null) && (parameters.get("policyIdReference") != null)) {
		    createSignedSAMLAssertion(parameters, cHandle, efVerweis);
		}
		return putInformationObject(cHandle, parameters, requestBody);
	    case GETSSS:
		return getSupportedSemanticSignifiers(cHandle, parameters);
	    default:
		// should never happen
		return createInternalErrorResult("This code part should be unreachable.");
	}
    }

    private BindingResult getSupportedSemanticSignifiers(ConnectionHandleType cHandle, Map<String, String> parameters) {
	Pair<EFVerweis, ConnectionHandleType> efVerweis = readEFVerweis(cHandle);
	String output = parameters.get("output");
	String encoding = parameters.get("encoding");
	if (efVerweis == null) {
	    return createInternalErrorResult("Reading EF.Verweis failed.");
	}
	cHandle = efVerweis.p2;
	String providerID = ByteUtils.toHexString(efVerweis.p1.getProviderID(), false);
	String recordID = ByteUtils.toHexString(efVerweis.p1.getRecordID(), false);
	SOAP soap = setUpSoapConnection(providerID, recordID, cHandle);
	if (soap == null) {
	    return createInternalErrorResult("Setup of soap connection failed.");
	}
	CapabilityList capabilityList = getCapabilityList(soap, recordID);
	if (capabilityList == null) {
	    return createInternalErrorResult("Could not receive CapabilityList via SOAP.");
	}
	BindingResult result = new BindingResult(BindingResultCode.OK);
	Node node;
	try {
	    node = m.marshal(capabilityList.getSupportedSemanticSignifiers());
	} catch (MarshallingTypeException e) {
	    String msg = "Could not marshal SupportedSematicSignifiers.";
	    logger.error(msg, e);
	    return createInternalErrorResult(msg);
	}
	result.setBody(new Body(node, TEXT_XML));
	return result;
    }

    private void createSignedSAMLAssertion(Map<String, String> parameters, ConnectionHandleType cHandle,
	    Pair<EFVerweis, ConnectionHandleType> efVerweis) {
	int issuedTokenTimeout = Integer.parseInt(parameters.get("issuedTokenTimeout"));
	String policyIdReference = parameters.get("policyIdReference");
	CardCrypto cardCrypto = new CardCrypto(dispatcher, cHandle);
	X509Certificate autnCert = cardCrypto.getAUTNCertificateFromEGK();
	String subjectCCHAUTN = autnCert.getSubjectX500Principal().getName();
	int begin = subjectCCHAUTN.indexOf("CN=") + 3;
	int end = subjectCCHAUTN.indexOf(",");
	String subjectPseudonymCCHAUTN = subjectCCHAUTN.substring(begin, end);
	try {
	    PHRPluginProperies.loadProperties();
	} catch (IOException e) {
	    logger.error("Failed to load PHRPluginProperties", e);
	    logger.error("No SAML assertion will be created.");
	    return;
	}
	String[] urls = PHRPluginProperies.getProperty("provider-urls").split(";");
	Map<String, String> mapping = new HashMap<String, String>();
	for (String s : urls) {
	    mapping.put(s.split(",")[0], s.split(",")[1]);
	}

	String providerURL = mapping.get(efVerweis.p1.getProviderID());
	if (providerURL == null) {
	    String msg = "No URL found for Provider ID " + efVerweis.p1.getProviderID();
	    logger.error(msg);
	    return;
	}
	String subjectCHCIOSIG = null;
	X509Certificate softCert = loadSoftCert();
	if (softCert == null) {
	    logger.error("No SAML assertion will be created.");
	    return;
	}
	subjectCHCIOSIG = softCert.getSubjectX500Principal().getName();
	try {
	    assertion = IssueAccessAssertionContract.buildAccessAssertion(issuedTokenTimeout, 
		    subjectCHCIOSIG, subjectCCHAUTN, providerURL, subjectPseudonymCCHAUTN, 
		    ByteUtils.toHexString(efVerweis.p1.getRecordID(), false), policyIdReference);
	    GenericCryptoSigner signer = new GenericCryptoSigner(dispatcher, cHandle, "PrK.CH.AUTN");
	    boolean signedSuccessfull = SignatureUtil.sign(assertion, signer);
	    if (signedSuccessfull) {
		logger.debug("Successfully signed assertion.");
	    } else {
		logger.debug("Signing the assertion failed.");
	    }
	} catch (Throwable e) {
	    logger.debug("Signing the assertion failed.", e);
	}

	// TODO Optional: Ausgabe eines Hinweistextes im Kartenlesegerät oder am Bildschirm, dass eine Autorisierung
	// (lesend oder schreibend abhängig von der Policy-ID-Referenz) auf die Patientenakte für eine bestimmte Zeit
	// erfolgen soll.

	// TODO SAML Assertion speichern falls erfolgreich
    }

    private X509Certificate loadSoftCert() {
	try {
	    KeyStore keyStore = KeyStore.getInstance("PKCS12");
	    PHRPluginProperies.loadProperties();
	    InputStream fis2 = FileUtils.resolveResourceAsStream(PHRPluginAction.class,
		    PHRPluginProperies.getProperty("cert_file"));
	    keyStore.load(fis2, PHRPluginProperies.getProperty("cert_pw").toCharArray());
	    fis2.close();
	    String alias = PHRPluginProperies.getProperty("cert_alias");
	    return (X509Certificate) keyStore.getCertificateChain(alias)[0];
	} catch (KeyStoreException e) {
	    logger.error("Failed to load software certificate.", e);
	} catch (NoSuchAlgorithmException e) {
	    logger.error("Failed to load software certificate.", e);
	} catch (CertificateException e) {
	    logger.error("Failed to load software certificate.", e);
	} catch (IOException e) {
	    logger.error("Failed to load software certificate.", e);
	}
	return null;
    }

    private BindingResult createInternalErrorResult(String msg) {
	BindingResult bindingResult = new BindingResult(BindingResultCode.INTERNAL_ERROR);
	bindingResult.setResultMessage(msg);
	return bindingResult;
    }

    private BindingResult putInformationObject(ConnectionHandleType cHandle, Map<String, String> parameters,
	    Body requestBody) {
	Pair<EFVerweis, ConnectionHandleType> efVerweis = readEFVerweis(cHandle);
	String semanticSignifier = parameters.get("semanticSignifier");
	byte[] requestBodyValue = null;
	String encoding = parameters.get("encoding");
	if (efVerweis == null) {
	    return createInternalErrorResult("Reading EF.Verweis failed."); 
	}
	cHandle = efVerweis.p2;
	String providerID = ByteUtils.toHexString(efVerweis.p1.getProviderID(), false);
	String recordID = ByteUtils.toHexString(efVerweis.p1.getRecordID(), false);
	SOAP soap = setUpSoapConnection(providerID, recordID, cHandle);
	if (soap == null) {
	    return createInternalErrorResult("Setup of soap connection failed."); 
	}
	CapabilityList capabilityList = getCapabilityList(soap, recordID);
	if (capabilityList == null) {
	    return createInternalErrorResult("Could not receive CapabilityList via SOAP."); 
	}

	boolean ssIsSupported = checkSemanticSignifierSupport(capabilityList, semanticSignifier);
	if (!ssIsSupported) {
	    BindingResult bindingResult = new BindingResult(BindingResultCode.OK);
	    bindingResult.setResultMessage("Semantic Signifier '" + semanticSignifier + "' is not Supported.");
	    return bindingResult;
	}
	if (requestBody != null) {
	    Document d = (Document) requestBody.getValue();
	    String decode = URLDecoder.decode(d.getFirstChild().getFirstChild().getNodeValue().substring(19));
	    if (encoding != null && encoding.equalsIgnoreCase("base64")) {
		requestBodyValue = Base64.decode(decode);
	    } else {
		requestBodyValue = decode.getBytes();
	    }
	}
	List<KeyBindingType> keyBinding = capabilityList.getSupportedKeys().getKeyBinding();
	KeyInfoType keyInfo = keyBinding.get(0).getKeyInfo();
	RSAKeyValueType rsaKeyValue = null;
	KeyValueType keyValue = (KeyValueType) keyInfo.getKeyValue();
	rsaKeyValue = (RSAKeyValueType) keyValue.getRSAKeyValue();
	if (rsaKeyValue.getExponent() == null) {
	    return createInternalErrorResult("CapabilityList is missing SupportedKeys.");
	}
	Document docMDO;
	try {
	    docMDO = m.str2doc(new String(requestBodyValue));
	} catch (SAXException e) {
	    return createInternalErrorResult("Conversion of request body to document failed."); 
	}
	Document encryptedMDO;
	try {
	    encryptedMDO = encryptInformationObject(rsaKeyValue, docMDO);
	} catch (EncryptionException e) {
	    return createInternalErrorResult("Encryption of information object failed."); 
	}

	CardCrypto cc = new CardCrypto(dispatcher, cHandle);
	X509Certificate encCertificateFromEGK = cc.getENCCertificateFromEGK(map);
	String subjectDN = encCertificateFromEGK.getSubjectDN().getName();
	String recordId = ByteUtils.toHexString(efVerweis.p1.getRecordID(), false);
	RLUSStatusCode response = sendMDO(soap, encryptedMDO.getDocumentElement(), recordId, subjectDN, providerID);
	if (response == null) {
	    return createInternalErrorResult("Sending the encrypted information object via soap failed."); 
	}
	if (! response.isSuccess()) {
	    return createInternalErrorResult(response.getMessage()); 
	}
	return new BindingResult(BindingResultCode.OK);
    }

    private Document encryptInformationObject(RSAKeyValueType rsaKeyValue, Document docMDO) throws EncryptionException {
	RSAPublicKeySpec rsa = new RSAPublicKeySpec(new BigInteger(1, rsaKeyValue.getModulus()),
		new BigInteger(1, rsaKeyValue.getExponent()));
	KeyFactory rsaKeyFac;
	try {
	    rsaKeyFac = KeyFactory.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
	    throw new EncryptionException("Could not get keyfactory for RSA algorithm.", e);
	}
	Key key;
	try {
	    key = rsaKeyFac.generatePublic(rsa);
	} catch (InvalidKeySpecException e) {
	    throw new EncryptionException("Given key spec is not usable for RSA.", e);
	}

	MDOCrypto mdoCrypto = new MDOCrypto();
	Document encryptedMDO = mdoCrypto.encryptMDO(docMDO, key);
	return encryptedMDO;
    }

    private BindingResult getInformationObject(ConnectionHandleType cHandle, Map<String, String> parameters) {
	String semanticSignifier = parameters.get("semanticSignifier");
	Pair<EFVerweis, ConnectionHandleType> efVerweis = readEFVerweis(cHandle);
	byte[] responseBodyValue = null;
	String responseBodyMimeType = null;
	String output = parameters.get("output");
	String encoding = parameters.get("encoding");
	if (efVerweis == null) {
	    return createInternalErrorResult("Reading EF.Verweis failed.");
	}
	cHandle = efVerweis.p2;
	String providerID = ByteUtils.toHexString(efVerweis.p1.getProviderID(), false);
	String recordID = ByteUtils.toHexString(efVerweis.p1.getRecordID(), false);
	SOAP soap = setUpSoapConnection(providerID, recordID, cHandle);
	if (soap == null) {
	    return createInternalErrorResult("Setup of soap connection failed.");
	}
	CapabilityList capabilityList = getCapabilityList(soap, recordID);
	if (capabilityList == null) {
	    return createInternalErrorResult("Could not receive CapabilityList via SOAP.");
	}

	boolean ssIsSupported = checkSemanticSignifierSupport(capabilityList, semanticSignifier);
	if (!ssIsSupported) {
	    BindingResult bindingResult = new BindingResult(BindingResultCode.OK);
	    bindingResult.setResultMessage("Semantic Signifier '" + semanticSignifier + "' is not Supported.");
	    return bindingResult;
	}
	ListRLUSGenericResponse listRLUSGenericResponse = getMDO(soap, semanticSignifier, cHandle, recordID);
	if (listRLUSGenericResponse == null) {
	    return createInternalErrorResult("Could not receive ListRLUSGenericResponse via SOAP.");
	}

	if (listRLUSGenericResponse.getAny().isEmpty()) {
	    RLUSStatusCode rlusStatusCode = listRLUSGenericResponse.getRLUSStatusCode();
	    System.out.println(rlusStatusCode.isSuccess());
	    System.out.println(rlusStatusCode.getMessage());
	    if (! rlusStatusCode.isSuccess() && rlusStatusCode.getMessage() != null) {
		return createInternalErrorResult(rlusStatusCode.getMessage());
	    }
	    String msg = "Failed to receive information object, although RLUSStatusCode is success.";
	    return createInternalErrorResult(msg);
	}
	Document responseDoc;
	try {
	    Element content = (Element) listRLUSGenericResponse.getAny().get(0);
	    Document superEncMdo = m.str2doc(m.doc2str(content), true);
	    logger.debug("Starting with decryption of information object.");
	    CardCrypto cardCrypto = new CardCrypto(dispatcher, cHandle);
	    responseDoc = cardCrypto.superDecryptMDO(superEncMdo);
	    logger.debug("Decrypted information object: {}", m.doc2str(responseDoc));
	} catch (SAXException e) {
	    logger.error("Conversion of string to document failed.", e);
	    return createInternalErrorResult("Conversion of string to document failed.");
	} catch (EncryptionException e) {
	    logger.error("Decryption of information object failed.", e);
	    return createInternalErrorResult("Decryption of information object failed.");
	} catch (TransformerException e) {
	    logger.error("Conversion of document to string failed.", e);
	    return createInternalErrorResult("Conversion of document to string failed.");
	}

	try {
	    responseBodyValue = m.doc2str(responseDoc).getBytes();
	} catch (TransformerException e) {
	    return createInternalErrorResult("Converting response document to string failed.");
	}
	responseBodyMimeType = TEXT_XML;

	if (output != null && output.equalsIgnoreCase(XHTML)) {
	    String xhtml = transformToXHTML(responseDoc);
	    // fix meta tag 
	    xhtml = xhtml.replace("<META http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">", "<META http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>");
	    if (xhtml != null) {
		responseBodyValue = xhtml.getBytes();
		responseBodyMimeType = TEXT_HTML;
	    } else {
		logger.error("Tranformation to XHTML failed; returning untransformed document.");
	    }
	}

	if (encoding != null && encoding.equalsIgnoreCase("base64")) {
	    logger.debug("Encoding MDO with base64.");
	    responseBodyValue = Base64.encode(responseBodyValue);
	}
	BindingResult bindingResult = new BindingResult(BindingResultCode.OK);
	try {
	    DocumentBuilderFactory fac = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = fac.newDocumentBuilder();
	    Document d = builder.newDocument();
	    Node e = d.createElement("base64Content");
	    e.appendChild(d.createTextNode(new String(responseBodyValue)));
	    d.appendChild(e);
	    bindingResult.setBody(new Body(d, responseBodyMimeType));
	} catch (ParserConfigurationException e) {
	    String msg = "Failed to create response body";
	    logger.error(msg, e);
	    return createInternalErrorResult(msg);
	}
	return bindingResult;
    }

    private String transformToXHTML(Document responseDoc) {
	try {
	    InputStream xslFileStream = FileUtils.resolveResourceAsStream(this.getClass(), XSLT_STYLESHEET);
	    StreamSource xslStreamSource = new StreamSource(xslFileStream);
	    Transformer transformer = TransformerFactory.newInstance().newTransformer(xslStreamSource);
	    ByteArrayOutputStream sw = new ByteArrayOutputStream();
	    StreamResult htmlResult = new StreamResult(sw);
	    transformer.transform(new DOMSource(responseDoc), htmlResult);
	    return sw.toString();
	} catch (TransformerException e) {
	    logger.error("Tranformation to XHTML failed.", e);
	} catch (TransformerFactoryConfigurationError e) {
	    logger.error("Tranformation to XHTML failed.", e);
	} catch (IOException e) {
	    logger.error("Tranformation to XHTML failed.", e);
	}
	return null;
    }

    private SOAP setUpSoapConnection(String providerID, String recordID, ConnectionHandleType handle) {
	String serverAddress;
	boolean useSoftSSLCert = false;
	URL url;
	SOAP soap;
	// map providerID to server address
	try {
	    PHRPluginProperies.loadProperties();
	    String[] urls = PHRPluginProperies.getProperty("provider-urls").split(";");
	    Map<String, String> mapping = new HashMap<String, String>();
	    for (String s : urls) {
		mapping.put(s.split(",")[0], s.split(",")[1]);
	    }

	    serverAddress = mapping.get(providerID);

	    String property = PHRPluginProperies.getProperty("use-soft-ssl-auth-cert");
	    if (property != null && property.equalsIgnoreCase("true")) {
		useSoftSSLCert = true;
	    }
	} catch (IOException e) {
	    logger.error("Couldn't get server Address from local mapping properties file; using fallback.", e);
	    serverAddress = "https://10.202.4.123:8443/mockRLUSGenericSOAPBinding";
	}
	logger.debug("Server address: {}", serverAddress);
	try {
	    url = new URL(serverAddress);
	} catch (MalformedURLException e) {
	    String msg = "Server Address of provider is not a valid URL";
	    logger.error(msg, e);
	    return null;
	}


	handle = CardUtils.connectToCardApplication(handle, CARD_APP_ESIGN, dispatcher);
	if (handle == null) {
	    logger.error("Failed to connect to esign application.");
	    return null;
	}

	CredentialFactory fac;
	if (useSoftSSLCert) {
	    try {
		String filePath = PHRPluginProperies.getProperty("cert_file");
		char[] password = PHRPluginProperies.getProperty("cert_pw").toCharArray();
		String alias = PHRPluginProperies.getProperty("cert_alias");
		InputStream is = FileUtils.resolveResourceAsStream(PHRPluginAction.class, filePath);
		KeyStoreSigner signer = new KeyStoreSigner(KeyStore.getInstance("PKCS12"), is, password, alias);
		fac = new SimpleKeyStoreCredentialFactory(signer);
	    } catch (KeyStoreException e) {
		logger.error("Failed to create CredentialFactory.", e);
		return null;
	    } catch (IOException e) {
		logger.error("Failed to create CredentialFactory.", e);
		return null;
	    }
	} else {
	    GenericCryptoSigner signer = new GenericCryptoSigner(dispatcher, handle, "PrK.CH.AUTN");
	    fac = new SimpleSmartCardCredentialFactory(signer);
	}
	TlsAuthentication tlsAuth = new DynamicAuthentication(null, null, fac);
	// FIXME: verify certificate chain as soon as a usable solution exists for the trust problem
	ClientCertTlsClient tlsClient = new ClientCertDefaultTlsClient(url.getHost());
	tlsClient.setAuthentication(tlsAuth);
	tlsClient.setClientVersion(ProtocolVersion.TLSv11);

	try {
	    soap = new SOAP(url, dispatcher, tlsClient, m);
	} catch (SOAPException e) {
	    String msg = "SOAP module could not be initialized.";
	    logger.error(msg, e);
	    return null;
	}
	return soap;
    }

    private BindingResult getPD(ConnectionHandleType cHandle) {
	Pair<byte[], ConnectionHandleType> efPD = 
		CardUtils.readDSI(cHandle, "EF.PD", CARD_APP_HEALTH_CARE, dispatcher, map);
	if (efPD == null) {
	    return createInternalErrorResult("Could not read EF.PD from health care application.");
	}

	Body body;
	try {
	    int lengthPD = ByteUtils.toInteger(new byte[] { efPD.p1[0], efPD.p1[1] });
	    // contents of ef.pd are gzipped
	    // offset is 2 because the first two bytes contain the length
	    GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(efPD.p1, 2, lengthPD));
	    ByteArrayOutputStream out = new ByteArrayOutputStream();
	    int len;
	    byte[] buffer = new byte[4096];
	    while ((len = gzis.read(buffer)) != -1) {
		out.write(buffer, 0, len);
	    }
	    String docStr = new String(out.toByteArray(), "iso-8859-15");
	    docStr = docStr.replace("ISO-8859-15", "UTF-8");
	    body = new Body(m.str2doc(docStr), TEXT_XML);
	} catch (IOException e) {
	    String msg = "Unzipping of EF.PD failed.";
	    logger.error(msg, e);
	    return createInternalErrorResult(msg);
	} catch (SAXException e) {
	    String msg = "Creation of response body failed.";
	    logger.error(msg, e);
	    return createInternalErrorResult(msg);
	}
	BindingResult bindingResult = new BindingResult(BindingResultCode.OK);
	bindingResult.setBody(body);
	return bindingResult;
    }

    private BindingResult initialize(Map<String, String> parameters, ConnectionHandleType cHandle) {
	String authenticationCode = parameters.get("authenticationCode");
	String providerID = parameters.get("providerID");
	//TODO check parameters 

	CardCrypto cardCrypto = new CardCrypto(dispatcher, cHandle);
	X509Certificate certEGK = cardCrypto.getENCCertificateFromEGK(map);
	if (certEGK == null) {
	    return createInternalErrorResult("Failed to read ENC certificate from eGK");
	}

	MDOCrypto enc = new MDOCrypto();

	RSAPublicKey publicKeyRecord;
	Document encPrivKeyRecord;
	try {
	    // Generate the record key pair
	    KeyPair keyPairRecord = enc.generateKeyPair(KEYALGORITHM, KEYSIZE);
	    publicKeyRecord = convertToRSAPublicKey(keyPairRecord.getPublic());
	    // Create the, with the eGK-publicKey hybrid-encrypted, privateKey of the record
	    byte[] ski = MDOCrypto.getSubjectKeyIdentifier(certEGK);
	    PrivateKey privateKey = keyPairRecord.getPrivate();
	    PublicKey publicKey = certEGK.getPublicKey();
	    encPrivKeyRecord = enc.encryptPrivateKeyRecord(privateKey, publicKey, ski);
	    privateKey = null;
	    keyPairRecord = null;
	} catch (EncryptionException e) {
	    logger.error(e.getMessage(), e);
	    return createInternalErrorResult(e.getMessage());
	}

	byte[] cert = cardCrypto.getEncodedAUTNCertificateFromEGK();
	if (cert == null) {
	    return createInternalErrorResult("Could not read AUTN certificate from eSign application.");
	}
	RecordKey recordKey = RLUSMessages.createRecordKey(authenticationCode, cert, publicKeyRecord, encPrivKeyRecord);

	InitializeRLUSGenericRequest request = RLUSMessages.createInitializeRLUSGenericRequest(recordKey);

	SOAP soap = setUpSoapConnection(providerID, "", cHandle);
	if (soap == null) {
	    return createInternalErrorResult("Setup of soap connection failed.");
	}
	Object response;
	try {
	    response = soap.sendRequest(request, assertion);
	} catch (SOAPException e) {
	    return createInternalErrorResult("Sending of initialize request failed.");
	} catch (DispatcherException e) {
	    return createInternalErrorResult("Sending of initialize request failed.");
	}
	if (! (response instanceof RLUSStatusCode)) {
	    return createInternalErrorResult("Response is not of expected type RLUSStatusCode.");
	} 
	RLUSStatusCode statusCode = (RLUSStatusCode) response;
	if (! statusCode.isSuccess()) {
	    return createInternalErrorResult("Server returned an error status as response to initialize request.");
	}
	II ii = statusCode.getRecordID().get(0);
	String recordIDString = ii.getRoot();
	logger.debug("RecordID from RLUSStatusCode: " + recordIDString);
	if (! CardUtils.writeEFVerweis(cHandle, providerID, recordIDString, dispatcher)) {
	    return createInternalErrorResult("Writing/Updating EF.Verweis failed.");
	}
	BindingResult bindingResult = new BindingResult(BindingResultCode.OK);
	bindingResult.setResultMessage(recordIDString);
	return bindingResult;
    }

    private RSAPublicKey convertToRSAPublicKey(PublicKey publicRecordKey) throws EncryptionException {
	try {
	    RSAPublicKey publicKey;
	    publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").translateKey(publicRecordKey);
	    return publicKey;
	} catch (NoSuchAlgorithmException e) {
	    throw new EncryptionException("Conversion to RSA key failed.", e);
	} catch (InvalidKeyException e) {
	    throw new EncryptionException("Conversion to RSA key failed.", e);
	}
    }

    private BindingResult locate(ConnectionHandleType cHandle, Pair<EFVerweis, ConnectionHandleType> efVerweis) {
	if (efVerweis == null) {
	    return createInternalErrorResult("Reading EF.Verweis failed.");
	}
	byte[] recordAndProviderID = ByteUtils.concatenate(efVerweis.p1.getRecordID(), efVerweis.p1.getProviderID());
	BindingResult bindingResult = new BindingResult(BindingResultCode.OK);
	bindingResult.setResultMessage(ByteUtils.toHexString(recordAndProviderID, false));
	return bindingResult;
    }

    private Pair<EFVerweis, ConnectionHandleType> readEFVerweis(ConnectionHandleType cHandle) {
	EFVerweis efVerweis = null;
	Pair<byte[], ConnectionHandleType> efVerweisData = 
		CardUtils.readDSI(cHandle, DSI_NAME_EF_VERWEIS, CARD_APP_HEALTH_CARE, dispatcher, map);
	if (efVerweisData != null) {
	    efVerweis = new EFVerweis(efVerweisData.p1);
	    logger.debug("EF.Verweis data: {}", efVerweis);
	}
	return new Pair<EFVerweis, ConnectionHandleType>(efVerweis, efVerweisData.p2);
    }

    /**
     * Wait until a card of the specified card type was inserted.
     * 
     * @param cardType The type of the card that should be inserted.
     * @return The ConnectionHandle of the inserted card or null if no card was inserted.
     */
    protected ConnectionHandleType waitForCardType(String cardType) {
	String cardName = rec.getTranslatedCardName(cardType);
	InsertCardDialog uc = new InsertCardDialog(gui, map, cardType, cardName);
	return uc.show();
    }

    private RLUSStatusCode sendMDO(SOAP soap, Element encryptedMDO, String recordId, String subjectDN, 
	    String providerId) {
	PutRLUSGenericRequest putRLUSGenericRequest = 
		RLUSMessages.createPutRLUSGenericRequest(encryptedMDO, recordId, subjectDN, providerId);
	Object response;
	try {
	    response = soap.sendRequest(putRLUSGenericRequest, assertion);
	} catch (SOAPException e) {
	    logger.error("SOAP communication failed.", e);
	    return null;
	} catch (DispatcherException e) {
	    logger.error("SOAP communication failed.", e);
	    return null;
	}
	if (! (response instanceof RLUSStatusCode)) {
	    logger.error("Couldn't retrieve information object. Did not receive a RLUSStatusCode.");
	    return null;
	} 
	return (RLUSStatusCode) response;
    }

    private boolean checkSemanticSignifierSupport(CapabilityList capabilityList, String semanticSignifier) {
	logger.debug("Matching semantic signifier {} with capability list.", semanticSignifier);
	for (RLUSsemanticSignifier ss : capabilityList.getSupportedSemanticSignifiers().getRLUSsemanticSignifier()) {
	    logger.debug("Comparing {} with {}:", semanticSignifier, ss.getName());
	    if (ss.getName().equalsIgnoreCase(semanticSignifier)) {
		logger.debug("Semantic signifier matches.");
		return true;
	    } else {
		logger.debug("Semantic signifier does not match.");
	    }
	}
	return false;
    }

    private CapabilityList getCapabilityList(SOAP soap, String recordId) {
	CapabilityList capabilityList = null;
	try {
	    ListRLUSGenericRequest list = RLUSMessages.createListRLUSGenericRequest("CL", recordId);
	    Object response = soap.sendRequest(list, assertion);
	    if (! (response instanceof ListRLUSGenericResponse)) {
		throw new SOAPException("Couldn't get CapabilityList. Expected response of type " +
				"ListRLUSGenericResponse but received " + response.getClass());
	    } 
	    ListRLUSGenericResponse listRLUSGenericResponse = (ListRLUSGenericResponse) response;
	    Element elemCapabilityList = (Element) listRLUSGenericResponse.getAny().get(0);
	    String localName = elemCapabilityList.getLocalName();
	    if (localName == null || ! localName.equals("CapabilityList")) {
		throw new SOAPException("Couldn't get CapabilityList. It wasn't contained in ListRLUSGenericResponse.");
	    }
	    boolean isValid = SignatureUtil.validate(elemCapabilityList);

	    if (isValid) {
		logger.debug("CapabilityList passed signature validation.");
		elemCapabilityList = (Element) listRLUSGenericResponse.getAny().get(0);
		capabilityList = (CapabilityList) m.unmarshal(elemCapabilityList);
	    } else {
		logger.error("CapabilityList failed signature validation.");
	    }

	    return capabilityList;
	} catch (SOAPException e) {
	    logger.error("Error during SOAP communication.", e);
	} catch (MarshallingTypeException e) {
	    logger.error("Unmarsalling of CapabilityList failed.", e);
	} catch (WSMarshallerException e) {
	    logger.error("Unmarsalling of CapabilityList failed.", e);
	} catch (DispatcherException e) {
	    logger.error("Error during SOAP communication.", e);
	} catch (ParserConfigurationException e) {
	    logger.error("Construction of ListRLUSGenericRequest failed", e);
	}
	return capabilityList;
    }

    private ListRLUSGenericResponse getMDO(SOAP soap, String semanticSignifier, ConnectionHandleType cHandle, 
	    String recordId) {
	try {
	    ListRLUSGenericRequest list = RLUSMessages.createListRLUSGenericRequest(semanticSignifier, recordId);
	    Object response = soap.sendRequest(list, assertion);

	    if (!(response instanceof ListRLUSGenericResponse)) {
		logger.error("Couldn't retrieve information object. Did not receive a ListRLUSGenericResponse.");
		return null;
	    }
	    ListRLUSGenericResponse listRLUSGenericResponse = (ListRLUSGenericResponse) response;
	    return listRLUSGenericResponse;
	} catch (SOAPException e) {
	    logger.error("SOAP communication failed.", e);
	} catch (DispatcherException e) {
	    logger.error("SOAP communication failed.", e);
	} catch (ParserConfigurationException e) {
	    logger.error("Construction of ListRLUSGenericRequest failed", e);
	} 
	return null;
    }

}
