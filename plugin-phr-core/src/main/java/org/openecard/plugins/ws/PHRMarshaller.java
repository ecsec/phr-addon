/****************************************************************************
 * Copyright (C) 2012 HS Coburg.
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

package org.openecard.plugins.ws;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.hl7.v3.II;
import org.omg.spec.rlus._201012.rlusgeneric.InitializeRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericResponse;
import org.omg.spec.rlus._201012.rlusgeneric.PutRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.PutRLUSGenericResponse;
import org.omg.spec.rlus._201012.rlustypes.FilterCriteriaType;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct.CBRContext;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct.SecurityContext;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct.SecurityContext.SourceIdentity;
import org.omg.spec.rlus._201012.rlustypes.RLUSSearchStruct;
import org.omg.spec.rlus._201012.rlustypes.RLUSSearchStructType.SearchByCriteria;
import org.omg.spec.rlus._201012.rlustypes.RLUSStatusCode;
import org.omg.spec.rlus._201012.rlustypes.RLUSsemanticSignifier;
import org.omg.spec.rlus._201012.rlustypes.SearchAttributesType;
import org.openecard.bouncycastle.util.encoders.Base64;
import org.openecard.ws.marshal.MarshallingTypeException;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerException;
import org.openecard.ws.marshal.WhitespaceFilter;
import org.openecard.ws.soap.MessageFactory;
import org.openecard.ws.soap.SOAPBody;
import org.openecard.ws.soap.SOAPException;
import org.openecard.ws.soap.SOAPMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3._2000._09.xmldsig_.CanonicalizationMethodType;
import org.w3._2000._09.xmldsig_.DigestMethodType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.ReferenceType;
import org.w3._2000._09.xmldsig_.SignatureMethodType;
import org.w3._2000._09.xmldsig_.SignatureType;
import org.w3._2000._09.xmldsig_.SignatureValueType;
import org.w3._2000._09.xmldsig_.SignedInfoType;
import org.w3._2000._09.xmldsig_.TransformType;
import org.w3._2000._09.xmldsig_.TransformsType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms.KeyBindingType;
import org.w3._2002._03.xkms.StatusType;
import org.w3._2005._08.addressing.AttributedURIType;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import de.fraunhofer.isst.rlus.types.Participant;
import de.fraunhofer.isst.rlus.types.ProvisioningObject;
import de.fraunhofer.isst.rlus.types.RecordTarget;
import de.fraunhofer.isst.rlus.types.RequestObject;
import fue_epa.capabilitylist.AddressInformation;
import fue_epa.capabilitylist.CapabilityList;
import fue_epa.capabilitylist.SupportedCommunicationPattern;
import fue_epa.capabilitylist.SupportedCommunicationPatterns;
import fue_epa.capabilitylist.SupportedKeys;
import fue_epa.capabilitylist.SupportedSemanticSignifiers;
import fue_epa.recordkey.RecordKey;


/**
 * Marshaller implementation for the PHR plugin.
 *
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class PHRMarshaller implements WSMarshaller {

    private static final Logger logger = LoggerFactory.getLogger(PHRMarshaller.class);

    private DocumentBuilderFactory documentBuilderFactory;
    private DocumentBuilder documentBuilder;
    private MessageFactory soapFactory;

    public PHRMarshaller() {
	documentBuilderFactory = null;
	documentBuilder = null;
	soapFactory = null;
	try {
	    documentBuilderFactory = DocumentBuilderFactory.newInstance();
	    documentBuilderFactory.setNamespaceAware(true);
	    documentBuilder = documentBuilderFactory.newDocumentBuilder();
	    soapFactory = MessageFactory.newInstance();
	} catch (Exception ex) {
	    ex.printStackTrace(System.err);
	    System.exit(1); // non recoverable
	}
    }


    @Override
    public void addXmlTypeClass(Class xmlTypeClass) throws MarshallingTypeException {
	// not available in this implementation
    }

    @Override
    public void removeAllTypeClasses() {
	// not available in this implementation
    }


    @Override
    public synchronized String doc2str(Node doc) throws TransformerException {
	TransformerFactory transfac = TransformerFactory.newInstance();
	Transformer trans = transfac.newTransformer();

	StringWriter sw = new StringWriter();
	StreamResult result = new StreamResult(sw);
	DOMSource source = new DOMSource(doc);
	trans.transform(source, result);
	String xmlString = sw.toString();

	return xmlString;
    }

    @Override
    public synchronized Document marshal(Object o) throws MarshallingTypeException {
	Document document = documentBuilder.newDocument();
	document.setXmlStandalone(true);

	Element rootElement = null;

	if (o instanceof ListRLUSGenericRequest) {
	    ListRLUSGenericRequest listRLUSGenericRequest = (ListRLUSGenericRequest) o;
	    rootElement = document.createElement("rlus:" + o.getClass().getSimpleName());
	    rootElement.setAttribute("xmlns:tns", "http://isst.fraunhofer.de/rlus/types");
	    rootElement.setAttribute("xmlns:rlus", "http://www.omg.org/spec/RLUS/201012/RLUSGeneric");
	    rootElement.setAttribute("xmlns:rlustypes", "http://www.omg.org/spec/RLUS/201012/RLUStypes");
	    RLUSSearchStruct rlusSearchStruct = listRLUSGenericRequest.getRLUSSearchStruct();
	    if (rlusSearchStruct != null) {
		Element elemSearchStruct = document.createElement("rlustypes:" + "RLUSSearchStruct");
		String semanticSignifiername = rlusSearchStruct.getSemanticSignifiername();
		if (semanticSignifiername != null) {
		    elemSearchStruct.setAttribute("semantic-signifiername", semanticSignifiername);
		}
		Element elemSearchByCriteria = document.createElement("rlustypes:" + "searchByCriteria");
		elemSearchStruct.appendChild(elemSearchByCriteria);
		Element elemFilterCriteria = document.createElement("rlustypes:" + "FilterCriteria");
		elemSearchByCriteria.appendChild(elemFilterCriteria);
		SearchByCriteria searchByCriteria = listRLUSGenericRequest.getRLUSSearchStruct().getSearchByCriteria();
		FilterCriteriaType filterCriteria = searchByCriteria.getFilterCriteria();
		Node node = (Node) filterCriteria.getAny();
		elemFilterCriteria.appendChild(document.importNode(node, true));
		Element elemSearchAttributes = document.createElement("rlustypes:" + "SearchAttributes");
		elemSearchByCriteria.appendChild(elemSearchAttributes);
		Element elemField = document.createElement("rlustypes:" + "Field");
		SearchAttributesType searchAttributes = rlusSearchStruct.getSearchByCriteria().getSearchAttributes();
		elemField.setAttribute("name", searchAttributes.getField().get(0).getName());
		elemField.setAttribute("qualifier", searchAttributes.getField().get(0).getQualifier());
		elemSearchAttributes.appendChild(elemField);
		rootElement.appendChild(elemSearchStruct);
	    }
	    Element elemMaxResultStreams = document.createElement("rlus:" + "maxResultStreams");
	    elemMaxResultStreams.setTextContent(String.valueOf(listRLUSGenericRequest.getMaxResultStreams()));
	    rootElement.appendChild(elemMaxResultStreams);
	    Element elemPreviousResultID = document.createElement("rlus:" + "previousResultID");
	    elemPreviousResultID.setTextContent(listRLUSGenericRequest.getPreviousResultID());
	    rootElement.appendChild(elemPreviousResultID);
	} else if (o instanceof PutRLUSGenericRequest) {
	    PutRLUSGenericRequest putRLUSGenericRequest = (PutRLUSGenericRequest) o;
	    rootElement = document.createElement("rlus:" + o.getClass().getSimpleName());
	    rootElement.setAttribute("xmlns:tns", "http://isst.fraunhofer.de/rlus/types");
	    rootElement.setAttribute("xmlns:rlus", "http://www.omg.org/spec/RLUS/201012/RLUSGeneric");
	    rootElement.setAttribute("xmlns:rlustypes", "http://www.omg.org/spec/RLUS/201012/RLUStypes");
	    String writeCommand = putRLUSGenericRequest.getWriteCommandEnum();
	    Element elemWriteCommand = document.createElement("rlus:" + "writeCommandEnum");
	    elemWriteCommand.setTextContent(writeCommand);
	    rootElement.appendChild(elemWriteCommand);
	    Element elemProvisioningObject = document.createElement("tns:" + "ProvisioningObject");
	    elemProvisioningObject.setAttribute("xmlns:tns", "http://isst.fraunhofer.de/rlus/types");
	    Element elemContent = document.createElement("tns:" + "Content");
	    try {
		Element mdo = (Element) putRLUSGenericRequest.getProvisioningObject().getContent();
		Node imported = document.importNode(mdo, true);
		elemContent.appendChild(imported);
	    } catch (DOMException e) {
		System.out.println("CODE: " + e.code);
	    }
	    elemProvisioningObject.appendChild(elemContent);
	    Element elemRecordTarget = document.createElement("tns:" + "RecordTarget");
	    Element elemRecordId = document.createElement("tns:" + "RecordId");
	    RecordTarget recordTarget = putRLUSGenericRequest.getProvisioningObject().getRecordTarget();
	    elemRecordId.setAttribute("tns:extension", (String) recordTarget.getRecordId());
	    elemRecordTarget.appendChild(elemRecordId);
	    elemProvisioningObject.appendChild(elemRecordTarget);
	    for (Participant p : putRLUSGenericRequest.getProvisioningObject().getParticipants()) {
		Element elemParticipants = document.createElement("tns:" + "Participants");
		elemParticipants.setAttribute("tns:RoleTypeCode", p.getRoleTypeCode());
		elemParticipants.setAttribute("tns:ParticipantTypeCode", p.getParticipantTypeCode());
		Element elemId = document.createElement("tns:" + "Id");
		elemId.setTextContent(p.getId());
		elemParticipants.appendChild(elemId);
		elemProvisioningObject.appendChild(elemParticipants);
	    }
	    for (de.fraunhofer.isst.rlus.types.System s : putRLUSGenericRequest.getProvisioningObject().getSystems()) {

		Element elemSystems = document.createElement("tns:" + "Systems");
		elemSystems.setAttribute("tns:SystemTypeCode", s.getSystemTypeCode());
		Element elemcbrContext = document.createElement("tns:" + "CBRContext");
		Element elemCBRName = document.createElement("tns:" + "CBRName");
		elemCBRName.setTextContent(s.getCBRContext().getCBRName());
		Element elemNetworkName = document.createElement("tns:" + "NetworkName");
		elemNetworkName.setTextContent(s.getCBRContext().getNetworkName());
		Element elemNetworkAddress = document.createElement("tns:" + "NetworkAddress");
		elemNetworkAddress.setTextContent(s.getCBRContext().getNetworkAddress());
		elemcbrContext.appendChild(elemCBRName);
		elemcbrContext.appendChild(elemNetworkName);
		elemcbrContext.appendChild(elemNetworkAddress);
		elemSystems.appendChild(elemcbrContext);
		Element elemId = document.createElement("tns:" + "Id");
		elemId.setTextContent(s.getId());
		elemSystems.appendChild(elemId);
		elemProvisioningObject.appendChild(elemSystems);
	    }
	    rootElement.appendChild(elemProvisioningObject);

	    Element elemRequestSrcStruct = document.createElement("rlustypes:" + "RLUSPutRequestSrcStruct");
	    rootElement.appendChild(elemRequestSrcStruct);
	} else if (o instanceof RLUSStatusCode) {
	    RLUSStatusCode rlusStatusCode = (RLUSStatusCode) o;
	    rootElement = document.createElement("rlustypes:" + o.getClass().getSimpleName());
	    rootElement.setAttribute("xmlns:rlustypes", "http://www.omg.org/spec/RLUS/201012/RLUStypes");
	    Element elemSuccess = document.createElement("rlustypes:" + "success");
	    elemSuccess.setTextContent(String.valueOf(rlusStatusCode.isSuccess()));
	    rootElement.appendChild(elemSuccess);
	} else if (o instanceof PutRLUSGenericResponse) {
	    PutRLUSGenericResponse putRLUSGenericResponse = (PutRLUSGenericResponse) o;
	    rootElement = document.createElement("rlus:" + o.getClass().getSimpleName());
	    rootElement.setAttribute("xmlns:rlus", "http://www.omg.org/spec/RLUS/201012/RLUSGeneric");
	    rootElement.setAttribute("xmlns:rlustypes", "http://www.omg.org/spec/RLUS/201012/RLUStypes");
	    rootElement.appendChild(marshalRLUSStatusCode(putRLUSGenericResponse.getRLUSStatusCode(), document));
	} else if (o instanceof InitializeRLUSGenericRequest) {
	    InitializeRLUSGenericRequest initializeRLUSGenericRequest = (InitializeRLUSGenericRequest) o;
	    rootElement = document.createElement("rlus:" + o.getClass().getSimpleName());
	    rootElement.setAttribute("xmlns:rlus", "http://www.omg.org/spec/RLUS/201012/RLUSGeneric");
	    rootElement.setAttribute("xmlns:rlustypes", "http://www.omg.org/spec/RLUS/201012/RLUStypes");
	    rootElement.appendChild(marshalRecordKey(initializeRLUSGenericRequest.getRecordKey(), document));
	    RLUSInitializeRequestSrcStruct rlusInitializeRequestSrcStruct = initializeRLUSGenericRequest.getRLUSInitializeRequestSrcStruct();
	    rootElement.appendChild(marshalRLUSInitializeRequestSrcStruct(rlusInitializeRequestSrcStruct, document));
	} else if (o instanceof RecordKey) {
	    rootElement = (Element) marshalRecordKey((RecordKey) o, document);
	} else if (o instanceof SignatureType) {
	    rootElement = marshalSignatureType(document, (SignatureType) o);
	} else if (o instanceof SupportedSemanticSignifiers) {
	    SupportedSemanticSignifiers sss = (SupportedSemanticSignifiers) o;
	    rootElement = document.createElement("SupportedSemanticSignifiers");
	    rootElement.setAttribute("xmlns", "fue-epa:capabilitylist");
	    for (RLUSsemanticSignifier signifier : sss.getRLUSsemanticSignifier()) {
		Element elementSignifier = document.createElement("RLUSsemantic-signifier");
		elementSignifier.setAttribute("xmlns", "http://www.omg.org/spec/RLUS/201012/RLUStypes");
		rootElement.appendChild(elementSignifier);
		Element elemName = document.createElement("name");
		elemName.setTextContent(signifier.getName());
		elementSignifier.appendChild(elemName);
		Element elemSignifierID = document.createElement("signifierID");
		elemSignifierID.setTextContent(signifier.getSignifierID());
		elementSignifier.appendChild(elemSignifierID);
		Element elemVersion = document.createElement("name");
		elemVersion.setTextContent(signifier.getVersion());
		elementSignifier.appendChild(elemVersion);
		Element elemschemaDefName = document.createElement("name");
		elemschemaDefName.setTextContent(signifier.getSchemaDefName());
		elementSignifier.appendChild(elemschemaDefName);
		Element elemschemaDefinitionReference = document.createElement("name");
		elemschemaDefinitionReference.setTextContent(signifier.getSchemaDefintionReference());
		elementSignifier.appendChild(elemschemaDefinitionReference);
	    }
	} else {
	    throw new IllegalArgumentException("Cannot marshal " + o.getClass().getSimpleName());
	}
	document.appendChild(rootElement);
	return document;
    }

    private Node marshalRecordKey(RecordKey recordKey, Document document) {
	Element elemRecordKey = document.createElement("recordkey:" + "RecordKey");
	elemRecordKey.setAttribute("xmlns:recordkey", "fue-epa:recordkey");
	elemRecordKey.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
	Element elemCitizenCertificate = document.createElement("recordkey:" + "CitizenCertificate");
	Element elemX509Data = document.createElement("ds:" + "X509Data");
	elemX509Data.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
	Element elemX509Certificate = document.createElement("ds:" + "X509Certificate");
	byte[] bytes = (byte[]) recordKey.getCititzenCertificate().getX509Data().getX509Certificate();
	elemX509Certificate.setTextContent(new String(Base64.encode(bytes)));
	elemX509Data.appendChild(elemX509Certificate);
	elemCitizenCertificate.appendChild(elemX509Data);
	elemRecordKey.appendChild(elemCitizenCertificate);
	Element elemAuthenticationCode = document.createElement("recordkey:" + "authenticationCode");
	elemAuthenticationCode.setTextContent(recordKey.getAuthenticationCode());
	elemRecordKey.appendChild(elemAuthenticationCode);
	Element elemSupportedKeys = document.createElement("recordkey:" + "SupportedKeys");
	Element elemKeyBinding = document.createElement("xkms:" + "KeyBinding");
	elemKeyBinding.setAttribute("xmlns:xkms", "http://www.w3.org/2002/03/xkms#");
	if (recordKey.getSupportedKeys().getKeyBinding().getId() != null) {
	    elemKeyBinding.setAttribute("ID", recordKey.getSupportedKeys().getKeyBinding().getId());
	}
	Element elemKeyUsage = document.createElement("xkms:" + "KeyUsage");
	elemKeyUsage.setTextContent(recordKey.getSupportedKeys().getKeyBinding().getKeyUsage().get(0));
	elemKeyBinding.appendChild(elemKeyUsage);
	Element elemStatus = document.createElement("xkms:" + "Status");
	StatusType status = recordKey.getSupportedKeys().getKeyBinding().getStatus();
	elemStatus.setAttribute("StatusValue", status.getStatusValue());
	elemKeyBinding.appendChild(elemStatus);
	Element elemKeyInfo = document.createElement("ds:" + "KeyInfo");
	elemKeyInfo.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
	Element elemKeyValue = document.createElement("ds:" + "KeyValue");
	Element elemrsaKeyValue = document.createElement("ds:" + "RSAKeyValue");
	Element elemModulus = document.createElement("ds:" + "Modulus");
	KeyValueType keyValue = (KeyValueType) recordKey.getSupportedKeys().getKeyBinding().getKeyInfo().getKeyValue();
	RSAKeyValueType rsaKey = (RSAKeyValueType) keyValue.getRSAKeyValue();
	elemModulus.setTextContent(new String(Base64.encode(rsaKey.getModulus())));
	elemrsaKeyValue.appendChild(elemModulus);
	Element elemExponent = document.createElement("ds:" + "Exponent");
	elemExponent.setTextContent(new String(Base64.encode(rsaKey.getExponent())));
	elemrsaKeyValue.appendChild(elemExponent);
	elemKeyValue.appendChild(elemrsaKeyValue);
	elemKeyInfo.appendChild(elemKeyValue);
	elemKeyBinding.appendChild(elemKeyInfo);
	elemSupportedKeys.appendChild(elemKeyBinding);

	SignatureType signature = recordKey.getSupportedKeys().getSignature();
	if (signature != null) {
	    Element elemSignature = marshalSignatureType(document, signature);
	    elemSupportedKeys.appendChild(elemSignature);
	}
	elemRecordKey.appendChild(elemSupportedKeys);
	Element elemEncryptedPrivateKey = document.createElement("recordkey:" + "EncryptedPrivateKey");
	Element any = (Element) recordKey.getEncryptedPrivateKey().getAny();
	Node adoptedNode = document.adoptNode(any);
	elemEncryptedPrivateKey.appendChild(adoptedNode);
	elemRecordKey.appendChild(elemEncryptedPrivateKey);
	return elemRecordKey;
    }


    private Element marshalSignatureType(Document document, SignatureType signature) {
	Element elemSignature = document.createElement("ds:" + "Signature");
	elemSignature.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
	Element elemSignedInfo = document.createElement("ds:" + "SignedInfo");
	try {
	    Element elemCanonicalizationMethod = document.createElement("ds:" + "CanonicalizationMethod");
	    CanonicalizationMethodType canonicalizationMethod = signature.getSignedInfo().getCanonicalizationMethod();
	    String algorithm = canonicalizationMethod.getAlgorithm();
	    elemCanonicalizationMethod.setAttribute("Algorithm", algorithm);
	    elemSignedInfo.appendChild(elemCanonicalizationMethod);
	} catch (NullPointerException e) {
	    e.printStackTrace();
	}
	Element elemSignatureMethod = document.createElement("ds:" + "SignatureMethod");
	elemSignatureMethod.setAttribute("Algorithm", signature.getSignedInfo().getSignatureMethod().getAlgorithm());
	elemSignedInfo.appendChild(elemSignatureMethod);
	Element elemReference = document.createElement("ds:" + "Reference");
	ReferenceType reference = signature.getSignedInfo().getReference().get(0);
	elemReference.setAttribute("URI", reference.getURI());

	Element elemTransforms = document.createElement("ds:" + "Transforms");
	for (TransformType tt : reference.getTransforms().getTransform()) {
	    Element elemTransform = document.createElement("ds:" + "Transform");
	    elemTransform.setAttribute("Algorithm", tt.getAlgorithm());
	    elemTransforms.appendChild(elemTransform);
	}
	elemReference.appendChild(elemTransforms);
	Element elemDigestMethod = document.createElement("ds:" + "DigestMethod");
	elemDigestMethod.setAttribute("Algorithm", reference.getDigestMethod().getAlgorithm());
	elemReference.appendChild(elemDigestMethod);
	Element elemDigestValue = document.createElement("ds:" + "DigestValue");
	elemDigestValue.setTextContent(new String(Base64.encode(reference.getDigestValue())));
	elemReference.appendChild(elemDigestValue);

	elemSignedInfo.appendChild(elemReference);
	Element elemSignatureValue = document.createElement("ds:" + "SignatureValue");
	elemSignatureValue.setTextContent(new String(Base64.encode(signature.getSignatureValue().getValue())));
	Element elemKeyInfoSignature = document.createElement("ds:" + "KeyInfo");

	Element elemX509DataSignature = document.createElement("ds:" + "X509Data");
	Element elemX509CertificateSignature = document.createElement("ds:" + "X509Certificate");
	X509DataType x509DataType = signature.getKeyInfo().getX509Data();
	byte[] x509Certificate = x509DataType.getX509Certificate();
	elemX509CertificateSignature.setTextContent(new String(Base64.encode(x509Certificate)));

	elemX509DataSignature.appendChild(elemX509CertificateSignature);

	elemKeyInfoSignature.appendChild(elemX509DataSignature);

	elemSignature.appendChild(elemSignedInfo);
	elemSignature.appendChild(elemSignatureValue);
	elemSignature.appendChild(elemKeyInfoSignature);
	return elemSignature;
    }


    private Node marshalRLUSInitializeRequestSrcStruct(RLUSInitializeRequestSrcStruct rlusInitializeRequestSrcStruct,
	    Document document) {
	Element elemRLUSInitializeRequestSrcStruct = document.createElement("rlustypes:" + "RLUSInitializeRequestSrcStruct");
	Element elemCBRContext = document.createElement("rlustypes:" + "CBRContext");
	Element elemCBRName = document.createElement("rlustypes:" + "CBRName");
	CBRContext cbrContext = rlusInitializeRequestSrcStruct.getCBRContext();
	elemCBRName.setTextContent(cbrContext.getCBRName());
	elemCBRContext.appendChild(elemCBRName);
	Element elemNetworkName = document.createElement("rlustypes:" + "NetworkName");
	elemNetworkName.setTextContent(cbrContext.getNetworkName());
	elemCBRContext.appendChild(elemNetworkName);
	Element elemNetworkAddress = document.createElement("rlustypes:" + "NetworkAddress");
	elemNetworkAddress.setTextContent(cbrContext.getNetworkAddress());
	elemCBRContext.appendChild(elemNetworkAddress);
	elemRLUSInitializeRequestSrcStruct.appendChild(elemCBRContext);
	Element elemInitializeContext = document.createElement("rlustypes:" + "InitializeContext");
	elemInitializeContext.setTextContent(rlusInitializeRequestSrcStruct.getInitializeContext());
	elemRLUSInitializeRequestSrcStruct.appendChild(elemInitializeContext);
	Element elemRLUSsemanticSignifierName = document.createElement("rlustypes:" + "RLUSsemantic-signifierName");
	elemRLUSsemanticSignifierName.setTextContent(rlusInitializeRequestSrcStruct.getRLUSsemanticSignifierName());
	elemRLUSInitializeRequestSrcStruct.appendChild(elemRLUSsemanticSignifierName);
	Element elemSecurityContext = document.createElement("rlustypes:" + "SecurityContext");
	Element elemSourceIdentity = document.createElement("rlustypes:" + "SourceIdentity");
	SecurityContext securityContext = rlusInitializeRequestSrcStruct.getSecurityContext();
	SourceIdentity sourceIdentity = securityContext.getSourceIdentity().get(0);
	elemSourceIdentity.setAttribute("identityName", sourceIdentity.getIdentityName());
	elemSecurityContext.appendChild(elemSourceIdentity);
	elemRLUSInitializeRequestSrcStruct.appendChild(elemSecurityContext);
	return elemRLUSInitializeRequestSrcStruct;
    }

    private Element marshalRLUSStatusCode(RLUSStatusCode rlusStatusCode, Document document) {
	Element elementRLUSStatusCode = document.createElement("rlustypes:" + "RLUSStatusCode");
	Element elemSuccess = document.createElement("rlustypes:" + "success");
	elemSuccess.setTextContent(String.valueOf(rlusStatusCode.isSuccess()));
	elementRLUSStatusCode.appendChild(elemSuccess);
	return elementRLUSStatusCode;
    }

    @Override
    public synchronized Document str2doc(String docStr) throws SAXException {
	try {
	    // read dom as w3
	    StringReader strReader = new StringReader(docStr);
	    InputSource inSrc = new InputSource(strReader);
	    Document doc = documentBuilder.parse(inSrc);
	    return doc;
	} catch (IOException ex) {
	    throw new SAXException(ex);
	}
    }

    public synchronized Document str2doc(String docStr, boolean filterWhitespaces) throws SAXException {
	try {
	    // read dom as w3
	    StringReader strReader = new StringReader(docStr);
	    InputSource inSrc = new InputSource(strReader);
	    Document doc = documentBuilder.parse(inSrc);
	    if (filterWhitespaces) {
		WhitespaceFilter.filter(doc);
	    }
	    return doc;
	} catch (IOException ex) {
	    throw new SAXException(ex);
	}
    }

    @Override
    public synchronized Document str2doc(InputStream docStr) throws SAXException, IOException {
	// read dom as w3
	Document doc;
	try {
	    doc = documentBuilder.parse(docStr);
	    return doc;
	} catch (IOException e) {
	    throw new SAXException(e);
	}
    }

    @Override
    public synchronized Object unmarshal(Node n) throws MarshallingTypeException, WSMarshallerException {
	Document newDoc = null;
	if (n instanceof Document) {
	    newDoc = (Document) n;
	} else if (n instanceof Element) {
	    newDoc = documentBuilder.newDocument();
	    Node root = newDoc.importNode(n, true);
	    newDoc.appendChild(root);
	} else {
	    throw new WSMarshallerException("Only w3c Document and Element are accepted.");
	}

	try {
	    XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
	    factory.setNamespaceAware(true);
	    XmlPullParser parser = factory.newPullParser();
	    parser.setInput(new ByteArrayInputStream(this.doc2str(newDoc).getBytes("UTF-8")), "UTF-8");
	    int eventType = parser.getEventType();
	    while (eventType != XmlPullParser.END_DOCUMENT) {
		if (eventType == XmlPullParser.START_TAG) {
		    Object obj = parse(parser, newDoc);
		    return obj;
		}
		eventType = parser.next();
	    }
	    return null;
	} catch (Exception e) {
	    throw new MarshallingTypeException(e);
	}
    }

    private synchronized Object parse(XmlPullParser parser, Document newDoc) throws XmlPullParserException, IOException, ParserConfigurationException, DatatypeConfigurationException {
	if (parser.getName().equals("ListRLUSGenericResponse")) {
	    ListRLUSGenericResponse listRLUSGenericResponse = new ListRLUSGenericResponse();
	    int eventType;
	    do {
		parser.next();
		eventType = parser.getEventType();
		if (eventType == XmlPullParser.START_TAG) {
		    if (parser.getName().equals("RLUSStatusCode")) {
			listRLUSGenericResponse.setRLUSStatusCode(this.parseRLUSStatusCode(parser));
		    } else if (parser.getName().equals("finishedFlag")) {
			listRLUSGenericResponse.setFinishedFlag(Long.parseLong(parser.nextText()));
		    } else {
			String tagName = parser.getName();
			System.out.println("parser.getName: " + tagName);
			NodeList elementsByTagName = newDoc.getElementsByTagName(tagName);
			if (elementsByTagName.getLength() == 0) {
			    elementsByTagName = newDoc.getElementsByTagName("cdp:ContentPackage");
			}
			System.out.println("elements size: " + elementsByTagName.getLength());
			listRLUSGenericResponse.getAny().add((Element) elementsByTagName.item(0));
			do {
			    parser.next();
			    eventType = parser.getEventType();
			} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals(tagName)));
		    }
		}
	    } while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("ListRLUSGenericResponse")));
	    return listRLUSGenericResponse;
	} else if (parser.getName().equals("PutRLUSGenericRequest")) {
	    PutRLUSGenericRequest putRLUSGenericRequest = new PutRLUSGenericRequest();
	    int eventType;
	    do {
		parser.next();
		eventType = parser.getEventType();
		if (eventType == XmlPullParser.START_TAG) {
		    if (parser.getName().equals("writeCommandEnum")) {
			putRLUSGenericRequest.setWriteCommandEnum(parser.nextText());
		    }
		}
	    } while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("PutRLUSGenericRequest")));
	    return putRLUSGenericRequest;
	} else if (parser.getName().equals("RLUSsemantic-signifier")) {
	    return parseRLUSSemanticSignifier(parser);
	} else if (parser.getName().equals("CapabilityList")) {
	    CapabilityList capabilityList = new CapabilityList();
	    AddressInformation addressInformation = new AddressInformation();
	    // error in android ?
	    //W3CEndpointReferenceBuilder w3cEndpointReferenceBuilder = new W3CEndpointReferenceBuilder();
	    KeyBindingType keyBinding = new KeyBindingType();
	    SupportedKeys supportedKeys = new SupportedKeys();
	    capabilityList.setSupportedKeys(supportedKeys);
	    supportedKeys.getKeyBinding().add(keyBinding);
	    Document document = documentBuilder.newDocument();
	    KeyValueType keyValueType = new KeyValueType();
	    RSAKeyValueType rsaKeyValue = new RSAKeyValueType();
	    keyValueType.setRSAKeyValue(rsaKeyValue);
	    KeyInfoType keyInfoType = new KeyInfoType();
	    keyBinding.setKeyInfo(keyInfoType);
	    keyBinding.getKeyInfo().setKeyValue(keyValueType);
	    SupportedCommunicationPatterns patterns = new SupportedCommunicationPatterns();
	    capabilityList.setSupportedCommunicationPatterns(patterns);
	    SupportedSemanticSignifiers signifiers = new SupportedSemanticSignifiers();
	    capabilityList.setSupportedSemanticSignifiers(signifiers);
	    capabilityList.setId(parser.getAttributeValue("http://www.w3.org/XML/1998/namespace", "Id"));
	    int eventType;
	    do {
		parser.next();
		eventType = parser.getEventType();
		if (eventType == XmlPullParser.START_TAG) {
		    if (parser.getName().equals("Address")) {
			AttributedURIType attributedURI = new AttributedURIType();
			attributedURI.setValue(parser.nextText());
			//w3cEndpointReferenceBuilder.address(attributedURI.getValue());
		    } else if (parser.getName().equals("AktenID")) {
			Element em = document.createElementNS("http://isst.fhg.de/epa", parser.getName());
			em.setTextContent(parser.nextText());
			//w3cEndpointReferenceBuilder.referenceParameter(em);
		    } else if (parser.getName().equals("Status")) {
			StatusType statusType = new StatusType();
			statusType.setStatusValue(parser.getAttributeValue(0));
			keyBinding.setStatus(statusType);
		    } else if (parser.getName().equals("KeyUsage")) {
			keyBinding.getKeyUsage().add(parser.nextText());
		    } else if (parser.getName().equals("Modulus")) {
			rsaKeyValue.setModulus(Base64.decode(parser.nextText()));
		    } else if (parser.getName().equals("Exponent")) {
			rsaKeyValue.setExponent(Base64.decode(parser.nextText()));
		    } else if (parser.getName().equals("SupportedCommunicationPattern")) {
			SupportedCommunicationPattern pattern = new SupportedCommunicationPattern();
			pattern.setType(parser.getAttributeValue(0));
			patterns.getSupportedCommunicationPattern().add(pattern);
		    } else if (parser.getName().equals("RLUSsemantic-signifier")) {
			RLUSsemanticSignifier rlusSemanticSignifier = parseRLUSSemanticSignifier(parser);
			signifiers.getRLUSsemanticSignifier().add(rlusSemanticSignifier);
		    } else if (parser.getName().equals("Signature")) {
			capabilityList.getSignature().add(parseSignatureType(parser));
		    } else {
			logger.warn("Untreated TAG: {}", parser.getName());
		    }
		}
	    } while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("CapabilityList")));
	    //addressInformation.setEndpointReference(w3cEndpointReferenceBuilder.build());
	    capabilityList.setAddressInformation(addressInformation);
	    return capabilityList;
	} else if (parser.getName().equals("ProvisioningObject")) {
	    ProvisioningObject provisioningObject = new ProvisioningObject();
	    int eventType;
	    do {
		parser.next();
		eventType = parser.getEventType();
		if (eventType == XmlPullParser.START_TAG) {
		    if (parser.getName().equals("Systems")) {
			provisioningObject.getSystems().add(parseSystem(parser));
		    } else if (parser.getName().equals("Content")) {
			provisioningObject.setContent(parser.nextText());
		    } else if (parser.getName().equals("Participants")) {
			provisioningObject.getParticipants().add(parseParticipant(parser));
		    } else if (parser.getName().equals("CreationTime")) {
			try {
			    DatatypeFactory datatypeFac = DatatypeFactory.newInstance();
			    XMLGregorianCalendar creationTime = datatypeFac.newXMLGregorianCalendar(parser.nextText());
			    provisioningObject.setCreationTime(creationTime);
			} catch (Exception e) {
			    e.printStackTrace();
			}
		    }
		}
	    } while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("ProvisioningObject")));
	    return provisioningObject;
	} else if (parser.getName().equals("RequestObject")) {
	    RequestObject requestObject = new RequestObject();
	    return requestObject;
	} else if (parser.getName().equals("PutRLUSGenericResponse")) {
	    PutRLUSGenericResponse response = new PutRLUSGenericResponse();
	    int eventType;
	    do {
		parser.next();
		eventType = parser.getEventType();
		if (eventType == XmlPullParser.START_TAG) {
		    if (parser.getName().equals("RLUSStatusCode")) {
			response.setRLUSStatusCode(parseRLUSStatusCode(parser));
		    }
		}
	    } while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("PutRLUSGenericResponse")));
	    return response;
	} else if (parser.getName().equals("RLUSStatusCode")) {
	    return parseRLUSStatusCode(parser);
	} else {
	    throw new IOException("Unmarshalling of " + parser.getName() + " is not yet supported.");
	}
    }

    private SignatureType parseSignatureType(XmlPullParser parser) throws XmlPullParserException, IOException {
	SignatureType signature = new SignatureType();
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("SignedInfo")) {
		    signature.setSignedInfo(parseSignedInfoType(parser));
		} else if (parser.getName().equals("SignatureValue")) {
		    SignatureValueType signatureValue = new SignatureValueType();
		    signatureValue.setValue(Base64.decode(parser.nextText()));
		    signature.setSignatureValue(signatureValue);
		} else if (parser.getName().equals("KeyInfo")) {
		    signature.setKeyInfo(parseKeyInfoType(parser));
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("Signature")));
	return signature;
    }


    private KeyInfoType parseKeyInfoType(XmlPullParser parser) throws XmlPullParserException, IOException {
	KeyInfoType keyInfoType = new KeyInfoType();
	if (parser.getAttributeCount() > 0) {
	    keyInfoType.setId(parser.getAttributeValue(0));
	}
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("X509Certificate")) {
		    X509DataType x509DataType = new X509DataType();
		    x509DataType.setX509Certificate(Base64.decode(parser.nextText()));
		    keyInfoType.setX509Data(x509DataType);
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("KeyInfo")));
	return keyInfoType;
    }

    private SignedInfoType parseSignedInfoType(XmlPullParser parser) throws XmlPullParserException, IOException {
	SignedInfoType signedInfoType = new SignedInfoType();
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("CanonicalizationMethod")) {
		    CanonicalizationMethodType value = new CanonicalizationMethodType();
		    value.setAlgorithm(parser.getAttributeValue(0));
		    signedInfoType.setCanonicalizationMethod(value);
		} else if (parser.getName().equals("SignatureMethod")) {
		    SignatureMethodType value = new SignatureMethodType();
		    value.setAlgorithm(parser.getAttributeValue(0));
		    signedInfoType.setSignatureMethod(value);
		} else if (parser.getName().equals("Reference")) {
		    signedInfoType.getReference().add(parseReferenceType(parser));
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("SignedInfo")));
	return signedInfoType;
    }


    private ReferenceType parseReferenceType(XmlPullParser parser) throws XmlPullParserException, IOException {
	ReferenceType referenceType = new ReferenceType();
	TransformsType transforms = new TransformsType();
	referenceType.setTransforms(transforms);
	referenceType.setURI(parser.getAttributeValue(0));
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("DigestMethod")) {
		    DigestMethodType value = new DigestMethodType();
		    value.setAlgorithm(parser.getAttributeValue(0));
		    referenceType.setDigestMethod(value);
		} else if (parser.getName().equals("DigestValue")) {
		    referenceType.setDigestValue(Base64.decode(parser.nextText()));
		} else if (parser.getName().equals("Transform")) {
		    TransformType e = new TransformType();
		    e.setAlgorithm(parser.getAttributeValue(0));
		    referenceType.getTransforms().getTransform().add(e);
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("Reference")));
	return referenceType;
    }


    private Participant parseParticipant(XmlPullParser parser) throws XmlPullParserException, IOException {
	Participant p = new Participant();
	p.setParticipantTypeCode(parser.getAttributeValue("http://isst.fraunhofer.de/rlus/types", "ParticipantTypeCode"));
	p.setRoleTypeCode(parser.getAttributeValue("http://isst.fraunhofer.de/rlus/types", "RoleTypeCode"));
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("Id")) {
		    p.setId(parser.nextText());
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("Participants")));
	return p;
    }


    private de.fraunhofer.isst.rlus.types.System parseSystem(XmlPullParser parser) throws XmlPullParserException, IOException {
	de.fraunhofer.isst.rlus.types.System s = new de.fraunhofer.isst.rlus.types.System();
	s.setSystemTypeCode(parser.getAttributeValue(0));
	de.fraunhofer.isst.rlus.types.CBRContext context = new de.fraunhofer.isst.rlus.types.CBRContext();
	s.setCBRContext(context);
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("Id")) {
		    s.setId(parser.nextText());
		} else if (parser.getName().equals("CBRName")) {
		    context.setCBRName(parser.nextText());
		} else if (parser.getName().equals("NetworkAddress")) {
		    context.setNetworkAddress(parser.nextText());
		} else if (parser.getName().equals("NetworkName")) {
		    context.setNetworkName(parser.nextText());
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("Systems")));
	return s;
    }


    private RLUSsemanticSignifier parseRLUSSemanticSignifier(XmlPullParser parser) throws XmlPullParserException,
	    IOException {
	RLUSsemanticSignifier rlusSemanticSignifier = new RLUSsemanticSignifier();
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("name")) {
		    rlusSemanticSignifier.setName(parser.nextText());
		} else if (parser.getName().equals("signifierID")) {
		    rlusSemanticSignifier.setSignifierID(parser.nextText());
		} else if (parser.getName().equals("version")) {
		    rlusSemanticSignifier.setVersion(parser.nextText());
		} else if (parser.getName().equals("schemaDefName")) {
		    rlusSemanticSignifier.setSchemaDefName(parser.nextText());
		} else if (parser.getName().equals("schemaDefintionReference")) {
		    rlusSemanticSignifier.setSchemaDefintionReference(parser.nextText());
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("RLUSsemantic-signifier")));
	return rlusSemanticSignifier;
    }

    private RLUSStatusCode parseRLUSStatusCode(XmlPullParser parser) throws XmlPullParserException, IOException {
	RLUSStatusCode statusCode = new RLUSStatusCode();
	int eventType;
	do {
	    parser.next();
	    eventType = parser.getEventType();
	    if (eventType == XmlPullParser.START_TAG) {
		if (parser.getName().equals("success")) {
		    statusCode.setSuccess(Boolean.parseBoolean(parser.nextText()));
		} else if (parser.getName().equals("recordID")) {
		    II e = new II();
		    e.setRoot(parser.getAttributeValue(0));
		    statusCode.getRecordID().add(e);
		} else if (parser.getName().equals("message")) {
		    statusCode.setMessage(parser.nextText());
		}
	    }
	} while (!(eventType == XmlPullParser.END_TAG && parser.getName().equals("RLUSStatusCode")));
	return statusCode;
    }

    @Override
    public SOAPMessage doc2soap(Document envDoc) throws SOAPException {
	SOAPMessage msg = soapFactory.createMessage(envDoc);
	return msg;
    }

    @Override
    public SOAPMessage add2soap(Document content) throws SOAPException {
	SOAPMessage msg = soapFactory.createMessage();
	SOAPBody body = msg.getSOAPBody();
	body.addDocument(content);

	return msg;
    }

}
