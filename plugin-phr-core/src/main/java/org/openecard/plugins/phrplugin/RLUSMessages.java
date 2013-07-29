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

import de.fraunhofer.isst.rlus.types.Participant;
import de.fraunhofer.isst.rlus.types.ProvisioningObject;
import de.fraunhofer.isst.rlus.types.RecordTarget;
import de.fraunhofer.isst.rlus.types.System;
import fue_epa.recordkey.CititzenCertificate;
import fue_epa.recordkey.EncryptedPrivateKey;
import fue_epa.recordkey.RecordKey;
import fue_epa.recordkey.SupportedKeys;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.omg.spec.rlus._201012.rlusgeneric.InitializeRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.PutRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlustypes.FieldType;
import org.omg.spec.rlus._201012.rlustypes.FilterCriteriaType;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct.CBRContext;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct.SecurityContext;
import org.omg.spec.rlus._201012.rlustypes.RLUSInitializeRequestSrcStruct.SecurityContext.SourceIdentity;
import org.omg.spec.rlus._201012.rlustypes.RLUSSearchStruct;
import org.omg.spec.rlus._201012.rlustypes.RLUSSearchStructType.SearchByCriteria;
import org.omg.spec.rlus._201012.rlustypes.SearchAttributesType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms.KeyBindingType;
import org.w3._2002._03.xkms.StatusType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * Helper class that bundles the creation of RLUS messages.
 * 
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class RLUSMessages {

    private static final String NAMESPACE_RLUSEXPRESSION = "http://www.omg.org/spec/RLUS/201012/RLUSexpression";

    /**
     * Creates a new PutRLUSGenericRequest with the given Element as payload.
     *
     * @param encryptedMDO payload
     * @param subjectDN distinguished name of the subject
     * @param recordId Id of the record
     * @param providerId Id of the provider
     * @return created PutRLUSGenericRequest
     */
    public static PutRLUSGenericRequest createPutRLUSGenericRequest(Element encryptedMDO, String recordId, 
	    String subjectDN, String providerId) {
	PutRLUSGenericRequest putRLUSGenericRequest = new PutRLUSGenericRequest();
	ProvisioningObject po = new ProvisioningObject();
	RecordTarget recordTarget = new RecordTarget();
	recordTarget.setRecordId(recordId);
	po.setRecordTarget(recordTarget);
	Participant participant = new Participant();
	participant.setRoleTypeCode("1");
	participant.setParticipantTypeCode("1");
	participant.setId(subjectDN);
	po.getParticipants().add(participant);
	System system1 = new System();
	system1.setSystemTypeCode("1");
	de.fraunhofer.isst.rlus.types.CBRContext cbrContext = new de.fraunhofer.isst.rlus.types.CBRContext();
	cbrContext.setNetworkAddress("127.0.0.1");
	cbrContext.setCBRName("?");
	cbrContext.setNetworkName("rlus_citizen_client.de");
	system1.setId("ePA-Open-eCard-Plugin");
	system1.setCBRContext(cbrContext);
	po.getSystems().add(system1);
	System system2 = new System();
	cbrContext = new de.fraunhofer.isst.rlus.types.CBRContext();
	String serverAddress = PHRPluginProperies.getProperty(providerId);

	InetAddress ip = null;
	try {
	    URL url = new URL(serverAddress);
	    ip = InetAddress.getByName(url.getHost());
	} catch (UnknownHostException e) {
	    // TODO 
	} catch (MalformedURLException e) {
	    // TODO 
	}

	cbrContext.setNetworkAddress(ip.getHostAddress());
	cbrContext.setCBRName("?");
	cbrContext.setNetworkName(serverAddress);
	system2.setId("?");
	system2.setCBRContext(cbrContext);
	system2.setSystemTypeCode("2");
	po.getSystems().add(system2);
	po.setContent(encryptedMDO);
	putRLUSGenericRequest.setProvisioningObject(po);
	putRLUSGenericRequest.setWriteCommandEnum("INSERT");
	return putRLUSGenericRequest;
    }

    /**
     * Creates a new PutRLUSGenericRequest with the given RecordKey.
     *
     * @param recordKey RecordKey with information for creation of a new record
     * @return created InitializeRLUSGenericRequest
     */
    public static InitializeRLUSGenericRequest createInitializeRLUSGenericRequest(RecordKey recordKey) {
	InitializeRLUSGenericRequest request = new InitializeRLUSGenericRequest();
	request.setRecordKey(recordKey);
	RLUSInitializeRequestSrcStruct rlusInitializeRequestSrcStruct = new RLUSInitializeRequestSrcStruct();
	rlusInitializeRequestSrcStruct.setRLUSsemanticSignifierName("CL");
	rlusInitializeRequestSrcStruct.setInitializeContext("?");
	SecurityContext securityContext = new SecurityContext();
	SourceIdentity sourceIdentity = new SourceIdentity();
	sourceIdentity.setIdentityName("?");
	securityContext.getSourceIdentity().add(sourceIdentity);
	rlusInitializeRequestSrcStruct.setSecurityContext(securityContext);
	CBRContext cbrContext = new CBRContext();
	cbrContext.setCBRName("?");
	cbrContext.setNetworkAddress("127.0.0.1");
	cbrContext.setNetworkName("rlus_citizen_client.de");
	rlusInitializeRequestSrcStruct.setCBRContext(cbrContext);
	request.setRLUSInitializeRequestSrcStruct(rlusInitializeRequestSrcStruct);
	return request;
    }

    /**
     * Creates a new ListRLUSGenericRequest to request a information object with the given semantic signifier.
     *
     * @param semanticSignifier semantic signifier
     * @param recordId Id of the record
     * @return created ListRLUSGenericRequest
     * @throws ParserConfigurationException 
     */
    public static ListRLUSGenericRequest createListRLUSGenericRequest(String semanticSignifier, String recordId) 
	    throws ParserConfigurationException {
	RLUSSearchStruct struct = new RLUSSearchStruct();
	struct.setSemanticSignifiername(semanticSignifier);

	SearchByCriteria searchByCriteria = new SearchByCriteria();
	FilterCriteriaType filterCriteriaType = new FilterCriteriaType();

	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	dbf.setNamespaceAware(true);
	DocumentBuilder builder = dbf.newDocumentBuilder();
	Document d = builder.newDocument();
	Element elemExpression = d.createElementNS("http://www.omg.org/spec/RLUS/201012/RLUStypes", "Expression");
	d.appendChild(elemExpression);

	Element binaryTerm1 = d.createElementNS(NAMESPACE_RLUSEXPRESSION, "BinaryTerm");
	binaryTerm1.setAttribute("text", "ext");
	binaryTerm1.setAttribute("type", "Text");
	Element operator = d.createElementNS(NAMESPACE_RLUSEXPRESSION, "Operator");
	operator.setAttribute("type", "EqualTo");
	Element binaryTerm2 = d.createElementNS(NAMESPACE_RLUSEXPRESSION, "BinaryTerm");
	binaryTerm2.setAttribute("text", recordId);
	binaryTerm2.setAttribute("type", "Text");
	elemExpression.appendChild(binaryTerm1);
	elemExpression.appendChild(operator);
	elemExpression.appendChild(binaryTerm2);

	filterCriteriaType.setAny(d.getDocumentElement());
	searchByCriteria.setFilterCriteria(filterCriteriaType);
	SearchAttributesType searchAttributesType = new SearchAttributesType();
	FieldType e = new FieldType();
	e.setName("org.hl7.v3.POCDMT000040ClinicalDocument/recordTarget/patientRole/id/extension");
	e.setQualifier("#ext");
	searchAttributesType.getField().add(e);
	searchByCriteria.setSearchAttributes(searchAttributesType);
	struct.setSearchByCriteria(searchByCriteria);

	ListRLUSGenericRequest list = new ListRLUSGenericRequest();
	list.setRLUSSearchStruct(struct);
	list.setMaxResultStreams(1);
	list.setPreviousResultID("-1");
	return list;
    }

    /**
     * Creates a new RecordKey using the given parameters.
     *
     * @param authenticationCode An authentication code that was sent to the citizen by mail
     * @param cert encoded AUTN certificate from the german health care card
     * @param publicKey public record key
     * @param encPrivateKeyRecord encrypted private record key
     * @return created RecordKey
     */
    public static RecordKey createRecordKey(String authenticationCode, byte[] cert, RSAPublicKey publicKey, 
	    Document encPrivateKeyRecord) {
	RecordKey recordKey = new RecordKey();
	recordKey.setAuthenticationCode(authenticationCode);
	SupportedKeys key = new SupportedKeys();
	KeyBindingType keyBindingType = new KeyBindingType();
	StatusType statusType = new StatusType();
	statusType.setStatusValue("http://www.w3.org/2002/03/xkms#Valid");
	keyBindingType.setStatus(statusType);
	keyBindingType.setId(UUID.randomUUID().toString());
	keyBindingType.getKeyUsage().add("http://www.w3.org/2002/03/xkms#Encryption");
	KeyInfoType keyInfoType = new KeyInfoType();
	KeyValueType keyValueType = new KeyValueType();
	RSAKeyValueType e2 = new RSAKeyValueType();
	e2.setExponent(publicKey.getPublicExponent().toByteArray());
	e2.setModulus(publicKey.getModulus().toByteArray());
	keyValueType.setRSAKeyValue(e2);
	keyInfoType.setKeyValue(keyValueType);
	keyBindingType.setKeyInfo(keyInfoType);
	key.setKeyBinding(keyBindingType);
	recordKey.setSupportedKeys(key);
	EncryptedPrivateKey encryptedPrivateKey = new EncryptedPrivateKey();
	encryptedPrivateKey.setAny(encPrivateKeyRecord.getDocumentElement());
	recordKey.setEncryptedPrivateKey(encryptedPrivateKey);
	CititzenCertificate cititzenCertificate = new CititzenCertificate();
	X509DataType x509DataType = new X509DataType();
	x509DataType.setX509Certificate(cert);
	cititzenCertificate.setX509Data(x509DataType);
	recordKey.setCititzenCertificate(cititzenCertificate);
	return recordKey;
    }

}
