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

import fue_epa.capabilitylist.CapabilityList;
import fue_epa.capabilitylist.SupportedCommunicationPattern;
import fue_epa.capabilitylist.SupportedCommunicationPatterns;
import fue_epa.capabilitylist.SupportedSemanticSignifiers;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlusgeneric.ListRLUSGenericResponse;
import org.omg.spec.rlus._201012.rlusgeneric.PutRLUSGenericRequest;
import org.omg.spec.rlus._201012.rlustypes.FieldType;
import org.omg.spec.rlus._201012.rlustypes.FilterCriteriaType;
import org.omg.spec.rlus._201012.rlustypes.RLUSSearchStruct;
import org.omg.spec.rlus._201012.rlustypes.RLUSSearchStructType.SearchByCriteria;
import org.omg.spec.rlus._201012.rlustypes.RLUSStatusCode;
import org.omg.spec.rlus._201012.rlustypes.RLUSsemanticSignifier;
import org.omg.spec.rlus._201012.rlustypes.SearchAttributesType;
import org.openecard.bouncycastle.util.encoders.Base64;
import org.openecard.ws.jaxb.JAXBMarshaller;
import org.openecard.ws.marshal.WSMarshaller;
import org.testng.annotations.Test;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2002._03.xkms.KeyBindingType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;


/**
 * Test if the RLUS messages get correctly marshalled and unmarshalled.
 *
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class PHRMarshallerTest {

    private static final String listRLUSGenericResponse;
    private static final String putRLUSGenericRequest;
    private static final String capabilityList;
    private static final String NAMESPACE_RLUSEXPRESSION = "http://www.omg.org/spec/RLUS/201012/RLUSexpression";

    static {
   	try {
   	    listRLUSGenericResponse = loadXML("ws/ListRLUSGenericResponse.xml");
   	    putRLUSGenericRequest = loadXML("ws/PutRLUSGenericRequest.xml");
   	    capabilityList = loadXML("ws/CapabilityList.xml");
   	} catch (IOException ex) {
   	    throw new RuntimeException(ex);
   	}
    }

    private static String loadXML(String resourcePath) throws IOException {
	InputStream in = PHRMarshallerTest.class.getClassLoader().getResourceAsStream(resourcePath);
	StringWriter w = new StringWriter();
	BufferedReader r = new BufferedReader(new InputStreamReader(in, Charset.forName("utf-8")));
	String nextLine;
	while ((nextLine = r.readLine()) != null) {
	    w.write(nextLine);
	    w.write(String.format("%n")); // platform dependant newline character
	}
	return w.toString();
    }

    @Test
    public void testConversionOfListRLUSGenericResponse() throws Exception {
	WSMarshaller m = new PHRMarshaller();
	Object o = m.unmarshal(m.str2doc(listRLUSGenericResponse));
	if (o instanceof ListRLUSGenericResponse) {
	    ListRLUSGenericResponse listRLUSGenericResponse = (ListRLUSGenericResponse) o;
	    RLUSStatusCode statusCode = listRLUSGenericResponse.getRLUSStatusCode();
	    assertTrue(statusCode.isSuccess());
	    System.out.println(m.doc2str((Element) listRLUSGenericResponse.getAny().get(0)));
	} else {
	    throw new Exception("Object should be an instace of GetRecognitionTreeResponse");
	}
    }

    @Test
    public void testConversionOfPutRLUSGenericRequest() throws Exception {
	WSMarshaller m = new PHRMarshaller();
	Object o = m.unmarshal(m.str2doc(putRLUSGenericRequest));
	if (o instanceof PutRLUSGenericRequest) {
	    PutRLUSGenericRequest putRLUSGenericRequest = (PutRLUSGenericRequest) o;
	    assertEquals(putRLUSGenericRequest.getWriteCommandEnum(), "INSERT");
	} else {
	    throw new Exception("Object should be an instace of GetRecognitionTreeResponse");
	}
    }

    @Test
    public void testConversionOfListRLUSGenericRequest() throws Exception {
	WSMarshaller m = new PHRMarshaller();
	ListRLUSGenericRequest request = new ListRLUSGenericRequest();
	request.setMaxResultStreams(1);
	request.setPreviousResultID("-1");
	RLUSSearchStruct struct = new RLUSSearchStruct();
	SearchByCriteria searchByCriteria = new SearchByCriteria();
	FilterCriteriaType filterCriteriaType = new FilterCriteriaType();
	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	dbf.setNamespaceAware(true);
	DocumentBuilder builder = dbf.newDocumentBuilder();
	Document doc = builder.newDocument();
	Element elemExpression = doc.createElementNS("http://www.omg.org/spec/RLUS/201012/RLUStypes", "Expression");
	doc.appendChild(elemExpression);

	Element binaryTerm1 = doc.createElementNS(NAMESPACE_RLUSEXPRESSION, "BinaryTerm");
	binaryTerm1.setAttribute("text", "ext");
	binaryTerm1.setAttribute("type", "Text");
	Element operator = doc.createElementNS(NAMESPACE_RLUSEXPRESSION, "Operator");
	operator.setAttribute("type", "EqualTo");
	Element binaryTerm2 = doc.createElementNS(NAMESPACE_RLUSEXPRESSION, "BinaryTerm");
	binaryTerm2.setAttribute("text", "1234567890");
	binaryTerm2.setAttribute("type", "Text");
	elemExpression.appendChild(binaryTerm1);
	elemExpression.appendChild(operator);
	elemExpression.appendChild(binaryTerm2);

	filterCriteriaType.setAny(doc.getDocumentElement());
	searchByCriteria.setFilterCriteria(filterCriteriaType);
	SearchAttributesType searchAttributesType = new SearchAttributesType();
	FieldType e = new FieldType();
	e.setName("org.hl7.v3.POCDMT000040ClinicalDocument/recordTarget/patientRole/id/extension");
	e.setQualifier("#ext");
	searchAttributesType.getField().add(e);
	searchByCriteria.setSearchAttributes(searchAttributesType);
	struct.setSearchByCriteria(searchByCriteria);
	struct.setSemanticSignifiername("CL");
	request.setRLUSSearchStruct(struct);
	Document docum = m.marshal(request);
	System.out.println(m.doc2str(docum));
	WSMarshaller m2 = new JAXBMarshaller();
	m2.removeAllTypeClasses();
	m2.addXmlTypeClass(ListRLUSGenericRequest.class);
	Document d = m2.marshal(request);
	System.out.println(m2.doc2str(d));
    }

    @Test
    public void testConversionOfCapabilityList() throws Exception {
	WSMarshaller m = new PHRMarshaller();
	Object o = m.unmarshal(m.str2doc(capabilityList));
	if (o instanceof CapabilityList) {
	    CapabilityList capabilityList = (CapabilityList) o;
	    //TODO 
	    //AddressInformation addressInformation = capabilityList.getAddressInformation();
	    // W3CEndpointReference endpointReference = addressInformation.getEndpointReference();
	    //assertEquals(endpointReference., "http://isst.fhg.de/epa/records");
	    //ReferenceParametersType referenceParameters = endpointReference.getReferenceParameters();
	    //Element em = (Element) referenceParameters.getAny().get(0);
	    //String tagName = em.getTagName();
	    //String textContent = em.getTextContent();
	    //assertEquals(tagName, "AktenID");
	    //assertEquals(textContent, "123456789");
	    KeyBindingType keyBinding = capabilityList.getSupportedKeys().getKeyBinding().get(0);
	    assertEquals(keyBinding.getStatus().getStatusValue(), "http://www.w3.org/2002/03/xkms#Valid");
	    keyBinding.getKeyInfo();
	    assertEquals(keyBinding.getKeyUsage().get(0), "http://www.w3.org/2002/03/xkms#Encryption");
	    KeyValueType keyValue = (KeyValueType) keyBinding.getKeyInfo().getKeyValue();
	    RSAKeyValueType rsaKeyValue = (RSAKeyValueType) keyValue.getRSAKeyValue();
	    String base64Exponent = Base64.toBase64String(rsaKeyValue.getExponent());
	    assertEquals(base64Exponent, "AQAB");
	    String base64Modulus = Base64.toBase64String(rsaKeyValue.getModulus());
	    assertEquals(base64Modulus,
		    "0nIsmR+aVW2egl5MIfOKy4HuMKkk9AZ/IQuDLVPlhzOfgngjVQCjr8uvmnqtNu8HBupui8LgGthO6U9D0CNT5mbmhIAErRAD" +
		    "UMIAFsi7LzBarUvNWTqYNEJmcHsAUZdrdcDrkNnG7SzbuJx+GDNiHKVDQggPBLc1XagW20RMvok=");
	    SupportedCommunicationPatterns patterns = capabilityList.getSupportedCommunicationPatterns();
	    List<SupportedCommunicationPattern> pattern = patterns.getSupportedCommunicationPattern();
	    SupportedCommunicationPattern actual = pattern.get(2);
	    SupportedCommunicationPattern expected = new SupportedCommunicationPattern();
	    expected.setType("fue-epa:patterns:km05");
	    assertEquals(actual.getType(), expected.getType());
	    SupportedSemanticSignifiers supportedSemanticSignifiers = capabilityList.getSupportedSemanticSignifiers();
	    RLUSsemanticSignifier rlusSemanticSignifier = supportedSemanticSignifiers.getRLUSsemanticSignifier().get(0);
	    String schemaDefintionReference = rlusSemanticSignifier.getSchemaDefintionReference();
	    assertEquals(schemaDefintionReference, "MedicationSummarySemanticSignifierDefinition.xsd");
	} else {
	    throw new Exception("Object should be an instace of GetRecognitionTreeResponse");
	}
    }

}
