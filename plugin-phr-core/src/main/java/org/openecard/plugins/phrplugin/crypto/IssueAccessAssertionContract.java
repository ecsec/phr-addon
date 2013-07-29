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

import java.io.StringReader;
import java.util.UUID;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;


/**
 * Citizen confirms (signs) the ad-hoc authorization policy (access assertion) by means of her pseudonym certificate
 * (C.CH.AUTN) of the eGK. The certificate is embedded in ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate. This
 * class serves as a template for issuing such policy.
 * 
 * @author Fraunhofer FOKUS
 */
public class IssueAccessAssertionContract {

    public static Document buildAccessAssertion(int issuedTokenTimeout, String subjectCHCIOSIG, String subjectCCHAUTN,
	    String providerURL, String subjectPseudonymCCHAUTN, String recordId, String policyIdReference)
	    throws Throwable {

	StringBuffer xml = new StringBuffer();

	DateTime instant = new DateTime(ISOChronology.getInstanceUTC());

	// saml:Assertion
	xml.append("<saml:Assertion " + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " + "Version=\"2.0\" "
		+ "Id=\"uuid-" + UUID.randomUUID() + "\" " + "IssueInstant=\"" + instant + "\" "
		+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
		+ "xsi:schemaLocation=\"urn:oasis:names:tc:SAML:2.0:assertion "
		+ "http://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd\">");

	// saml:Issuer
	xml.append("<saml:Issuer " + "Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName\" "
		+ "NameQualifier=\"urn:fhg:fokus:na:c-ch-autn\">");
	xml.append(subjectCCHAUTN);
	xml.append("</saml:Issuer>");

	// saml:Conditions
	xml.append("<saml:Conditions " + "NotBefore=\"" + instant + "\" " + "NotOnOrAfter=\""
		+ new DateTime(instant.getMillis() + issuedTokenTimeout) + "\">");
	xml.append("<saml:AudienceRestriction>");
	xml.append("<saml:Audience>" + providerURL + "</saml:Audience>");
	xml.append("</saml:AudienceRestriction>");
	xml.append("</saml:Conditions>");

	// saml:Statement
	xml.append("<xacml-saml:Statement " + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
		+ "xmlns:xacml-saml=\"urn:oasis:xacml:2.0:saml:assertion:schema:os\" "
		+ "xsi:type=\"xacml-saml:XACMLPolicyStatementType\" "
		+ "xsi:schemaLocation=\"urn:oasis:names:tc:xacml:2.0:profile:saml2.0:v2:schema:assertion "
		+ "http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-saml-assertion-schema-os.xsd\">");

	xml.append("<xacml:PolicySet "
		+ "xmlns:xacml=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os\" "
		+ "PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:ordered-permit-overrides\" "
		+ "PolicySetId=\"uuid-" + UUID.randomUUID() + "\" "
		+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
		+ "xsi:schemaLocation=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os "
		+ "http://docs.oasis-open.org/xacml/access_control-xacml-2.0-policy-schema-os.xsd\">");
	xml.append("<xacml:Target>");
	xml.append("<xacml:Subjects>");
	xml.append("<xacml:Subject>");
	xml.append("<xacml:SubjectMatch " + "MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">");
	xml.append("<xacml:AttributeValue " + "DataType=\"http://www.w3.org/2001/XMLSchema#string\">");
	xml.append(subjectCHCIOSIG);
	xml.append("</xacml:AttributeValue>");
	xml.append("<xacml:SubjectAttributeDesignator " + "AttributeId=\"urn:oid:1.3.6.1.4.1.778.51.624.112.5\" "
		+ "DataType=\"http://www.w3.org/2001/XMLSchema#string\"/>");
	xml.append("</xacml:SubjectMatch>");
	xml.append("</xacml:Subject>");
	xml.append("</xacml:Subjects>");
	xml.append("<xacml:Resources>");
	xml.append("<xacml:Resource>");
	xml.append("<xacml:ResourceMatch>");
	xml.append("<xacml:AttributeValue " + "DataType=\"http://www.w3.org/2001/XMLSchema#string\">");
	xml.append(subjectPseudonymCCHAUTN);
	xml.append("</xacml:AttributeValue>");
	xml.append("<xacml:ResourceAttributeDesignator "
		+ "AttributeId=\"urn:fhg:fokus:epa:attributes:resource:record-pseudonym\" "
		+ "DataType=\"http://www.w3.org/2001/XMLSchema#string\"/>");
	xml.append("</xacml:ResourceMatch>");
	xml.append("<xacml:ResourceMatch>");
	xml.append("<xacml:AttributeValue>");
	xml.append(recordId);
	xml.append("</xacml:AttributeValue>");
	xml.append("<xacml:ResourceAttributeDesignator "
		+ "AttributeId=\"urn:fhg:fokus:epa:attributes:resource:record-id\" "
		+ "DataType=\"http://www.w3.org/2001/XMLSchema#string\"/>");
	xml.append("</xacml:ResourceMatch>");
	xml.append("</xacml:Resource>");
	xml.append("</xacml:Resources>");
	xml.append("</xacml:Target>");
	xml.append("<xacml:PolicyIdReference>");
	xml.append(policyIdReference);
	xml.append("</xacml:PolicyIdReference>");
	xml.append("</xacml:PolicySet>");
	xml.append("</xacml-saml:Statement>");

	xml.append("</saml:Assertion>");

	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	DocumentBuilder builder = factory.newDocumentBuilder();
	InputSource is = new InputSource(new StringReader(xml.toString()));

	return builder.parse(is);
    }

}
