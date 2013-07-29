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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.testng.annotations.Test;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

/**
 * Test for IssueAccessAssertionContract.
 * 
 * @author Fraunhofer FOKUS
 */
public class IssueAccessAssertionContractTest {

    /**
     * An access assertion will be built and output to System.out for human eye checking.
     * 
     * @throws Throwable
     */
    @Test
    public void test() throws Throwable {
	int issuedTokenTimeout = 172800000; // 48 hours
	String subjectCCHAUTN = "CN=851221afcae8226c55625b309208d58823b81ec0,OU=Institutionsknz,O=Herausgeber,C=DE";
	String subjectPseudonymCCHAUTN = "2K/UlIm3RWuKN2X458Gfdgjkl345hf872ED2qw754F3heqwztTGUB3h";
	String providerURL = "https://ehealth-g1.fokus.fraunhofer.de/epa";
	String subjectCHCIOSIG = "1-1x25sd-dsds"; // SMC-B-TelematikID from Admission/Admissions/ProfessionInfo/registrationNumber
	String recordId = "sdfgjhg562456hj256jh2g56jh2g56jh";
	String policyIdReference = "urn:fhg:fokus:epa:names:xacml:2.0:default:policyid:read-write-all";

	// create the assertion
	Document accessAssertion = IssueAccessAssertionContract.buildAccessAssertion(issuedTokenTimeout, subjectCHCIOSIG, subjectCCHAUTN, providerURL, subjectPseudonymCCHAUTN, recordId, policyIdReference);

	// print the assertion 
	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	DocumentBuilder db = dbf.newDocumentBuilder();
	DOMImplementation domImpl = db.getDOMImplementation();
	DOMImplementationLS ls = (DOMImplementationLS) domImpl;
	LSSerializer lss = ls.createLSSerializer();
	LSOutput lso = ls.createLSOutput();
	lso.setByteStream(System.out);
	lss.write(accessAssertion, lso);
    }
}
