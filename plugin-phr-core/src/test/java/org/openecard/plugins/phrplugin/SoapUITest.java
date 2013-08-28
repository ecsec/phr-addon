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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;


/**
 * Test the correct integration of PHR Plugin and HTTP Binding.
 * This test starts up a test client and sends a http request for an information object to it.
 * If everything works correctly the information object is returned.
 * Because of SoapUI this test can not be executed standalone.
 * The german health care card with insurance number X110102997 is required because the test messages are encrypted
 * for it.
 * 
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class SoapUITest {

    private static final Logger logger = LoggerFactory.getLogger(SoapUITest.class);
    private static final boolean skip = true;

    /**
     * Start up the TestClient.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setUpClass() throws Exception {
	if (skip) {
	    throw new SkipException("Test completely disabled");
	}
	try {
	    new TestClient();
	    // Wait some seconds until the SAL comes up
	    Thread.sleep(2500);
	} catch (Exception e) {
	    logger.debug(e.getMessage(), e);
	    Assert.fail();
	}
    }

    @Test(enabled = true)
    public void testeIDClient() {
	try {
	    URL u = new URL("http://localhost:24727/phr-Client?action=getInformationObject&semanticSignifier=MedicationSummary&output=xhtml");
	    String response = httpRequest(u, false);

	    Assert.assertNotNull(response);
	    Assert.assertEquals(response.length(), 7667);
	} catch (Exception e) {
	    logger.debug(e.getMessage(), e);
	    Assert.fail();
	}
    }

    /**
     * Performs a HTTP Request (GET or POST) to the specified URL and returns the response as String.
     *
     * @param url URL to connect to
     * @param doPOST true for POST, false for GET
     * @return response as string
     */
    private static String httpRequest(URL url, boolean doPOST) {
	HttpURLConnection c = null;
	try {
	    c = (HttpURLConnection) url.openConnection();
	    if (doPOST) {
		c.setDoOutput(true);
		c.getOutputStream();
	    }
	    BufferedReader in = new BufferedReader(new InputStreamReader(c.getInputStream()));
	    String inputLine;
	    StringBuilder content = new StringBuilder(4096);

	    while ((inputLine = in.readLine()) != null) {
		content.append(inputLine);
	    }
	    in.close();

	    return content.toString();
	} catch (IOException e) {
	    if (c.getErrorStream() != null) {
		try {
		    readErrorStream(c.getErrorStream());
		} catch (IOException ioe) {
		    logger.error(e.getMessage(), e);
		}
	    }
	    logger.error(e.getMessage(), e);
	    return null;
	}
    }
    /**
     * Reads the HTML Error Response from the Server.
     */
    private static void readErrorStream(InputStream errorStream) throws IOException {
	BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(errorStream));
	StringBuilder stringBuilder = new StringBuilder(4096);

	String line;
	while ((line = bufferedReader.readLine()) != null) {
	    stringBuilder.append(line);
	}

	logger.error("HTML Error response from server:\n{}", stringBuilder.toString());
    }

}
