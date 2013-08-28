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

package org.openecard.plugins.phrplugin.tls;

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType.RecognitionInfo;
import iso.std.iso_iec._24727.tech.schema.EstablishContext;
import iso.std.iso_iec._24727.tech.schema.EstablishContextResponse;
import iso.std.iso_iec._24727.tech.schema.GetRecognitionTreeResponse;
import iso.std.iso_iec._24727.tech.schema.ListIFDs;
import iso.std.iso_iec._24727.tech.schema.ListIFDsResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import org.openecard.bouncycastle.crypto.tls.Certificate;
import org.openecard.bouncycastle.crypto.tls.ProtocolVersion;
import org.openecard.bouncycastle.crypto.tls.TlsAuthentication;
import org.openecard.bouncycastle.crypto.tls.TlsClientProtocol;
import org.openecard.bouncycastle.crypto.tls.TlsServerProtocol;
import org.openecard.common.ClientEnv;
import org.openecard.common.ECardConstants;
import org.openecard.common.enums.EventType;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.sal.state.SALStateCallback;
import org.openecard.common.util.StringUtils;
import org.openecard.crypto.common.sal.GenericCryptoSigner;
import org.openecard.crypto.tls.ClientCertDefaultTlsClient;
import org.openecard.crypto.tls.ClientCertTlsClient;
import org.openecard.crypto.tls.auth.CredentialFactory;
import org.openecard.crypto.tls.auth.DynamicAuthentication;
import org.openecard.crypto.tls.auth.SimpleSmartCardCredentialFactory;
import org.openecard.gui.swing.SwingDialogWrapper;
import org.openecard.gui.swing.SwingUserConsent;
import org.openecard.ifd.scio.IFD;
import org.openecard.plugins.phrplugin.CardUtils;
import org.openecard.recognition.CardRecognition;
import org.openecard.sal.TinySAL;
import org.openecard.sal.protocol.genericcryptography.GenericCryptoProtocolFactory;
import org.openecard.sal.protocol.pincompare.PINCompareProtocolFactory;
import org.openecard.transport.dispatcher.MessageDispatcher;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static org.testng.Assert.assertTrue;


/**
 * Manual test for TLS client authentication using the german health care card.
 * It ensures the correct use of the card as client credential.
 * This test needs an (arbitrary) german health care card to run.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class EgkTlsAuthenticationTest {

    private static final String DID_NAME_AUTN = "PrK.CH.AUTN";
    private static final Logger logger = LoggerFactory.getLogger(EgkTlsAuthenticationTest.class);
    private static final byte[] cardApplication_ROOT = StringUtils.toByteArray("D2760001448000");
    private static final byte[] CARD_APP_ESIGN = StringUtils.toByteArray("A000000167455349474E");
    private static final String HOSTNAME = "localhost";
    private static final int PORT = 1234;
    private static final boolean skip = true;

    private static ClientEnv env;
    private static TinySAL instance;
    private static CardStateMap states;
    private static IFD ifd;
    private static WSMarshaller marshaller;
    private static Dispatcher dispatcher;

    private AssertionError serverAssertionError;
    private static ConnectionHandleType connectionHandleType;

    @BeforeClass
    public static void setUp() throws Exception {
	if (skip) {
	    throw new SkipException("Test completely disabled.");  
	} 
	env = new ClientEnv();
	dispatcher = new MessageDispatcher(env);
	env.setDispatcher(dispatcher);
	ifd = new IFD();
	ifd.setGUI(new SwingUserConsent(new SwingDialogWrapper()));
	env.setIFD(ifd);
	states = new CardStateMap();
	marshaller = WSMarshallerFactory.createInstance();
	marshaller.removeAllTypeClasses();
	marshaller.addXmlTypeClass(GetRecognitionTreeResponse.class);
	EstablishContextResponse ecr = env.getIFD().establishContext(new EstablishContext());
	CardRecognition cr = new CardRecognition(ifd, ecr.getContextHandle());
	ListIFDs listIFDs = new ListIFDs();

	listIFDs.setContextHandle(ecr.getContextHandle());
	ListIFDsResponse listIFDsResponse = ifd.listIFDs(listIFDs);
	RecognitionInfo recognitionInfo = cr.recognizeCard(listIFDsResponse.getIFDName().get(0), new BigInteger("0"));
	SALStateCallback salCallback = new SALStateCallback(cr, states);

	connectionHandleType = new ConnectionHandleType();
	connectionHandleType.setContextHandle(ecr.getContextHandle());
	connectionHandleType.setRecognitionInfo(recognitionInfo);
	connectionHandleType.setIFDName(listIFDsResponse.getIFDName().get(0));
	connectionHandleType.setSlotIndex(new BigInteger("0"));

	salCallback.signalEvent(EventType.CARD_RECOGNIZED, connectionHandleType);
	instance = new TinySAL(env, states);
	env.setSAL(instance);

	connectionHandleType = CardUtils.connectToCardApplication(connectionHandleType, cardApplication_ROOT, dispatcher);
	boolean authStatus = CardUtils.authenticatePINHome(connectionHandleType, dispatcher, states);
	Assert.assertTrue(authStatus);
    }

    private void setServerAssertionError(AssertionError ae) {
	this.serverAssertionError = ae;
    }

    /**
     * Starts a TLS Server and connects to this server with SmartCardCredential.
     * The Server checks that a client certificate which contains 'gematik' is send.
     * 
     * @throws Exception
     */
    @Test
    public void test() throws Exception {
	Thread serverThread = new TlsServerThread();
	serverThread.start();

	Socket clientSocket = null;
	try {
	    clientSocket = new Socket(HOSTNAME, PORT);
	    assertTrue(clientSocket.isConnected());
	    connectionHandleType = CardUtils.connectToCardApplication(connectionHandleType, CARD_APP_ESIGN, dispatcher);
	    if (connectionHandleType == null) {
		throw new Exception("Failed to connect to esign application.");
	    }
	    GenericCryptoSigner signer = new GenericCryptoSigner(dispatcher, connectionHandleType, DID_NAME_AUTN);
	    CredentialFactory fac = new SimpleSmartCardCredentialFactory(signer);
	    TlsAuthentication tlsAuth = new DynamicAuthentication(null, null, fac);
	    ClientCertTlsClient tlsClient = new ClientCertDefaultTlsClient(HOSTNAME);
	    tlsClient.setAuthentication(tlsAuth);
	    tlsClient.setClientVersion(ProtocolVersion.TLSv11);
	    InputStream inputStream = clientSocket.getInputStream();
	    OutputStream outputStream = clientSocket.getOutputStream();
	    TlsClientProtocol handler = new TlsClientProtocol(inputStream, outputStream);
	    handler.connect(tlsClient);
	} catch (IOException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw ex;
	} finally {
	    if (clientSocket != null) {
		try {
		    clientSocket.close();
		} catch (IOException e) {
		    logger.error("Failed to close client socket.", e);
		}
	    }
	}

	// wait for server thread and check if it threw an assertion error
	serverThread.join();
	if (serverAssertionError != null) {
	    throw serverAssertionError;
	}
    }

    private final class TlsServerThread extends Thread {
	public void run() {
	    ServerSocket serverSocket = null;
	    try {
		serverSocket = new ServerSocket(1234);
		Socket s = serverSocket.accept();
		TlsServerProtocol server = new TlsServerProtocol(s.getInputStream(), s.getOutputStream(),
			new SecureRandom());
		server.accept(new TestTlsServer() {
		    @Override
		    public void notifyClientCertificate(Certificate certificates) throws IOException {
			try {
			    String issuer = certificates.getCertificateAt(0).getIssuer().toString();
			    assertTrue(issuer.contains("gematik"));
			} catch (AssertionError ae) {
			    setServerAssertionError(ae);
			}
			super.notifyClientCertificate(certificates);
		    }
		});
	    } catch (IOException e) {
		logger.error(e.getMessage(), e);
	    } finally {
		if (serverSocket != null) {
		    try {
			serverSocket.close();
		    } catch (IOException e) {
			logger.error("Failed to close server socket.", e);
		    }
		}
	    }
	}
    }

}
