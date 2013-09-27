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

import iso.std.iso_iec._24727.tech.schema.CardApplicationConnect;
import iso.std.iso_iec._24727.tech.schema.CardApplicationConnectResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPath;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathResponse.CardAppPathResultSet;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType.RecognitionInfo;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DIDScopeType;
import iso.std.iso_iec._24727.tech.schema.Decipher;
import iso.std.iso_iec._24727.tech.schema.DecipherResponse;
import iso.std.iso_iec._24727.tech.schema.EstablishContext;
import iso.std.iso_iec._24727.tech.schema.EstablishContextResponse;
import iso.std.iso_iec._24727.tech.schema.ListIFDs;
import iso.std.iso_iec._24727.tech.schema.ListIFDsResponse;
import iso.std.iso_iec._24727.tech.schema.PinCompareDIDAuthenticateInputType;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.openecard.common.ClientEnv;
import org.openecard.common.ECardConstants;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.enums.EventType;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.sal.state.SALStateCallback;
import org.openecard.common.util.FileUtils;
import org.openecard.common.util.StringUtils;
import org.openecard.gui.swing.SwingDialogWrapper;
import org.openecard.gui.swing.SwingUserConsent;
import org.openecard.ifd.scio.IFD;
import org.openecard.recognition.CardRecognition;
import org.openecard.sal.TinySAL;
import org.openecard.transport.dispatcher.MessageDispatcher;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerFactory;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import static org.testng.Assert.assertEquals;


/**
 * Manual test for super de- and encryption of medical data objects. <br/>
 * This test uses the german health care card and a self generated record key pair to test super de- and encryption of
 * medical data objects.
 * It works only for the german health care cards with a insurance number X110102997 OR X110103001.
 * 
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class MDOSuperDeAndEncryptionTest {

    private static final byte[] cardApplication = StringUtils.toByteArray("A000000167455349474E");
    private static final byte[] cardApplication_ROOT = StringUtils.toByteArray("D2760001448000");
    private static final int KEYSIZE = 2048;
    private static final String KEYALGORITHM = "RSA";
    private static final String ORIGINAL_MDO = "crypto/medplan_schühmann.xml";
    private static final String SUPERENCRYPTEDMDOFILE = 
	//"crypto/superencryptedMDO_X110103001.xml";
	"crypto/superencryptedMDO_X110102997.xml";
    private static final boolean skip = true;

    private static ClientEnv env;
    private static TinySAL instance;
    private static CardStateMap states;
    private static IFD ifd;
    private static WSMarshaller marshaller;
    static ConnectionHandleType connectionHandleType;
    static Dispatcher d;

    @BeforeClass
    public static void setUp() throws Exception {
	if (skip) {
	    throw new SkipException("Test completely disabled");
	}
	env = new ClientEnv();
	d = new MessageDispatcher(env);
	env.setDispatcher(d);
	ifd = new IFD();
	ifd.setGUI(new SwingUserConsent(new SwingDialogWrapper()));
	env.setIFD(ifd);
	states = new CardStateMap();

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

	marshaller = WSMarshallerFactory.createInstance();
    }

    /**
     * Test if a MDO is encrypted correctly with super encryption.
     *
     * @throws Exception if the test fails
     */
    @Test(enabled = true)
    public void testSuperencryptMDO() throws Exception {
	MDOCrypto enc = new MDOCrypto();
	CardCrypto cardCrypto = new CardCrypto(d, connectionHandleType);
	// Generate the record key pair
	KeyPair keyPairRecord = enc.generateKeyPair(KEYALGORITHM, KEYSIZE);

	// Create the, with the EGK-publicKey hybrid-encrypted, privateKey
	// of the record
	X509Certificate certEGK = cardCrypto.getENCCertificateFromEGK(states);
	Document encPrivateKeyRecordEGK = enc.encryptPrivateKeyRecord(keyPairRecord.getPrivate(),
		certEGK.getPublicKey(), MDOCrypto.getSubjectKeyIdentifier(certEGK));

	// Create the, with the publicKey of the record hybrid-encrypted, MDO
	InputStream mdoStream = FileUtils.resolveResourceAsStream(MDOSuperDeAndEncryptionTest.class, ORIGINAL_MDO);
	Document mdoString = marshaller.str2doc(mdoStream);
	Document encMdo = enc.encryptMDO(mdoString, keyPairRecord.getPublic());

	// Create the superEncrypted MDO
	Document superEncMdo = enc.mergeDocuments(encMdo, encPrivateKeyRecordEGK);
	Document decryptedMdo = superDecryptMDO(superEncMdo);

	// Compare the MDO after encryption and decryption with the original MDO
	mdoStream = FileUtils.resolveResourceAsStream(MDOSuperDeAndEncryptionTest.class, ORIGINAL_MDO);
	String originalMDOString = marshaller.doc2str(marshaller.str2doc(mdoStream));
	String decryptedMDOString = marshaller.doc2str(decryptedMdo);
	assertEquals(formatXML(decryptedMDOString), formatXML(originalMDOString));
    }

    /**
     * Test if a super encrypted MDO is decrypted correctly.
     *
     * @throws Exception if the test fails
     */
    @Test(enabled = true)
    public void testSuperdecryptMDO() throws Exception {
	// Get the pre super encrypted MDO document
	InputStream streamEncryptedMDO = FileUtils.resolveResourceAsStream(MDOSuperDeAndEncryptionTest.class, SUPERENCRYPTEDMDOFILE);
	Document superEncMdo = marshaller.str2doc(FileUtils.toString(streamEncryptedMDO));

	// Decrypt the document
	Document decrMdo = superDecryptMDO(superEncMdo);

	// compare the decrypted MDO with the original MDO
	InputStream streamOriginalMDO = FileUtils.resolveResourceAsStream(MDOSuperDeAndEncryptionTest.class, ORIGINAL_MDO);
	String originalMDOString = marshaller.doc2str(marshaller.str2doc(streamOriginalMDO));
	String decryptedMDOString = marshaller.doc2str(marshaller.str2doc(marshaller.doc2str(decrMdo)));
	assertEquals(formatXML(decryptedMDOString), formatXML(originalMDOString));
    }

    private Document superDecryptMDO(Document superEncMdo) throws EncryptionException, WSException {
	MDOCrypto enc = new MDOCrypto();
	// Extract the hybrid-encrypted privateKey of the record
	Document extractedEncPrivKeyRec = enc.extractEncryptedPrivateKeyRecord(superEncMdo);

	// Extract the, with the publicKey of the German health care card encrypted,
	// symmetric key
	byte[] extractedEncSymKey = enc.extractEncSymmetricKey(extractedEncPrivKeyRec);

	// decrypt the encrypted symmetric key by the use of the German health care card
	byte[] decryptedSymKey = decryptSymmetricKeyEGK(extractedEncSymKey);

	// decrypt the private key of the record by the use of the symmetric key
	byte[] decrPrivKeyRec = enc.decryptPrivateKeyRecord(extractedEncPrivKeyRec, decryptedSymKey);

	// decrypt the MDO which is encrypted wit the records public key by the use of the records private key
	Document decrMdo = enc.decryptMDO(superEncMdo, decrPrivKeyRec);
	return decrMdo;
    }

    private byte[] decryptSymmetricKeyEGK(byte[] extractedEncSymKey) throws WSException {
	CardApplicationPath cardApplicationPath = new CardApplicationPath();
	CardApplicationPathType cardApplicationPathType = new CardApplicationPathType();
	cardApplicationPathType.setCardApplication(cardApplication);
	cardApplicationPath.setCardAppPathRequest(cardApplicationPathType);
	CardApplicationPathResponse cardApplicationPathResponse = instance.cardApplicationPath(cardApplicationPath);
	WSHelper.checkResult(cardApplicationPathResponse);
	CardApplicationConnect parameters = new CardApplicationConnect();
	CardAppPathResultSet cardAppPathResultSet = cardApplicationPathResponse.getCardAppPathResultSet();
	parameters.setCardApplicationPath(cardAppPathResultSet.getCardApplicationPathResult().get(0));
	CardApplicationConnectResponse result = instance.cardApplicationConnect(parameters);
	WSHelper.checkResult(result);
	assertEquals(ECardConstants.Major.OK, result.getResult().getResultMajor());

	DIDAuthenticate didAthenticate = new DIDAuthenticate();
	didAthenticate.setDIDName("PIN.home");
	PinCompareDIDAuthenticateInputType didAuthenticationData = new PinCompareDIDAuthenticateInputType();
	didAthenticate.setAuthenticationProtocolData(didAuthenticationData);
	didAthenticate.setConnectionHandle(result.getConnectionHandle());
	didAthenticate.getConnectionHandle().setCardApplication(cardApplication_ROOT);
	didAuthenticationData.setProtocol(ECardConstants.Protocol.PIN_COMPARE);
	didAthenticate.setAuthenticationProtocolData(didAuthenticationData);
	DIDAuthenticateResponse didAuthenticateResult = instance.didAuthenticate(didAthenticate);
	WSHelper.checkResult(didAuthenticateResult);

	assertEquals(didAuthenticateResult.getAuthenticationProtocolData().getProtocol(),
		ECardConstants.Protocol.PIN_COMPARE);
	assertEquals(didAuthenticateResult.getAuthenticationProtocolData().getAny().size(), 0);
	assertEquals(ECardConstants.Major.OK, didAuthenticateResult.getResult().getResultMajor());

	Decipher decipher = new Decipher();
	decipher.setCipherText(extractedEncSymKey);
	decipher.setConnectionHandle(result.getConnectionHandle());
	decipher.getConnectionHandle().setCardApplication(cardApplication);
	decipher.setDIDName("PrK.CH.ENC_rsaDecipherPKCS1_V1_5");
	decipher.setDIDScope(DIDScopeType.LOCAL);
	DecipherResponse decipherResponse = instance.decipher(decipher);

	return decipherResponse.getPlainText();
    }

    private static String formatXML(String input, int indent) {
	try {
	    Source xmlInput = new StreamSource(new StringReader(input));
	    StringWriter stringWriter = new StringWriter();
	    StreamResult xmlOutput = new StreamResult(stringWriter);
	    TransformerFactory transformerFactory = TransformerFactory.newInstance();
	    transformerFactory.setAttribute("indent-number", indent);
	    Transformer transformer = transformerFactory.newTransformer();
	    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
	    transformer.transform(xmlInput, xmlOutput);
	    return xmlOutput.getWriter().toString();
	} catch (TransformerConfigurationException e) {
	    // TODO log
	    return input;
	} catch (TransformerException e) {
	    // TODO log
	    return input;
	}
    }

    private static String formatXML(String input) {
	return formatXML(input, 2);
    }

}
