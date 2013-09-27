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

import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.DIDScopeType;
import iso.std.iso_iec._24727.tech.schema.DSIRead;
import iso.std.iso_iec._24727.tech.schema.DSIReadResponse;
import iso.std.iso_iec._24727.tech.schema.Decipher;
import iso.std.iso_iec._24727.tech.schema.DecipherResponse;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.openecard.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.util.StringUtils;
import org.openecard.plugins.phrplugin.CardUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

/**
 * Convenience class for crypto related operations with the german health care card.
 * This bundles functions for reading x.509 certificates and super decrypting information objects.
 * 
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class CardCrypto {

    private static final Logger logger = LoggerFactory.getLogger(CardCrypto.class);
    private Dispatcher dispatcher;
    private ConnectionHandleType cHandle;
    private static final byte[] CARD_APP_ESIGN = StringUtils.toByteArray("A000000167455349474E");
    private static final String EF_C_CH_ENC = "EF.C.CH.ENC";
    private static final String EF_C_CH_AUTN = "EF.C.CH.AUTN";

    /**
     * Create a new CardCrypto object that uses the given dispatcher to send messages to the card given via cHandle.
     *
     * @param dispatcher Dispatcher to use for sending messages
     * @param cHandle connection handle for the card to use
     */
    public CardCrypto(Dispatcher dispatcher, ConnectionHandleType cHandle) {
	this.dispatcher = dispatcher;
	this.cHandle = cHandle;
    }

    /**
     * Reads and returns the ENC certificate of the eGK as {@link X509Certificate}.
     *
     * @return ENC as {@link X509Certificate}
     */
    public X509Certificate getENCCertificateFromEGK(CardStateMap cardStates) {
	X509Certificate certEGK = null;
	try {
	    CardUtils.authenticatePINHome(cHandle, dispatcher, cardStates);
	    cHandle = CardUtils.connectToCardApplication(cHandle, CARD_APP_ESIGN, dispatcher);

	    CardUtils.datasetSelect(cHandle, EF_C_CH_ENC, dispatcher);

	    // read the certificate
	    DSIRead dsiRead = new DSIRead();
	    dsiRead.setConnectionHandle(cHandle);
	    dsiRead.getConnectionHandle().setCardApplication(CARD_APP_ESIGN);
	    dsiRead.setDSIName(EF_C_CH_ENC);
	    DSIReadResponse dsiReadResponse = (DSIReadResponse) dispatcher.deliver(dsiRead);
	    WSHelper.checkResult(dsiReadResponse);

	    CertificateFactory fac = CertificateFactory.getInstance("X.509");
	    ByteArrayInputStream certStream = new ByteArrayInputStream(dsiReadResponse.getDSIContent());
	    certEGK = (X509Certificate) fac.generateCertificate(certStream);
	} catch (WSException e) {
	    logger.error(e.getMessage(), e);
	} catch (CertificateException e) {
	    logger.error(e.getMessage(), e);
	} catch (InvocationTargetException e) {
	    logger.error(e.getMessage(), e);
	} catch (DispatcherException e) {
	    logger.error(e.getMessage(), e);
	}
	return certEGK;
    }

    /**
     * Reads and returns the raw bytes of the AUTN certificate of the eGK.
     *
     * @return raw bytes of AUTN
     */
    public byte[] getEncodedAUTNCertificateFromEGK() {
	byte[] certBytes = null;
	try { 
	    // Connect to eSign application
	    cHandle = CardUtils.connectToCardApplication(cHandle, CARD_APP_ESIGN, dispatcher);
	    // read the raw certificate bytes
	    DSIRead dsiRead = new DSIRead();
	    dsiRead.setConnectionHandle(cHandle);
	    dsiRead.getConnectionHandle().setCardApplication(CARD_APP_ESIGN);
	    dsiRead.setDSIName(EF_C_CH_AUTN);
	    DSIReadResponse dsiReadResponse = (DSIReadResponse) dispatcher.deliver(dsiRead);
	    WSHelper.checkResult(dsiReadResponse);
	    certBytes = dsiReadResponse.getDSIContent();
	} catch (WSException e) {
	    logger.error("Could not read Certificate from eGK.", e);
	} catch (InvocationTargetException e) {
	    logger.error("Could not read Certificate from eGK.", e);
	} catch (DispatcherException e) {
	    logger.error("Could not read Certificate from eGK.", e);
	}
	return certBytes;
    }

    /**
     * Reads and returns the AUTN certificate of the eGK as {@link X509Certificate}.
     *
     * @return AUTN as {@link X509Certificate}
     */
    public X509Certificate getAUTNCertificateFromEGK() {
	X509Certificate certEGK = null;
	byte[] certBytes = getEncodedAUTNCertificateFromEGK();
	if (certBytes == null) {
	    return null;
	}
	try {
	    // Convert to X509Certificate
	    CertificateFactory fac = CertificateFactory.getInstance("X.509");
	    ByteArrayInputStream certStream = new ByteArrayInputStream(certBytes);
	    certEGK = (X509Certificate) fac.generateCertificate(certStream);
	} catch (CertificateException e) {
	    logger.error("Could not get X509 certificate factory OR could not parse certificate.", e);
	}
	return certEGK;
    }

    /**
     * Super decrypt the given information object by the use of the german health care card.
     *
     * @param superEncMdo encrypted information object that should be decrypted
     * @return decrypted information object
     * @throws EncryptionException if the decryption fails
     */
    public Document superDecryptMDO(Document superEncMdo) throws EncryptionException {
	logger.debug("Decrypting MDO.");
	MDOCrypto enc = new MDOCrypto();
	// Extract the hybrid-encrypted privateKey of the record
	Document extractedEncPrivKeyRec = enc.extractEncryptedPrivateKeyRecord(superEncMdo);

	// Extract the, with the publicKey of the German health care card encrypted,
	// symmetric key
	byte[] extractedEncSymKey = enc.extractEncSymmetricKey(extractedEncPrivKeyRec);
	logger.debug("Extracted encrypted symmetric key: {} ", ByteUtils.toHexString(extractedEncSymKey));
	// decrypt the encrypted symmetric key by the use of the German health care card
	byte[] decryptedSymKey;
	try {
	    decryptedSymKey = decryptSymmetricKeyEGK(extractedEncSymKey);
	} catch (WSException e) {
	    String msg = "Decryption of symmetric key by the use of the german health care card failed.";
	    logger.error(msg, e);
	    throw new EncryptionException(msg, e);
	} catch (InvocationTargetException e) {
	    String msg = "Decryption of symmetric key by the use of the german health care card failed.";
	    logger.error(msg, e);
	    throw new EncryptionException(msg, e);
	} catch (DispatcherException e) {
	    String msg = "Decryption of symmetric key by the use of the german health care card failed.";
	    logger.error(msg, e);
	    throw new EncryptionException(msg, e);
	}
	logger.debug("Decrypted symmetric key: {} ", ByteUtils.toHexString(decryptedSymKey));
	// decrypt the private key of the record by the use of the symmetric key
	byte[] decrPrivKeyRec = enc.decryptPrivateKeyRecord(extractedEncPrivKeyRec, decryptedSymKey);
	logger.debug("Decrypted private key record: {} ", ByteUtils.toHexString(decrPrivKeyRec));
	// decrypt the MDO which is encrypted wit the records public key by the use of the records private key
	Document decrMdo = enc.decryptMDO(superEncMdo, decrPrivKeyRec);
	return decrMdo;
    }

    private byte[] decryptSymmetricKeyEGK(byte[] extractedEncSymKey) throws WSException, InvocationTargetException,
    DispatcherException {
	logger.debug("Decrypting symmetric Key using german health care card.");
	CardUtils.connectToCardApplication(cHandle, CARD_APP_ESIGN, dispatcher);

	Decipher decipher = new Decipher();
	decipher.setCipherText(extractedEncSymKey);
	decipher.setConnectionHandle(cHandle);
	decipher.getConnectionHandle().setCardApplication(CARD_APP_ESIGN);
	decipher.setDIDName("PrK.CH.ENC_rsaDecipherPKCS1_V1_5");
	decipher.setDIDScope(DIDScopeType.LOCAL);
	DecipherResponse decipherResponse = (DecipherResponse) dispatcher.deliver(decipher);
	WSHelper.checkResult(decipherResponse);

	return decipherResponse.getPlainText();
    }
}
