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

import iso.std.iso_iec._24727.tech.schema.CardApplicationConnect;
import iso.std.iso_iec._24727.tech.schema.CardApplicationConnectResponse;
import iso.std.iso_iec._24727.tech.schema.CardApplicationPathType;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DSIRead;
import iso.std.iso_iec._24727.tech.schema.DSIReadResponse;
import iso.std.iso_iec._24727.tech.schema.DataSetSelect;
import iso.std.iso_iec._24727.tech.schema.DataSetSelectResponse;
import iso.std.iso_iec._24727.tech.schema.PinCompareDIDAuthenticateInputType;
import java.lang.reflect.InvocationTargetException;
import org.openecard.common.ECardConstants;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.apdu.exception.APDUException;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.sal.state.CardStateEntry;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.util.ByteUtils;
import org.openecard.common.util.Pair;
import org.openecard.common.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Convenience class for card operations that are not connected to cryptology.
 * This bundles functions connection to card applications and reading/writing of DSIs.
 * 
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class CardUtils {

    private static final Logger logger = LoggerFactory.getLogger(CardUtils.class);

    private static final byte[] CARD_APP_ROOT = StringUtils.toByteArray("D2760001448000");
    private static final byte[] FID_EF_VERWEIS = new byte[] {(byte) 0xD0, 0x09 };
    private static final byte[] CARD_APP_HEALTH_CARE = StringUtils.toByteArray("D27600000102");

    /**
     * Connect to the given application of the card specified with a connection handle using a empty CardApplicationPath
     * and afterwards a CardApplicationConnect.
     * 
     * @param cHandle The connection handle for the card
     * @param applicationIdentifier identifier of the card application
     * @param dispatcher Dispatcher for message delivery
     * @return The updated connection handle (now including a SlotHandle)
     */
    public static ConnectionHandleType connectToCardApplication(ConnectionHandleType cHandle, 
	    byte[] applicationIdentifier, Dispatcher dispatcher) {
	ConnectionHandleType handle = null;
	try {
	    CardApplicationPathType reqPath = new CardApplicationPathType();
	    reqPath.setCardApplication(applicationIdentifier);
	    reqPath.setChannelHandle(cHandle.getChannelHandle());
	    reqPath.setContextHandle(cHandle.getContextHandle());
	    reqPath.setIFDName(cHandle.getIFDName());
	    reqPath.setSlotIndex(cHandle.getSlotIndex());

	    CardApplicationConnect cardApplicationConnect = new CardApplicationConnect();
	    cardApplicationConnect.setCardApplicationPath(reqPath);
	    CardApplicationConnectResponse cardApplicationConnectResponse = 
		    (CardApplicationConnectResponse) dispatcher.deliver(cardApplicationConnect);

	    // Check CardApplicationConnectResponse
	    WSHelper.checkResult(cardApplicationConnectResponse);

	    // Update ConnectionHandle. It now includes a SlotHandle.
	    handle = cardApplicationConnectResponse.getConnectionHandle();
	} catch (InvocationTargetException e) {
	    logger.error("Connecting to card application failed.", e);
	} catch (WSException e) {
	    logger.error("Connecting to card application failed.", e);
	} catch (DispatcherException e) {
	    logger.error("Connecting to card application failed.", e);
	}
	return handle;
    }

    /**
     * Authenticate PIN.home if not already authenticated.
     *
     * @param cHandle connection handle identifying the card
     * @param dispatcher dispatcher for message communication
     * @param cardStateMap CardStatMap to check of PIN.home is already authenticated
     * @return true if PIN.home is authenticated, otherwise false
     */
    public static boolean authenticatePINHome(ConnectionHandleType cHandle, Dispatcher dispatcher, 
	    CardStateMap cardStateMap) {
	// getEntry throws Nullpointerexception when two entries exist for one card
	// this happend at FOKUS, but can not be reproduced at HS Coburg
	//CardStateEntry entry = cardStateMap.getEntry(cHandle);
	CardStateEntry entry = cardStateMap.getMatchingEntries(cHandle).iterator().next();
	if (entry.isAuthenticated("PIN.home", CARD_APP_ROOT)) {
	    return true;
	}
	try {
	    cHandle = connectToCardApplication(cHandle, CARD_APP_ROOT, dispatcher);
	    DIDAuthenticate didAthenticate = new DIDAuthenticate();
	    didAthenticate.setDIDName("PIN.home");
	    PinCompareDIDAuthenticateInputType didAuthenticationData = new PinCompareDIDAuthenticateInputType();
	    didAthenticate.setAuthenticationProtocolData(didAuthenticationData);
	    didAthenticate.setConnectionHandle(cHandle);
	    didAthenticate.getConnectionHandle().setCardApplication(CARD_APP_ROOT);
	    didAuthenticationData.setProtocol(ECardConstants.Protocol.PIN_COMPARE);
	    didAthenticate.setAuthenticationProtocolData(didAuthenticationData);
	    DIDAuthenticateResponse didAuthenticateResult = (DIDAuthenticateResponse) dispatcher.deliver(didAthenticate);
	    WSHelper.checkResult(didAuthenticateResult);
	    return true;
	} catch (InvocationTargetException e) {
	    logger.error(e.getMessage(), e);
	} catch (WSException e) {
	    logger.error(e.getMessage(), e);
	} catch (DispatcherException e) {
	    logger.error(e.getMessage(), e);
	}
	return false;
    }

    /**
     * Read the contents of the DSI identified through dsiName and cardApplication and return the contents.
     *
     * @param cHandle connection handle identifying the card
     * @param dsiName name of the DSI
     * @param cardApplication identifier of card application
     * @param dispatcher {@link Dispatcher} for message communication
     * @param cardStates {@link CardStateMap}
     * @return Pair of dsi contents and updated connection handle
     */
    public static Pair<byte[], ConnectionHandleType> readDSI(ConnectionHandleType cHandle, String dsiName, 
	    byte[] cardApplication, Dispatcher dispatcher, CardStateMap cardStates) {
	byte[] content = null;
	try {
	    if (! CardUtils.authenticatePINHome(cHandle, dispatcher, cardStates)) {
		String msg = "User authentication by the means of PIN Home failed.";
		logger.error(msg);
		return null;
	    }

	    cHandle = CardUtils.connectToCardApplication(cHandle, cardApplication, dispatcher);
	    datasetSelect(cHandle, dsiName, dispatcher);

	    DSIRead dsiRead = new DSIRead();
	    dsiRead.setConnectionHandle(cHandle);
	    dsiRead.getConnectionHandle().setCardApplication(cardApplication);
	    dsiRead.setDSIName(dsiName);
	    DSIReadResponse dsiReadResponse = (DSIReadResponse) dispatcher.deliver(dsiRead);
	    WSHelper.checkResult(dsiReadResponse);
	    content = dsiReadResponse.getDSIContent();
	} catch (InvocationTargetException e) {
	    logger.error(e.getMessage(), e);
	} catch (WSException e) {
	    logger.error(e.getMessage(), e);
	} catch (DispatcherException e) {
	    logger.error(e.getMessage(), e);
	}
	return new Pair<byte[], ConnectionHandleType>(content, cHandle);
    }

    public static void datasetSelect(ConnectionHandleType cHandle, String datasetName, Dispatcher dispatcher)
	    throws WSException, DispatcherException, InvocationTargetException {
	DataSetSelect req = new DataSetSelect();
	req.setConnectionHandle(cHandle);
	req.setDataSetName(datasetName);
	DataSetSelectResponse res = (DataSetSelectResponse) dispatcher.deliver(req);
	WSHelper.checkResult(res);
    }

    /**
     * Write the given IDs into EF.Verweis on the german health care card.
     * 
     * @param cHandle connection handle identifying the card
     * @param providerID ID of the provider
     * @param recordIDString ID of the record as String
     * @param dispatcher dispatcher for message communication
     * @return true if the IDs have been written successfully, otherwise false
     */
    static boolean writeEFVerweis(ConnectionHandleType cHandle, String providerID, String recordIDString, 
	    Dispatcher dispatcher) {
	byte[] recordID = StringUtils.toByteArray(recordIDString);
	if (recordID.length != 12) {
	    logger.error("Length of recordID must be 12 (6 Bytes in String representation).");
	    return false;
	}
	byte[] data = new byte[] { 0x00, 0x45, 0x50, 0x41, 0x01 };
	data = ByteUtils.concatenate(data, StringUtils.toByteArray(providerID));
	data = ByteUtils.concatenate(data, recordID);
	logger.debug("Data that will be written to EF.Verweis:" + ByteUtils.toHexString(data));
	try {
	    cHandle = CardUtils.connectToCardApplication(cHandle, CARD_APP_HEALTH_CARE, dispatcher);
	    if (cHandle != null) {
		byte[] slotHandle = cHandle.getSlotHandle();
		org.openecard.common.apdu.utils.CardUtils.writeFile(dispatcher, slotHandle, FID_EF_VERWEIS, data);
		return true;
	    } else {
		logger.error("Connection to health care application failed.");
	    }
	} catch (APDUException e) {
	    logger.error("Writing EF.Verweis failed.", e);
	}
	return false;
    }

}
