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

import org.openecard.common.util.ByteUtils;


/**
 * Convenience class for easier access to the byte contents of EF.Verweis on german health care cards.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public class EFVerweis {

    private byte[] serviceType = new byte[4];
    private byte recordType;
    private byte[] providerID = new byte[3];
    private byte[] recordID = new byte[12];

    /**
     * Creates a new EFVerweis object from the record data read from the card.
     * 
     * @param raw raw record data as read from the card
     * @throws IllegalArgumentException if the length of the raw record data is not equal to 20
     */
    public EFVerweis(byte[] raw) {
	if (raw.length != 20) {
	    throw new IllegalArgumentException("EF.Verweis record data length needs to be 20.");
	}
	System.arraycopy(raw, 0, serviceType, 0, 4);
	recordType = raw[4];
	System.arraycopy(raw, 5, providerID, 0, 3);
	System.arraycopy(raw, 8, recordID, 0, 12);
    }

    public byte[] getServiceType() {
	return ByteUtils.clone(serviceType);
    }

    public byte getRecordType() {
	return recordType;
    }

    public byte[] getProviderID() {
	return ByteUtils.clone(providerID);
    }

    public byte[] getRecordID() {
	return ByteUtils.clone(recordID);
    }

    @Override
    public String toString() {
	String string = 
		"ServiceType: " + ByteUtils.toHexString(serviceType) + 
		" RecordType: " + recordType +
		" ProviderID: " + ByteUtils.toHexString(providerID) + 
		" RecordID: " + ByteUtils.toHexString(recordID);
	return string;
    }

}
