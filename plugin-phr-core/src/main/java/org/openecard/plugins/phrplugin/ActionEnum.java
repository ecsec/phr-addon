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


/**
 * Enum with all actions supported by the PHR plugin.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public enum ActionEnum {

    LOCATE("locate"), 
    INITIALIZE("initialize"), 
    GETINFORMATIONOBJECT("getInformationObject"), 
    PUTINFORMATIONOBJECT("putInformationObject"),
    GETPD("getPD");

    private final String text;

    /**
     * @param text
     */
    private ActionEnum(final String text) {
	this.text = text;
    }

    @Override
    public String toString() {
	return text;
    }

    public static ActionEnum get(String text) {
	for (ActionEnum actionEnum : values()) {
	    if (actionEnum.toString().equalsIgnoreCase(text)) {
		return actionEnum;
	    }
	}

	throw new IllegalArgumentException(text + " is not a valid ActionEnum");
    }

}
