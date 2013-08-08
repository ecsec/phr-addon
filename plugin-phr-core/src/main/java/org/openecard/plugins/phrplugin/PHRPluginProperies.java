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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.openecard.common.util.FileUtils;


/**
 * Helper class for loading the provider properties of the PHR plugin.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public final class PHRPluginProperies {

    private static final Properties props = new Properties();

    /**
     * Loads the plugin Properties from the properties file in the home configuration directory.
     * <br/> Creates the properties file if it doesn't exist.
     *
     * @throws IOException if the home configuration directory coudn't be found or the properties file coudn't be loaded
     */
    public static void loadProperties() throws IOException {
	InputStream is = null;

	String propFileStr = FileUtils.getHomeConfigDir().getAbsolutePath() + File.separatorChar + "plugins"
		+ File.separatorChar + "PHR" + ".properties";
	File propFile = new File(propFileStr);

	if (! propFile.exists()) {
	    propFile.createNewFile();
	}

	is = new FileInputStream(propFile);
	props.load(is);
    }

    /**
     * Searches for the property with the specified key in this property list.
     * The method returns null if the property is not found.
     *
     * @param key the property key.
     * @return the value in this property list with the specified key value.
     */
    public static String getProperty(String key) {
	return props.getProperty(key);
    }

}
