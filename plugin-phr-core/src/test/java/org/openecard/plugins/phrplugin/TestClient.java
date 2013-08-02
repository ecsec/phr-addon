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

import iso.std.iso_iec._24727.tech.schema.EstablishContext;
import java.io.InputStream;
import org.openecard.addon.AddonManager;
import org.openecard.addon.ClasspathRegistry;
import org.openecard.addon.manifest.AddonBundleDescription;
import org.openecard.common.ClientEnv;
import org.openecard.common.ECardConstants;
import org.openecard.common.sal.state.CardStateMap;
import org.openecard.common.sal.state.SALStateCallback;
import org.openecard.common.util.FileUtils;
import org.openecard.control.ControlInterface;
import org.openecard.control.binding.http.HTTPBinding;
import org.openecard.control.binding.http.handler.common.DefaultHandler;
import org.openecard.control.handler.ControlHandlers;
import org.openecard.event.EventManager;
import org.openecard.gui.swing.SwingDialogWrapper;
import org.openecard.gui.swing.SwingUserConsent;
import org.openecard.ifd.scio.IFD;
import org.openecard.management.TinyManagement;
import org.openecard.recognition.CardRecognition;
import org.openecard.sal.TinySAL;
import org.openecard.sal.protocol.genericcryptography.GenericCryptoProtocolFactory;
import org.openecard.sal.protocol.pincompare.PINCompareProtocolFactory;
import org.openecard.transport.dispatcher.MessageDispatcher;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;


/**
 * Implements a TestClient to test the correct integration of PHR Plugin and HTTP Binding.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 */
public final class TestClient {

    private static final Logger logger = LoggerFactory.getLogger(TestClient.class);

    // Service Access Layer (SAL)
    private TinySAL sal;
    // card states
    private CardStateMap cardStates;

    public TestClient() {
	try {
	    setup();
	} catch (Exception e) {
	    logger.error(e.getMessage(), e);
	}
    }

    private void setup() throws Exception {
	// Set up client environment
	ClientEnv env = new ClientEnv();

	// Set up the IFD
	IFD ifd = new IFD();
	env.setIFD(ifd);

	// Set up Management
	TinyManagement management = new TinyManagement(env);
	env.setManagement(management);

	// Set up the Dispatcher
	MessageDispatcher dispatcher = new MessageDispatcher(env);
	env.setDispatcher(dispatcher);
	ifd.setDispatcher(dispatcher);

	// Perform an EstablishContext to get a ContextHandle
	EstablishContext establishContext = new EstablishContext();

	byte[] contextHandle = ifd.establishContext(establishContext).getContextHandle();

	CardRecognition recognition = new CardRecognition(ifd, contextHandle);

	// Set up EventManager
	EventManager em = new EventManager(recognition, env, contextHandle);
	env.setEventManager(em);

	// Set up SALStateCallback
	cardStates = new CardStateMap();
	SALStateCallback salCallback = new SALStateCallback(recognition, cardStates);
	em.registerAllEvents(salCallback);

	// Set up SAL
	sal = new TinySAL(env, cardStates);
	env.setSAL(sal);

	// Set up GUI
	SwingUserConsent gui = new SwingUserConsent(new SwingDialogWrapper());
	sal.setGUI(gui);
	sal.addProtocol(ECardConstants.Protocol.GENERIC_CRYPTO, new GenericCryptoProtocolFactory());
	sal.addProtocol(ECardConstants.Protocol.PIN_COMPARE, new PINCompareProtocolFactory());
	ifd.setGUI(gui);

	// Initialize the EventManager
	em.initialize();

	WSMarshaller marshaller = WSMarshallerFactory.createInstance();
	marshaller.addXmlTypeClass(AddonBundleDescription.class);
	InputStream manifestStream = FileUtils.resolveResourceAsStream(PHRPluginAction.class, "PHRPlugin-Manifest.xml");
	Document manifestDoc = marshaller.str2doc(manifestStream);
	ClasspathRegistry.getInstance().register((AddonBundleDescription) marshaller.unmarshal(manifestDoc));

	HTTPBinding binding = new HTTPBinding(HTTPBinding.DEFAULT_PORT);
	binding.setAddonManager(AddonManager.createInstance(dispatcher, gui, cardStates, recognition, em, sal.getProtocolInfo()));
	ControlHandlers handler = new ControlHandlers();

	handler.addControlHandler(new DefaultHandler());
	ControlInterface control = new ControlInterface(binding, handler);
	control.start();
    }

}
