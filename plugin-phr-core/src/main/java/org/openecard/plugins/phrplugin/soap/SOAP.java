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

package org.openecard.plugins.phrplugin.soap;

import iso.std.iso_iec._24727.tech.schema.ResponseType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import javax.xml.transform.TransformerException;
import org.omg.spec.rlus._201012.rlusgeneric.InitializeRLUSGenericRequest;
import org.openecard.apache.http.HttpEntity;
import org.openecard.apache.http.HttpException;
import org.openecard.apache.http.HttpResponse;
import org.openecard.apache.http.entity.ContentType;
import org.openecard.apache.http.entity.StringEntity;
import org.openecard.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.openecard.apache.http.protocol.BasicHttpContext;
import org.openecard.apache.http.protocol.HttpContext;
import org.openecard.apache.http.protocol.HttpRequestExecutor;
import org.openecard.bouncycastle.crypto.tls.ProtocolVersion;
import org.openecard.bouncycastle.crypto.tls.TlsClient;
import org.openecard.bouncycastle.crypto.tls.TlsClientProtocol;
import org.openecard.common.WSHelper;
import org.openecard.common.WSHelper.WSException;
import org.openecard.common.interfaces.Dispatcher;
import org.openecard.common.interfaces.DispatcherException;
import org.openecard.common.util.FileUtils;
import org.openecard.crypto.tls.proxy.ProxySettings;
import org.openecard.plugins.phrplugin.PHRPluginProperies;
import org.openecard.plugins.phrplugin.RLUSMessages;
import org.openecard.plugins.phrplugin.crypto.SignatureUtil;
import org.openecard.transport.httpcore.HttpRequestHelper;
import org.openecard.transport.httpcore.HttpUtils;
import org.openecard.transport.httpcore.StreamHttpClientConnection;
import org.openecard.ws.marshal.MarshallingTypeException;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerException;
import org.openecard.ws.soap.SOAPException;
import org.openecard.ws.soap.SOAPHeader;
import org.openecard.ws.soap.SOAPMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;


/**
 * PAOS implementation for JAXB types.
 * This implementation can be configured to speak TLS by creating the instance with a TlsClient. The dispatcher instance
 * is used to deliver the messages to the instances implementing the webservice interfaces.
 *
 * @author Dirk Petrautzki <dirk.petrautzki@hs-coburg.de>
 */
public class SOAP {

    private static final Logger logger = LoggerFactory.getLogger(SOAP.class);

    private final WSMarshaller m;
    private final URL endpoint;
    private final TlsClient tlsClient;

    /**
     * Creates a PAOS instance and configures it for a given endpoint.
     * If tlsClient is not null the connection must be HTTPs, else HTTP.
     *
     * @param endpoint The endpoint of the server.
     * @param dispatcher The dispatcher instance capable of dispatching the received messages.
     * @param tlsClient The TlsClient containing the configuration of the yet to be established TLS channel, or
     *   {@code null} if TLS should not be used.
     * @param marshaller WSMarshaller to use for message (un-)marshalling
     * @throws SOAPException In case the PAOS module could not be initialized.
     */
    public SOAP(URL endpoint, Dispatcher dispatcher, TlsClient tlsClient, WSMarshaller marshaller) 
	    throws SOAPException {
	this.endpoint = endpoint;
	this.tlsClient = tlsClient;
	this.m = marshaller;
    }

    private Object processSOAPResponse(InputStream content) throws SOAPException {
	try {
	    Document doc = m.str2doc(content);
	    SOAPMessage msg = m.doc2soap(doc);

	    if (logger.isDebugEnabled()) {
		try {
		    logger.debug("Message received:\n{}", m.doc2str(doc));
		} catch (TransformerException ex) {
		    logger.warn("Failed to log PAOS request message.", ex);
		}
	    }

	    return m.unmarshal(msg.getSOAPBody().getChildElements().get(0));
	} catch (MarshallingTypeException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new SOAPException(ex.getMessage(), ex);
	} catch (WSMarshallerException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new SOAPException(ex.getMessage(), ex);
	} catch (IOException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new SOAPException(ex.getMessage(), ex);
	} catch (SAXException ex) {
	    logger.error(ex.getMessage(), ex);
	    throw new SOAPException(ex.getMessage(), ex);
	}
    }

    private String createSOAPRequest(Object obj, Element hdr) throws MarshallingTypeException, SOAPException, TransformerException {
	SOAPMessage msg = createSOAPMessage(obj);
	Document document = msg.getDocument();
	SOAPHeader header = msg.getSOAPHeader();

	if (hdr != null) {
	    QName elementName = new QName("http://schemas.xmlsoap.org/ws/2003/06/secext", "Security");
	    Element version = header.addChildElement(elementName);
	    version.appendChild(msg.getDocument().importNode(hdr, true));
	}

	if (obj instanceof InitializeRLUSGenericRequest) {
	    signDocument(document);
	}

	String result = m.doc2str(document);
	logger.debug("Message sent:\n{}", result);

	return result;
    }

    /**
     * Signs the given document with the temp software certificate.
     * This will later be replaced with SMC-B signing.
     * 
     * @param document {@link Document} that will be signed
     */
    private void signDocument(Document document) {
	// TODO replace with hardware key
	java.security.cert.Certificate[] softCert = null;
	PrivateKey myPrivateKey = null;
	try {
	    KeyStore keyStore = KeyStore.getInstance("PKCS12");
	    PHRPluginProperies.loadProperties();
	    InputStream fis2 = FileUtils.resolveResourceAsStream(RLUSMessages.class,
		    PHRPluginProperies.getProperty("cert_file"));
	    keyStore.load(fis2, PHRPluginProperies.getProperty("cert_pw").toCharArray());
	    fis2.close();
	    KeyStore.PasswordProtection param = new KeyStore.PasswordProtection(PHRPluginProperies.getProperty(
		    "cert_pw").toCharArray());
	    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
		    PHRPluginProperies.getProperty("cert_alias"), param);
	    myPrivateKey = pkEntry.getPrivateKey();
	    softCert = keyStore.getCertificateChain(PHRPluginProperies.getProperty("cert_alias"));
	    SignatureUtil.sign(document, (Element) document.getElementsByTagName("xkms:KeyBinding").item(0),
		    (X509Certificate) softCert[0], myPrivateKey);
	} catch (KeyStoreException e) {
	    logger.error("Document signing failed", e);
	} catch (NoSuchAlgorithmException e) {
	    logger.error("Document signing failed", e);
	} catch (CertificateException e) {
	    logger.error("Document signing failed", e);
	} catch (IOException e) {
	    logger.error("Document signing failed", e);
	} catch (UnrecoverableEntryException e) {
	    logger.error("Document signing failed", e);
	}
    }

    private SOAPMessage createSOAPMessage(Object content) throws MarshallingTypeException, SOAPException {
	Document contentDoc = m.marshal(content);
	SOAPMessage msg = m.add2soap(contentDoc);

	return msg;
    }

    /**
     * Sends start PAOS and answers all successor messages to the server associated with this instance.
     * Messages are exchanged until the server replies with a {@code StartPAOSResponse} message.
     *
     * @param message The StartPAOS message which is sent in the first message.
     * @param header that will be placed into SOAP header, may be null
     * @return The {@code StartPAOSResponse} message from the server.
     * @throws DispatcherException In case there errors with the message conversion or the dispatcher.
     * @throws SOAPException In case there were errors in the transport layer.
     */
    public Object sendRequest(Object message, @Nullable Document header) throws DispatcherException, SOAPException {
	Object msg = message;
	String hostname = endpoint.getHost();
	int port = endpoint.getPort();
	if (port == -1) {
	    port = endpoint.getDefaultPort();
	}
	String resource = endpoint.getFile();

	try {
	    StreamHttpClientConnection conn;
	    try {
		conn = createTlsConnection(hostname, port, ProtocolVersion.TLSv11);
	    } catch (IOException e) {
		logger.error("Connecting to the PAOS endpoint with TLSv1.1 failed. Falling back to TLSv1.0.", e);
		conn = createTlsConnection(hostname, port, ProtocolVersion.TLSv10);
	    }

	    HttpContext ctx = new BasicHttpContext();
	    HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
	    // prepare request
	    BasicHttpEntityEnclosingRequest req = new BasicHttpEntityEnclosingRequest("POST", resource);
	    req.setParams(conn.getParams());
	    HttpRequestHelper.setDefaultHeader(req, endpoint);
	    ContentType reqContentType = ContentType.create("application/soap+xml", "UTF-8");
	    HttpUtils.dumpHttpRequest(logger, "before adding content", req);
	    String reqMsgStr = createSOAPRequest(msg, header != null ? header.getDocumentElement() : null);

	    StringEntity reqMsg = new StringEntity(reqMsgStr, reqContentType);
	    req.setEntity(reqMsg);
	    req.setHeader(reqMsg.getContentType());
	    req.setHeader("Content-Length", Long.toString(reqMsg.getContentLength()));
	    // send request and receive response
	    HttpResponse response = httpexecutor.execute(req, conn, ctx);
	    int statusCode = response.getStatusLine().getStatusCode();
	    conn.receiveResponseEntity(response);
	    HttpEntity entity = response.getEntity();
	    byte[] entityData = FileUtils.toByteArray(entity.getContent());
	    HttpUtils.dumpHttpResponse(logger, response, entityData);
	    checkHTTPStatusCode(msg, statusCode);
	    // consume entity
	    Object requestObj = processSOAPResponse(new ByteArrayInputStream(entityData));

	    return requestObj;
	} catch (HttpException ex) {
	    throw new SOAPException("Failed to deliver or receive PAOS HTTP message.", ex);
	} catch (IOException ex) {
	    throw new SOAPException(ex);
	} catch (URISyntaxException ex) {
	    throw new SOAPException("Hostname or port of the remote server are invalid.", ex);
	} catch (MarshallingTypeException ex) {
	    throw new DispatcherException("Failed to marshal JAXB object.", ex);
	} catch (TransformerException ex) {
	    throw new DispatcherException(ex);
	}
    }

    private StreamHttpClientConnection createTlsConnection(String hostname, int port, ProtocolVersion tlsVersion)
	    throws IOException, URISyntaxException {

	Socket socket = ProxySettings.getDefault().getSocket(hostname, port);
	tlsClient.setClientVersion(tlsVersion);
	InputStream sockIn = socket.getInputStream();
	OutputStream sockOut = socket.getOutputStream();
	TlsClientProtocol handler = new TlsClientProtocol(sockIn, sockOut);
	try {
	    handler.connect(tlsClient);
	} catch (IOException io) {
	    handler.close();
	    throw io;
	}
	StreamHttpClientConnection conn = new StreamHttpClientConnection(handler.getInputStream(), handler.getOutputStream());

	return conn;
    }

    /**
     * Check the status code returned from the server. 
     * If the status code indicates an error, a PAOSException will be thrown.
     * 
     * @param msg The last message we sent to the server
     * @param statusCode The status code we received from the server
     * @throws SOAPException If the server returned a HTTP error code
     */
    private void checkHTTPStatusCode(Object msg, int statusCode) throws SOAPException {
	if (statusCode < 200 || statusCode > 299) {
	    if (msg instanceof ResponseType) {
		ResponseType resp = (ResponseType) msg;
		try {
		    WSHelper.checkResult(resp);
		} catch (WSException ex) {
		    throw new SOAPException("Received HTML Error Code " + statusCode, ex);
		}
	    }
	    throw new SOAPException("Received HTML Error Code " + statusCode);
	}
    }

}
