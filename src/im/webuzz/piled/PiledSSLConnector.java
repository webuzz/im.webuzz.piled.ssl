/*******************************************************************************
 * Copyright (c) 2010 - 2011 webuzz.im
 *
 * Author:
 *   Zhou Renjian / zhourenjian@gmail.com - initial API and implementation
 *******************************************************************************/

package im.webuzz.piled;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

public class PiledSSLConnector {
	public SSLEngine engine;
	public ByteBuffer outNetBuffer;
	public ByteBuffer inAppBuffer;
	public ByteBuffer inNetBuffer;

	public SocketChannel socket;
	private PiledSSLServer server;

	public int bufferSize;
	
	public boolean handshook;
	
	private boolean closed;

	static String activeSSLKeyStore;
	
	static SSLContext sslContext;

	static String[] enabledProtocols;
	
	static String[] enabledCiphers;

	PiledSSLConnector() {
	}
	
	public PiledSSLConnector(PiledSSLServer server, SocketChannel socketChannel) {
		this.server = server;
		this.socket = socketChannel;
		this.closed = false;
		
		startSSL();
	}

	public void startSSL() {
		startSSL(false);
	}
	
	void startSSL(boolean verbose) {
		SSLContext context = sslContext;
		if (context == null) {
			context = initializeSSLContext();
			if (context == null) {
				if (verbose) System.out.println("Failed to initialize SSL context!");
				return; // error!
			}
		}
		engine = context.createSSLEngine();
		engine.setUseClientMode(false);
		engine.setNeedClientAuth(false);
		if (enabledProtocols != null) {
			engine.setEnabledProtocols(enabledProtocols);
		} else {
			String[] protocols = engine.getSupportedProtocols();
			if (verbose) System.out.println("SSL engine supported protocols:");
			if (protocols != null && protocols.length > 0) {
				String[] ps = PiledSSLConfig.sslProtocols;
				if (ps != null && ps.length > 0) {
					List<String> matchedProtocols = new ArrayList<String>(ps.length);
					for (String p : ps) {
						if (p == null) continue;
						for (String protocol : protocols) {
							if (p.equals(protocol)) {
								matchedProtocols.add(protocol);
								if (verbose) System.out.println(protocol + " [Enabled]");
								break;
							}
						}
					}
					int size = matchedProtocols.size();
					if (size > 0) {
						enabledProtocols = matchedProtocols.toArray(new String[size]);
						engine.setEnabledProtocols(enabledProtocols);
					}
					if (verbose) {
						for (String protocol : protocols) {
							if (matchedProtocols.contains(protocol)) continue;
							System.out.println(protocol + " [Skipped]");
						}						
					}
				}
			}
		}
		if (enabledCiphers != null) {
			engine.setEnabledCipherSuites(enabledCiphers);
		} else {
			String[] ciphers = engine.getSupportedCipherSuites();
			if (verbose) System.out.println("SSL engine supported cipher suites:");
			if (ciphers != null && ciphers.length > 0) {
				String[] cs = PiledSSLConfig.sslCipherSuites;
				if (cs != null && cs.length > 0) {
					List<String> matchedCiphers = new ArrayList<String>(cs.length);
					for (String c : cs) {
						if (c == null) continue;
						for (String cipher : ciphers) {
							if (c.equals(cipher)) {
								matchedCiphers.add(cipher);
								if (verbose) System.out.println(cipher + " [Enabled]");
								break;
							}
						}
					}
					int size = matchedCiphers.size();
					if (size > 0) {
						enabledCiphers = matchedCiphers.toArray(new String[size]);
						engine.setEnabledCipherSuites(enabledCiphers);
					}
					if (verbose) {
						for (String cipher : ciphers) {
							if (matchedCiphers.contains(cipher)) continue;
							System.out.println(cipher + " [Skipped]");
						}						
					}
				}
			}
		}
		//engine.setEnabledProtocols(PiledConfig.sslProtocols);
		//engine.setEnabledCipherSuites(PiledConfig.sslCipherSuites);
		// Setting to session creation to false will disable SSL.
		//engine.setEnableSessionCreation(PiledSSLConfig.sslSessionCreation);

		this.closed = false;
		
//		this.outNetBuffer = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
//		this.inNetBuffer = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
//		this.inAppBuffer = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());

		this.outNetBuffer = null;
		this.inNetBuffer = null;
		this.inAppBuffer = null;
		this.bufferSize = Math.max(engine.getSession().getPacketBufferSize(), engine.getSession().getApplicationBufferSize());

		this.handshook = false;

		try {
			engine.beginHandshake();
		} catch (SSLException e) {
			e.printStackTrace();
		}
	}

	public static SSLContext initializeSSLContext() {
		// Also reset cached protocols and ciphers
		enabledProtocols = null;
		enabledCiphers = null;
		
		try {
			String keyStore = PiledSSLConfig.sslKeyStore;
			SSLContext context = createSSLContext(false, keyStore, PiledSSLConfig.sslPassword);
			activeSSLKeyStore = keyStore;
			sslContext = context;
			return context;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static SSLContext createSSLContext(
			boolean clientMode, 
			String keystore, 
			String password) throws Exception {
		if (keystore == null) return null;
		// Create/initialize the SSLContext with key material
		char[] passphrase = password != null ? password.toCharArray() : null;
		// First initialize the key and trust material.
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(keystore);
		ks.load(fis, passphrase);
		SSLContext sslContext = SSLContext.getInstance("TLS");
		
		if (clientMode) {
			// TrustManager's decide whether to allow connections.
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ks);
			sslContext.init(null, tmf.getTrustManagers(), null);
		} else {
			// KeyManager's decide which key material to use.
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, passphrase);
			X509ExtendedKeyManager x509KeyManager = null;
			if (PiledSSLConfig.sslSupportSNI) {
				for (KeyManager keyManager : kmf.getKeyManagers()) {
					if (keyManager instanceof X509ExtendedKeyManager) {
						x509KeyManager = (X509ExtendedKeyManager) keyManager;
					}
				}
			}
			if (x509KeyManager == null) {
				sslContext.init(kmf.getKeyManagers(), null, null);
			} else {
				sslContext.init(new KeyManager[] { new SNIKeyManager(x509KeyManager) }, null, null);
			}
		}
		fis.close();
		return sslContext;
	}

	public void close() {
		this.close(false);
	}
	
	public void close(boolean remoteClosing) {
		if (closed) {
			return;
		}
		closed = true;
		if (engine != null) {
			engine.closeOutbound();
//			try {
//				engine.closeInbound();
//			} catch (SSLException e) {
//				e.printStackTrace();
//			}
//			engine = null;
			if (!remoteClosing && !engine.isOutboundDone()) {
				server.writeSSLDummyPacket(this, socket);
			}
			// JDK 1.6 SSLSession memory leak. https://bugs.openjdk.java.net/browse/JDK-6386530
			// In JDK 1.6.0_u45, it is not fixed.
			// Fixing tips: https://projects.tigase.org/issues/1395
			SSLSession session = engine.getSession();
			if (session != null) {
				session.invalidate();
			}
		}
		if (socket != null) {
			SelectionKey key = socket.keyFor(server.selector);
			if (key != null) {
				key.cancel();
			}
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
}
