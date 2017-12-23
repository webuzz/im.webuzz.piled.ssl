package im.webuzz.piled;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;

public class SNIKeyManager extends X509ExtendedKeyManager {

	private final X509ExtendedKeyManager keyManager;

	public SNIKeyManager(X509ExtendedKeyManager keyManager) {
		this.keyManager = keyManager;
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
		ExtendedSSLSession session = (ExtendedSSLSession) engine.getHandshakeSession();
		for (SNIServerName name : session.getRequestedServerNames()) {
			if (name.getType() == StandardConstants.SNI_HOST_NAME) {
				String hostname = ((SNIHostName) name).getAsciiName();
				if (hostname != null && keyManager.getCertificateChain(hostname) != null
						&& keyManager.getPrivateKey(hostname) != null) {
					return hostname;
				}
				break;
			}
		}
		return keyManager.chooseEngineServerAlias(keyType, issuers, engine);
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return keyManager.getServerAliases(keyType, issuers);
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return keyManager.getCertificateChain(alias);
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return keyManager.getPrivateKey(alias);
	}

}
