package im.webuzz.piled;

import java.util.Arrays;
import java.util.Properties;

import im.webuzz.threadpool.ThreadPoolExecutorConfig;

public class PiledSSLConfig {

	/**
	 * SSL server listening address. Server can be set to listen on given IP or all IPs.
	 * By default no specific address is given, server will listen on all IPs.
	 */
	public static String sslAddress = null;
	/**
	 * SSL server port. If not set, SSL server will not be run.
	 */
	public static int sslPort = -1; // disabled!
	/**
	 * Need a SSL key store to run SSL server.
	 */
	public static String sslKeyStore;
	/**
	 * Password for SSL key store.
	 */
	public static String sslPassword;
	
	public static boolean sslSupportSNI = true;
	
	public static String sslDefaultHost = null;
	
	public static String[] sslProtocols = new String[] {
		"TLSv1.3",
		"TLSv1.2",
		"TLSv1.1",
		"TLSv1",
		//"SSLv2Hello",
		//"SSLv3"
	};
	
	public static boolean sslPreferServerCiphersOrder = true;
	// From Java 1.8
	// grep -v SSL_ ~/ciphers18.txt | grep -v "_DH_" | grep -v "_DHE_" | grep -v "_RC4_" | grep -v "_NULL_" | grep -v "_anon_" | grep -v "_EMPTY_" | grep -v "_KRB5_" | grep -v "_DSS_" | awk '{printf "\"%s\",\r\n", $1}'
	public static String[] sslCipherSuites = new String[] {
		/*
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		//*/
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
			"TLS_RSA_WITH_AES_256_CBC_SHA256",
			"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
			"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	};
	public static int sslSessionCacheSize = 10000;
	public static int sslSessionTimeout = 3600;
	
	private static String[] sslCurrentProtocols = sslProtocols;
	private static String[] sslCurrentCipherSuites = sslCipherSuites;
	
	//public static boolean sslSessionCreation = true;
	
	public static boolean sslExceptionLogging = false;
	
	/**
	 * Each worker work on a CPU die. It should be less than the total dies
	 * of the server's CPU.
	 *  1+ : Set exactly specified workers
	 *  0  : Use system CPU cores
	 * -1  : System CPU cores number - this number's absolute value
	 * -2  : Same value of {@link PiledConfig#httpWorkers}
	 */
	public static int sslWorkers = -2;

	public static ThreadPoolExecutorConfig sslWorkerPool = new ThreadPoolExecutorConfig();
	public static ThreadPoolExecutorConfig sslEnginePool = new ThreadPoolExecutorConfig();
	
	static {
		sslWorkerPool.coreThreads = 20;
		sslWorkerPool.maxThreads = 128;
		sslWorkerPool.idleThreads = 10;
		sslWorkerPool.threadIdleSeconds = 60L;
		sslWorkerPool.queueTasks = 100;
		sslWorkerPool.threadTimeout = false;
		
		sslEnginePool.coreThreads = 20;
		sslEnginePool.maxThreads = 32;
		sslEnginePool.idleThreads = 10;
		sslEnginePool.threadIdleSeconds = 60L;
		sslEnginePool.queueTasks = 1000; //Integer.MAX_VALUE; // by default, no queue limit
		sslEnginePool.threadTimeout = false;
	}

	public static void update(Properties prop) {
		/**
		 * Reload SSL context in case of certificates get updated.
		 */
		String keyStore = PiledSSLConfig.sslKeyStore;
		String activeKeyStore = PiledSSLConnector.activeSSLKeyStore;
		if (keyStore != null && keyStore.length() > 0
				&& activeKeyStore != null && activeKeyStore.length() > 0
				&& !keyStore.equals(activeKeyStore)) {
			//PiledSSLConnector.sslContext = null; // SSLContext will be re-initialized later
			PiledSSLConnector.initializeSSLContext(); // re-initialize SSLContext
		}
		
		if (!Arrays.equals(sslCurrentProtocols, sslProtocols)) {
			PiledSSLConnector.enabledProtocols = null; // recalculate protcols
			sslCurrentProtocols = sslProtocols;
		}
		if (!Arrays.equals(sslCurrentCipherSuites, sslCipherSuites)) {
			PiledSSLConnector.enabledCiphers = null; // recalculate ciphers
			sslCurrentCipherSuites = sslCipherSuites;
		}
	}

}
