/*******************************************************************************
 * Copyright (c) 2010 - 2011 webuzz.im
 *
 * Author:
 *   Zhou Renjian / zhourenjian@gmail.com - initial API and implementation
 *******************************************************************************/

package im.webuzz.piled;

import im.webuzz.threadpool.ChainedThreadPoolExecutor;
import im.webuzz.threadpool.ThreadPoolExecutorConfig;

/**
 * HTTP KeepAlive monitor, HTTP connection monitor and hot deployment monitor.
 * 
 * Send out a heart beat to Piled server every 10 seconds, and Piled
 * server will test all existed keep alive connections whether it is
 * expired or not.
 * 
 * Send signals to server to clean expired or hanged connections. And re-initialize
 * configuration if there are updates.
 * 
 * @author zhourenjian
 *
 */
class SSLServerMonitor implements Runnable {

	private PiledAbstractServer server;
	
	public SSLServerMonitor(PiledAbstractServer server) {
		super();
		this.server = server;
	}

	@Override
	public void run() {
		int count = 0;
		ThreadPoolExecutorConfig lastWorkerConfig = PiledSSLConfig.sslWorkerPool;
		if (lastWorkerConfig == null) {
			lastWorkerConfig = new ThreadPoolExecutorConfig();
		}
		ThreadPoolExecutorConfig lastEngineConfig = PiledSSLConfig.sslEnginePool;
		if (lastEngineConfig == null) {
			lastEngineConfig = new ThreadPoolExecutorConfig();
		}
		while (server.isRunning()) {
			for (int i = 0; i < 5; i++) {
				try {
					Thread.sleep(2000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				if (!server.isRunning()) {
					break;
				}
			}

			ThreadPoolExecutorConfig wc = PiledSSLConfig.sslWorkerPool;
			// Keep-Alive monitor
			for (HttpWorker worker : server.workers) {
				synchronized (worker.queue) {
					/**
					 * @see HttpWorker#run
					 */
					worker.queue.add(new ServerDataEvent(null, null, 0));
					worker.queue.notify();
				}
				if (wc != null) {
					wc.updatePoolWithComparison(worker.workerPool, lastWorkerConfig);
				}
			}
			if (wc != null) {
				lastWorkerConfig = wc;
			}
			
			ThreadPoolExecutorConfig ec = PiledSSLConfig.sslEnginePool;
			if (ec != null && server instanceof PiledSSLServer) {
				PiledSSLServer sslServer = (PiledSSLServer) server;
				ChainedThreadPoolExecutor[] enginePools = sslServer.enginePools;
				if (enginePools != null) {
					for (ChainedThreadPoolExecutor pool : enginePools) {
						if (pool != null) {
							ec.updatePoolWithComparison(pool, lastEngineConfig);
						}
					}
				}
				lastEngineConfig = ec;
			}

			count++;
			if (count % 6 == 5) { // Every 60s
				// Connection monitor
				server.send(null, null, 0, -1); // clean expired or hanged connections
				
				// Hot deployment
				server.initializeWrapperInstances();
				server.initializeFilterInstances();
				server.initializePiletInstances();
			}
		} // end of while
	}
	
}
