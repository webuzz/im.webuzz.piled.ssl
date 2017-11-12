/*******************************************************************************
 * Copyright (c) 2010 - 2011 webuzz.im
 *
 * Author:
 *   Zhou Renjian / zhourenjian@gmail.com - initial API and implementation
 *******************************************************************************/

package im.webuzz.piled;

//import im.webuzz.config.Config;
import im.webuzz.pilet.HttpConfig;
import im.webuzz.pilet.HttpLoggingConfig;
import im.webuzz.pilet.MIMEConfig;
import im.webuzz.threadpool.ChainedThreadPoolExecutor;
import im.webuzz.threadpool.SimpleNamedThreadFactory;
import im.webuzz.threadpool.SimpleThreadPoolExecutor;
import im.webuzz.threadpool.ThreadPoolExecutorConfig;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

public class PiledSSLServer extends PiledAbstractServer {
	// An empty buffer used as the source buffer for wrap() operations during
	// SSL handshakes.
	private static ByteBuffer BLANK = ByteBuffer.allocate(0);

	Map<SocketChannel, PiledSSLConnector> sessionMap = new ConcurrentHashMap<SocketChannel, PiledSSLConnector>();
	
	ChainedThreadPoolExecutor[] enginePools;

	static PiledSSLServer singleton;
	
	public PiledSSLServer(InetAddress hostAddress, int port, HttpWorker[] workers) {
		super(hostAddress, port, true, workers);
	}
	
	@Override
	protected void bindWorkers(HttpWorker[] workers) {
		this.workers = workers;
		if (this.workers != null) {
			ThreadPoolExecutorConfig wc = PiledSSLConfig.sslWorkerPool;
			if (wc == null) {
				wc = new ThreadPoolExecutorConfig();
			}
			ThreadPoolExecutorConfig ec = PiledSSLConfig.sslEnginePool;
			if (ec == null) {
				ec = new ThreadPoolExecutorConfig();
				ec.workerName = "HTTPS Engine";
			}
			int count = workers.length;
			enginePools = new ChainedThreadPoolExecutor[count];
			for (int i = 0; i < count; i++) {
				enginePools[i] = new ChainedThreadPoolExecutor(ec,
						new SimpleNamedThreadFactory("HTTPS Engine Worker" + (count == 1 ? "" : "-" + (i + 1))) {
							@Override
							public void updatePrefix(String prefix) {
								if (namePrefix != null) return;
								super.updatePrefix(prefix);
							}
						});
				enginePools[i].allowCoreThreadTimeOut(ec.threadTimeout);
				SimpleThreadPoolExecutor executor = new SimpleThreadPoolExecutor(wc,
						new SimpleNamedThreadFactory("HTTPS Service Worker" + (count == 1 ? "" : "-" + (i + 1))) {
							@Override
							public void updatePrefix(String prefix) {
								if (namePrefix != null) return;
								super.updatePrefix(prefix);
							}
						});
				executor.allowCoreThreadTimeOut(wc.threadTimeout);
				this.workers[i].bindingServer(this, executor);
			}
		}
	}
	
	public void init() throws IOException {
		super.init();
		this.pendingData = new ConcurrentHashMap<SocketChannel, List<ByteBuffer>>(); // supports multiple threads
	}

	@Override
	public void runLoop() throws IOException {
		super.runLoop();
		if (enginePools != null) {
			for (int i = 0; i < enginePools.length; i++) {
				ChainedThreadPoolExecutor pool = enginePools[i];
				if (pool != null) {
					pool.shutdown();
				}
			}
		}
	}
	
	protected void accept(SelectionKey key) throws IOException {
		// For an accept to be pending the channel must be a server socket channel.
		ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
		if (serverSocketChannel == null) {
			return;
		}

		// Accept the connection and make it non-blocking
		SocketChannel socketChannel = serverSocketChannel.accept();
		if (socketChannel == null) {
			return;
		}
		Socket socket = socketChannel.socket();
		if (socket == null) {
			return;
		}
		socket.setTcpNoDelay(true);
		socketChannel.configureBlocking(false);

		PiledSSLConnector piledSSLConnector = new PiledSSLConnector(this, socketChannel);
		// Finally, wake up our selecting thread so it can make the required changes
		this.sessionMap.put(socketChannel, piledSSLConnector);

		// Register the new SocketChannel with our Selector, indicating
		// we'd like to be notified when there's data waiting to be read
		socketChannel.register(this.selector, SelectionKey.OP_READ, new Long(System.currentTimeMillis()));
	}

	protected void read(final SelectionKey key) throws IOException {
		final SocketChannel socketChannel = (SocketChannel) key.channel();
		key.interestOps(0); // Do not call until following task is run, in which will invoke key#interestOps
		int index = 0;
		if (socketChannel != null) {
			index = socketChannel.hashCode() % enginePools.length;
		}
		// Even though key.interestOps(0) is invoked, other threads (e.g. application write)
		// may push change request to invoke key#interestOps to change ops.
		// Chained thread pool must be used.
		enginePools[index].execute(socketChannel, new Runnable() {
			
			@Override
			public void run() {
				try {
					safeRun();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			
			public void safeRun() {
				if (!socketChannel.isOpen()) {
					return;
				}
				boolean gotData = false;
				PiledSSLConnector sessionMetadata = (PiledSSLConnector) sessionMap.get(socketChannel);
				int hsResult = checkSSLHandshake(sessionMetadata, key, socketChannel, SelectionKey.OP_READ);
				if (hsResult == -1) { // error or closed
					return; // closed!
				} else if (hsResult == 0) {
					pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_READ));
					key.selector().wakeup();
					return;
				} else if (hsResult == 2) { // For OP_READ, we will make sure data is ready
					gotData = true;
					// continue ...
				} // else continue ...
				
				if (sessionMetadata.inNetBuffer == null) {
					sessionMetadata.inNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
				}
				ByteBuffer inNetBuffer = sessionMetadata.inNetBuffer;
				if (!gotData/* && !inNetBuffer.hasRemaining()*/) {
					int numRead = -1;
					try {
						numRead = socketChannel.read(inNetBuffer);
					} catch (IOException e) {
						if (PiledSSLConfig.sslExceptionLogging) {
							e.printStackTrace();
						} else {
							String message = e.getMessage();
							if (message.indexOf("Connection reset by peer") == -1
									&& message.indexOf("Connection timed out") == -1
									&& message.indexOf("Broken pipe") == -1
									&& message.indexOf("closed by the remote host") == -1
									&& message.indexOf("connection was aborted") == -1
									&& message.indexOf("No route to host") == -1) {
								e.printStackTrace();
							}
						}
						numRead = -1;
					}
			
					if (numRead == -1) {
						// Remote entity shut the socket down cleanly. Do the
						// same from our end and cancel the channel.
						closeChannel(key, socketChannel, true, true);
						return;
					}
					if (numRead == 0) {
						interestNext(key, socketChannel);
						return;
					}
				}
				
				inNetBuffer.flip();
				if (sessionMetadata.inAppBuffer == null) {
					sessionMetadata.inAppBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
				}
				ByteBuffer inAppBuffer = sessionMetadata.inAppBuffer;
				boolean processed = false;
				while (inNetBuffer.hasRemaining()) {
					if (sessionMetadata.engine == null) {
						new IOException("SSL Engine being null?").printStackTrace();
						closeChannel(key, socketChannel, true, true);
						return;
					}
					SSLEngineResult result = null;
					try {
						result = sessionMetadata.engine.unwrap(inNetBuffer, inAppBuffer);
					} catch (SSLException e) {
						e.printStackTrace();
						closeChannel(key, socketChannel, true, true);
						return;
					}
					inAppBuffer.flip();
					if (inAppBuffer.hasRemaining()) {
						workers[socketChannel.hashCode() % workers.length].processData(socketChannel, inAppBuffer.array(),
								inAppBuffer.arrayOffset(), inAppBuffer.remaining());
						processed = true;
					}
					inAppBuffer.clear();
					if (result != null) {
						Status rsStatus = result.getStatus();
						if (rsStatus == Status.BUFFER_UNDERFLOW) {
							break;
						} else if (rsStatus == Status.CLOSED) {
							closeChannel(key, socketChannel, true, true);
							return;
						}
					}
				}
				if (!processed) {
					inAppBuffer.flip();
					if (inAppBuffer.hasRemaining()) {
						workers[socketChannel.hashCode() % workers.length].processData(socketChannel, inAppBuffer.array(),
								inAppBuffer.arrayOffset(), inAppBuffer.remaining());
					}
					inAppBuffer.clear();
				}
				
				// Compact our read buffer after we've handled the data instead of before
				// we read so that during the SSL handshake we can deal with the BUFFER_UNDERFLOW
				// case by simple waiting for more data (which will be appended into this buffer).
				if (inNetBuffer.hasRemaining()) {
					inNetBuffer.compact();
				} else {
					//inNetBuffer.clear();
					if (sessionMetadata.inNetBuffer == inNetBuffer) {
						sessionMetadata.inNetBuffer = null;
					}
					ByteBufferPool.putByteBufferToPool(inNetBuffer);
				}
				interestNext(key, socketChannel);
			}
			
		});
	}

	private void interestNext(SelectionKey key, SocketChannel socketChannel) {
		List<ByteBuffer> queue = (List<ByteBuffer>) this.pendingData.get(socketChannel);
		boolean interestedInWriting = queue != null && !queue.isEmpty();
		/*
		if (interestedInWriting) {
			// Register an interest in writing on this channel
			key.interestOps(SelectionKey.OP_WRITE);
		} else {
			key.interestOps(SelectionKey.OP_READ);
		}
		// */
		pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS,
				interestedInWriting ? SelectionKey.OP_WRITE : SelectionKey.OP_READ));
		key.selector().wakeup();
	}
	
	@Override
	protected void closeExtraResource(SocketChannel socketChannel, boolean notifyClosing) {
		PiledSSLConnector sessionMetadata = sessionMap.get(socketChannel);
		if (sessionMetadata != null) {
			sessionMetadata.close(notifyClosing);
			sessionMap.remove(socketChannel);
			
			if (sessionMetadata.inAppBuffer != null) {
				ByteBufferPool.putByteBufferToPool(sessionMetadata.inAppBuffer);
				sessionMetadata.inAppBuffer = null;
			}
			if (sessionMetadata.inNetBuffer != null) {
				ByteBufferPool.putByteBufferToPool(sessionMetadata.inNetBuffer);
				sessionMetadata.inNetBuffer = null;
			}
			if (sessionMetadata.outNetBuffer != null) {
				ByteBufferPool.putByteBufferToPool(sessionMetadata.outNetBuffer);
				sessionMetadata.outNetBuffer = null;
			}
		}
	}

	/*
	 * Return SSL handshake checking result.
	 * -1: Error
	 * 0: Still need handshakes
	 * 1: Need no handshakes
	 * 2: Handshake finished, continue following operations
	 */
	private int checkSSLHandshake(PiledSSLConnector sessionMetadata, SelectionKey key, SocketChannel socketChannel,
			int inOperation) {
		if (sessionMetadata == null || sessionMetadata.engine == null) {
			closeChannel(key, socketChannel, false, true);
			return -1;
		}
		boolean handshaking = !sessionMetadata.handshook;
		if (handshaking) {
			HandshakeStatus hsStatus = sessionMetadata.engine.getHandshakeStatus();
			handshaking = (hsStatus != HandshakeStatus.NOT_HANDSHAKING && hsStatus != HandshakeStatus.FINISHED);
			if (!handshaking) {
				sessionMetadata.handshook = true;
			}
		}
		if (handshaking) {
			try {
				if (this.progressSSLHandshake(sessionMetadata, key, socketChannel, inOperation)) {
					return 2; // just finished handshake, continue
				} else {
					return 0; // still need handshake
				}
			} catch (IOException e) {
				if (PiledSSLConfig.sslExceptionLogging) e.printStackTrace(); // or be quiet for remote handshake exceptions
				closeChannel(key, socketChannel, true, true);
				return -1;
			}
		}
		return 1; // need no handshake
	}
	
	protected void write(final SelectionKey key) throws IOException {
		final SocketChannel socketChannel = (SocketChannel) key.channel();
		key.interestOps(0); // Do not call until following task is run, in which will invoke key#interestOps
		int index = 0;
		if (socketChannel != null) {
			index = socketChannel.hashCode() % enginePools.length;
		}
		// Even though key.interestOps(0) is invoked, other threads (e.g. application write)
		// may push change request to invoke key#interestOps to change ops.
		// Chained thread pool must be used.
		enginePools[index].execute(socketChannel, new Runnable() {
			
			@Override
			public void run() {
				try {
					safeRun();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			
			public void safeRun() {
				if (!socketChannel.isOpen()) {
					return;
				}
				
				PiledSSLConnector sessionMetadata = (PiledSSLConnector) sessionMap.get(socketChannel);
				int hsResult = checkSSLHandshake(sessionMetadata, key, socketChannel, SelectionKey.OP_WRITE);
				if (hsResult == -1) { // error or closed
					return; // closed
				} else if (hsResult == 0) { // still need handshakes
					pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_READ));
					key.selector().wakeup();
					return;
				}
				List<ByteBuffer> queue = (List<ByteBuffer>) pendingData.get(socketChannel);
				if (queue == null) {
					closeChannel(key, socketChannel, false, true);
					return;
				}
				int totalSent = 0;
				while (!queue.isEmpty()) {
					ByteBuffer buf = (ByteBuffer) queue.get(0);
					if (buf.capacity() == 0) {
						pendingData.remove(socketChannel);
						queue.remove(0);
						//if (sessionMetadata.outNetBuffer != null) {
						//	ByteBufferPool.putByteBufferToPool(sessionMetadata.outNetBuffer);
						//	sessionMetadata.outNetBuffer = null;
						//}
						if (totalSent > 0) {
							// notify data written, negative value means all queued data written
							workers[socketChannel.hashCode() % workers.length].processData(socketChannel, null, 0, -totalSent);
						}
						closeChannel(key, socketChannel, false, true);
						return;
					}
					
					// queue not empty with at least one buffer
					ByteBuffer outNetBuffer = sessionMetadata.outNetBuffer;
					
					do {
						if (outNetBuffer == null && buf.hasRemaining()) { // not partly sent
							if (sessionMetadata.outNetBuffer == null) {
								sessionMetadata.outNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
							}
							outNetBuffer = sessionMetadata.outNetBuffer;
							try {
								//sessionMetadata.engine.wrap(buf, outNetBuffer);
								SSLEngineResult result = sessionMetadata.engine.wrap(buf, outNetBuffer);
								outNetBuffer.flip();
								if (!outNetBuffer.hasRemaining()) { // outNetBuffer contains no bytes
									System.out.println("SSL Error: Empty outNetBuffer " + buf.remaining() + " ? " + buf.hasRemaining());
									if (result != null) {
										Status status = result.getStatus();
										if (status == Status.BUFFER_OVERFLOW) {
											System.out.println("SSL Error: Overflow " + buf.remaining());
										} else if (status == Status.BUFFER_UNDERFLOW) {
											System.out.println("SSL Error: Underflow " + buf.remaining());
										} else if (status == Status.CLOSED) {
											System.out.println("SSL Error: Close Status = " + status.ordinal());
										} else {
											System.out.println("SSL Error: Status = " + status.ordinal());
										}
									}
									if (!buf.hasRemaining()) {
										break;
									}
									if (sessionMetadata.outNetBuffer == outNetBuffer) {
										sessionMetadata.outNetBuffer = null;
									}
									ByteBufferPool.putByteBufferToPool(outNetBuffer);
									closeChannel(key, socketChannel, true, true);
									return;
								}
							} catch (SSLException e) {
								// Internal server error!
								e.printStackTrace();
								// Put outNetBuffer back to pool
								if (sessionMetadata.outNetBuffer == outNetBuffer) {
									sessionMetadata.outNetBuffer = null;
								}
								ByteBufferPool.putByteBufferToPool(outNetBuffer);
								closeChannel(key, socketChannel, true, true);
								return;
							}
						} else {
							outNetBuffer = sessionMetadata.outNetBuffer; // should always be not null!
						}
						
						int numWritten = -1;
						try {
							numWritten = socketChannel.write(outNetBuffer);
						} catch (Throwable e) {
							String message = e.getMessage();
							if (message != null && message.indexOf("Connection reset by peer") == -1
									&& message.indexOf("Broken pipe") == -1
									&& message.indexOf("connection was forcibly closed") == -1) {
								e.printStackTrace();
							}
							numWritten = -1;
						}
						//System.out.println("Written " + numWritten);
						
						if (numWritten < 0) {
							// Put outNetBuffer back to pool
							if (sessionMetadata.outNetBuffer == outNetBuffer) {
								sessionMetadata.outNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(outNetBuffer);
							closeChannel(key, socketChannel, true, true);
							return;
						}
						
						if (numWritten == 0 || outNetBuffer.hasRemaining()) { // partly sent
							if (totalSent > 0) {
								workers[socketChannel.hashCode() % workers.length].processData(socketChannel, null, 0, totalSent);
							}
							//key.interestOps(SelectionKey.OP_WRITE);
							pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_WRITE));
							key.selector().wakeup();
							return;
						}
						outNetBuffer.clear();
						if (buf.hasRemaining()) {
							outNetBuffer = null;
						}
					} while (buf.hasRemaining());
					
					/*
					if (buf.hasRemaining()) {
						// schedule write operation for next time
						// try to write all data in the buffer may cause freezing,
						// or may freeze other connections
						//key.interestOps(SelectionKey.OP_WRITE);
						pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_WRITE));
						key.selector().wakeup();
						return;
					}
					// */
					
					//outNetBuffer.clear();
					if (sessionMetadata.outNetBuffer == outNetBuffer) {
						sessionMetadata.outNetBuffer = null;
					}
					ByteBufferPool.putByteBufferToPool(outNetBuffer);
					
					int sent = buf.limit();
					if (!queue.isEmpty()) {
						queue.remove(0); // always removing from head, thread safe
					}
					totalSent += sent;
				} // end of while queue
				
				if (totalSent > 0) {
					workers[socketChannel.hashCode() % workers.length].processData(socketChannel, null, 0, -totalSent);
					// notify data written, negative value means all queued data written
				}
				//key.interestOps(interestingWriting ? SelectionKey.OP_WRITE : SelectionKey.OP_READ);
				pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_READ));
				key.selector().wakeup();
			}
			
		});
	}	

	/*
	 * Return whether SSL handshake is finished and next operation should be performed.
	 */
	private boolean progressSSLHandshake(PiledSSLConnector sessionMetadata, SelectionKey key, SocketChannel socketChannel,
			int inOperation) throws IOException {
		SSLEngine engine = sessionMetadata.engine;
		Runnable task;
		//SSLEngineResult result;
		while (true) {
			switch (engine.getHandshakeStatus()) {
			case FINISHED:
			case NOT_HANDSHAKING:
				sessionMetadata.handshook = true;
				if (inOperation == SelectionKey.OP_WRITE) {
					return true;
				} else {
					interestNext(key, socketChannel);
					return false;
				}
			case NEED_TASK:
				while ((task = engine.getDelegatedTask()) != null) {
					task.run();
				}
				break;
			case NEED_UNWRAP: {
				// Since the handshake needs an unwrap() and we're only in here because of either
				// a read and a write, we assume(!) we're in here because of a read and that
				// data is available.
				if (sessionMetadata.inNetBuffer == null) {
					sessionMetadata.inNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
				}
				ByteBuffer inNetBuffer = sessionMetadata.inNetBuffer;
				//if (!inNetBuffer.hasRemaining()) {
					int numRead = socketChannel.read(inNetBuffer);
					if (numRead < 0) {
						throw new SSLException("Handshake aborted by remote entity (socket closed)");
					}
				//}
				//int numRead = inNetBuffer.remaining();
				if (numRead == 0 && engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP) {
					// Bail so we go back to blocking the selector
					
					// Since we're in here the channel is already registered for OP_READ.
					// Don't re-queue it since that will needlessly wake up the selecting
					// thread.
					//key.interestOps(SelectionKey.OP_READ);
					pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_READ));
					key.selector().wakeup();
					return false;
				}
				
				inNetBuffer.flip();
				ByteBuffer inAppBuffer = null;
				if (inNetBuffer.hasRemaining()) {
					if (sessionMetadata.inAppBuffer == null) {
						sessionMetadata.inAppBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
					}
					inAppBuffer = sessionMetadata.inAppBuffer;
				}
				
				int unwrapCount = 0;
				while (inNetBuffer.hasRemaining()) {
					SSLEngineResult result = engine.unwrap(inNetBuffer, inAppBuffer);
					unwrapCount++;
					if (unwrapCount > 1000000) {
						Status rsStatus = result.getStatus();
						System.out.println("Handshake status: " + rsStatus.ordinal() + "/" + rsStatus.name() + " " + rsStatus);
						System.out.println("Handshake buffer: " + inNetBuffer.remaining() + " vs " + inAppBuffer.remaining() + " " + inAppBuffer.position());
						HandshakeStatus hsStatus = engine.getHandshakeStatus();
						System.out.println("Engine status: " + hsStatus.ordinal() + "/" + hsStatus.name() + " " + hsStatus);
						throw new SSLException("Handshake unwrap too many times!");
					}

					HandshakeStatus hsStatus = engine.getHandshakeStatus();
					if (hsStatus == HandshakeStatus.NEED_TASK) {
						while ((task = engine.getDelegatedTask()) != null) {
							task.run();
						}
					}
					
					Status rsStatus = result.getStatus();
					if (rsStatus == Status.BUFFER_UNDERFLOW) {
						if (inNetBuffer.hasRemaining()) {
							inNetBuffer.compact();
						} else {
							//inNetBuffer.clear();
							if (sessionMetadata.inNetBuffer == inNetBuffer) {
								sessionMetadata.inNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inNetBuffer);
						}
						//key.interestOps(SelectionKey.OP_READ);
						pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_READ));
						key.selector().wakeup();
						return false;
					} else if (rsStatus != Status.OK) {
						if (rsStatus == Status.CLOSED) {
							throw new SSLException("Handshake closed by remote entity");
						} else if (rsStatus == Status.BUFFER_OVERFLOW) {
							throw new SSLException("Handshake unwrap overflow!");
						} else { // Unkown status
							throw new SSLException("Handshake unwrap unkown error (" + rsStatus.ordinal() + "/" + rsStatus + "!");
						}
					}

					// Status OK
					if (inAppBuffer.position() > 0) { // A handshake already produces data for us to consume.
						if (inNetBuffer.hasRemaining()) {
							inNetBuffer.compact();
						} else {
							//inNetBuffer.clear();
							if (sessionMetadata.inNetBuffer == inNetBuffer) {
								sessionMetadata.inNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inNetBuffer);
						}
						sessionMetadata.handshook = true;
						return true; // continue to read or write data
					}

					if (hsStatus == HandshakeStatus.FINISHED || hsStatus == HandshakeStatus.NOT_HANDSHAKING) {
						if (unwrapCount > 100000) {
							System.out.println("Handshake unwrap takes " + unwrapCount + " to finish");
						}
						if (inNetBuffer.hasRemaining()) {
							inNetBuffer.compact();
							sessionMetadata.handshook = true;
							return true; // continue to read or write data
						} else {
							//inNetBuffer.clear();
							if (sessionMetadata.inNetBuffer == inNetBuffer) {
								sessionMetadata.inNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inNetBuffer);
							if (sessionMetadata.inAppBuffer == inAppBuffer) {
								sessionMetadata.inAppBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inAppBuffer);
							if (inOperation == SelectionKey.OP_WRITE) {
								return true;
							} else {
								interestNext(key, socketChannel);
								return false;
							}
						}
					}

				} // end of while
				//inNetBuffer.clear();
				if (sessionMetadata.inNetBuffer == inNetBuffer) {
					sessionMetadata.inNetBuffer = null;
				}
				ByteBufferPool.putByteBufferToPool(inNetBuffer);
				if (inAppBuffer != null) {
					if (sessionMetadata.inAppBuffer == inAppBuffer) {
						sessionMetadata.inAppBuffer = null;
					}
					ByteBufferPool.putByteBufferToPool(inAppBuffer);
				}
				break; // break switch
			} // end of NEED_UNWRAP
			case NEED_WRAP: {
				// The engine wants to give us data to send to the remote party to advance
				// the handshake. Let it :-)

				if (sessionMetadata.outNetBuffer == null) {
					sessionMetadata.outNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
				}
				ByteBuffer outNetBuffer = sessionMetadata.outNetBuffer;
				if (outNetBuffer.position() == 0) {
					// We have no outstanding data to write for the handshake (from a previous wrap())
					// so ask the engine for more.
					/*result = */engine.wrap(BLANK, outNetBuffer);
					outNetBuffer.flip();
				} // else There's data remaining from the last wrap() call, fall through and try to write it

				// Write the data away
				int numWritten = socketChannel.write(outNetBuffer);
				if (numWritten < 0) {
					throw new SSLException("Handshake aborted by remote entity (socket closed)");
				}

				if (outNetBuffer.hasRemaining()) {
					outNetBuffer.compact();
					//key.interestOps(SelectionKey.OP_WRITE);
					pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_WRITE));
					key.selector().wakeup();
					return false;
				}

				// All the data was written away, clear the buffer out
				//outNetBuffer.clear();
				if (sessionMetadata.outNetBuffer == outNetBuffer) {
					sessionMetadata.outNetBuffer = null;
				}
				ByteBufferPool.putByteBufferToPool(outNetBuffer);
				
				if (engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP) {
					// We need more data (to pass to unwrap(), signal we're interested
					// in reading on the socket
					//key.interestOps(SelectionKey.OP_READ);
					pendingChanges.offer(new ChangeRequest(socketChannel, ChangeRequest.CHANGEOPS, SelectionKey.OP_READ));
					key.selector().wakeup();
					// And return since we have to wait for the socket to become available.
					return false;
				}
				
				// For all other cases fall through so we can check what the next step is.
				// This ensures we handle delegated tasks, and handshake completion neatly.
				break;
			} // end of branch NEED_WRAP
			} // end of switch
//			interestNext(key, socketChannel);
//			return false;
		}
	}
	
	void writeSSLDummyPacket(PiledSSLConnector sessionMetadata, SocketChannel socketChannel) {
		if (sessionMetadata.outNetBuffer == null) {
			sessionMetadata.outNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
		}
		ByteBuffer outNetBuffer = sessionMetadata.outNetBuffer;
		try {
			/*SSLEngineResult res = */sessionMetadata.engine.wrap(BLANK, outNetBuffer);
			outNetBuffer.flip();
			socketChannel.write(outNetBuffer);
		} catch (Throwable e) {
			// Problems with the engine. Probably it is dead. So close 
			// the socket and forget about it. 
			if (socketChannel != null) {
				try {
					socketChannel.close();
				} catch (IOException ex) {
					/* Ignore. */
				}
			}
		}
		if (sessionMetadata.outNetBuffer == outNetBuffer) {
			sessionMetadata.outNetBuffer = null;
		}
		ByteBufferPool.putByteBufferToPool(outNetBuffer);
	}

	@Override
	public void stop() {
		super.stop();
		Thread shutdownThread = new Thread("Stop Server Thread") {
			public void run() {
				try {
					Thread.sleep(20000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				System.exit(0);
			};
		};
		shutdownThread.setDaemon(true);
		shutdownThread.start();
	}

	public static void main(String[] args) {
		/*
		if (args != null && args.length > 0) {
			if (args.length > 1 && "--ssl-details".equals(args[0])) {
				Config.initialize(args[1]);
				Config.registerUpdatingListener(PiledSSLConfig.class);
				new PiledSSLConnector().startSSL(true);
				return;
			}
			Config.initialize(args[0]);
		} else {
			Config.initialize();
		}
		Config.registerUpdatingListener(HttpConfig.class);
		Config.registerUpdatingListener(HttpLoggingConfig.class);
		Config.registerUpdatingListener(MIMEConfig.class);
		Config.registerUpdatingListener(PiledConfig.class);
		Config.registerUpdatingListener(PiledSSLConfig.class);
		// */
		try {
			Class<?> clazz = Class.forName(PiledConfig.configClassName);
			if (clazz != null) {
				Method initMethod = args != null && args.length > 0 ? clazz.getMethod("initialize", String.class) : clazz.getMethod("initialize");
				if (initMethod != null && (initMethod.getModifiers() & Modifier.STATIC) != 0) {
					if (args != null && args.length > 0) {
						if (args.length > 1 && "--ssl-details".equals(args[0])) {
							initMethod.invoke(clazz, args[1]);
						} else {
							initMethod.invoke(clazz, args[0]);
						}
					} else {
						initMethod.invoke(clazz);
					}
				}
				Method registerMethod = clazz.getMethod("registerUpdatingListener", Class.class);
				if (registerMethod != null && (registerMethod.getModifiers() & Modifier.STATIC) != 0) {
					registerMethod.invoke(clazz, HttpConfig.class);
					registerMethod.invoke(clazz, HttpLoggingConfig.class);
					registerMethod.invoke(clazz, MIMEConfig.class);
					registerMethod.invoke(clazz, PiledConfig.class);
					registerMethod.invoke(clazz, PiledSSLConfig.class);
				}
			}
		} catch (ClassNotFoundException e) {
			System.out.println("[WARN]: Class " + PiledConfig.configClassName + " is not found. Server may not be configurable.");
		} catch (Throwable e) {
			e.printStackTrace();
			System.out.println("[WARN]: There are errors. Server may not be configurable.");
		}
		if (args != null && args.length > 1 && "--ssl-details".equals(args[0])) {
			new PiledSSLConnector().startSSL(true);
			return;
		}
	
		int workerCount = PiledSSLConfig.sslWorkers;
		if (workerCount <= -2) {
			workerCount = PiledConfig.httpWorkers;
		}
		if (workerCount <= 0) {
			workerCount = Runtime.getRuntime().availableProcessors() + workerCount;
			if (workerCount <= 0) {
				workerCount = 1;
			}
		}

		runServer(workerCount);
	}

	public static void extraRun(int httpWorkerCount) {
		//Config.registerUpdatingListener(PiledSSLConfig.class);
		try {
			Class<?> clazz = Class.forName(PiledConfig.configClassName);
			if (clazz != null) {
				Method registerMethod = clazz.getMethod("registerUpdatingListener", Class.class);
				if (registerMethod != null && (registerMethod.getModifiers() & Modifier.STATIC) != 0) {
					registerMethod.invoke(clazz, PiledSSLConfig.class);
				}
			}
		} catch (ClassNotFoundException e) {
			System.out.println("[WARN]: Class " + PiledConfig.configClassName + " is not found. PiledSSLConfig may not be configurable.");
		} catch (Throwable e) {
			//e.printStackTrace();
			System.out.println("[WARN]: There are errors. PiledSSLConfig may not be configurable.");
		}
		
		if (PiledSSLConfig.sslPort > 0) {
			int sslWorkerCount = PiledSSLConfig.sslWorkers;
			if (sslWorkerCount <= -2) {
				sslWorkerCount = httpWorkerCount;
			}
			if (sslWorkerCount <= 0) {
				sslWorkerCount = Runtime.getRuntime().availableProcessors() + sslWorkerCount;
				if (sslWorkerCount <= 0) {
					sslWorkerCount = 1;
				}
			}
			final int workerCount = sslWorkerCount;
			Thread sslServerThread = new Thread(new Runnable() {
				@Override
				public void run() {
					runServer(workerCount);
				}
			}, "Piled HTTPS Server");
			sslServerThread.setDaemon(true);
			sslServerThread.setPriority(Thread.MAX_PRIORITY);
			sslServerThread.start();
		}
	}
	
	static void runServer(int workerCount) {
		if (PiledSSLConfig.sslPort <= 0) {
			PiledSSLConfig.sslPort = 443;
		}

		HttpWorker[] sslWorkers = new HttpWorker[workerCount];
		boolean created = false;
		String workerClass = PiledConfig.worker;
		if (workerClass != null && workerClass.length() > 0) {
			try {
				Class<?> clazz = Class.forName(workerClass);
				try {
					Method initMethod = clazz.getMethod("initialize");
					if (initMethod != null && (initMethod.getModifiers() & Modifier.STATIC) != 0) {
						initMethod.invoke(clazz);
					}
				} catch (SecurityException e) {
					e.printStackTrace();
				} catch (IllegalArgumentException e) {
					e.printStackTrace();
				} catch (NoSuchMethodException e) {
					e.printStackTrace();
				} catch (InvocationTargetException e) {
					e.printStackTrace();
				}
				if (clazz != null && HttpWorker.class.isAssignableFrom(clazz)) {
					for (int i = 0; i < sslWorkers.length; i++) {
						sslWorkers[i] = (HttpWorker) clazz.newInstance();
					}
					created = true;
				}
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (InstantiationException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			}
		}
		if (!created) {
			for (int i = 0; i < sslWorkers.length; i++) {
				sslWorkers[i] = new HttpWorker();
			}
		}
		String address = PiledSSLConfig.sslAddress;
		InetAddress serverAddress = null;
		if (address != null && address.length() > 0 && !"*".equals(address)) {
			try {
				serverAddress = InetAddress.getByName(address);
			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
		}
		PiledSSLServer sslServer = new PiledSSLServer(serverAddress, PiledSSLConfig.sslPort, sslWorkers);

		try {
			PiledSSLConnector.initializeSSLContext(); // initialize SSL Context
			
			sslServer.init();

			sslServer.initializeWrapperInstances();
			sslServer.initializeFilterInstances();
			sslServer.initializePiletInstances();

			singleton = sslServer;
			
			for (int i = 0; i < sslWorkers.length; i++) {
				Thread workerThread = new Thread(sslWorkers[i], "Piled HTTPS Worker" + (sslWorkers.length > 1 ? "-" + (i + 1) : ""));
				workerThread.setDaemon(true);
				workerThread.setPriority(Thread.MAX_PRIORITY - 1);
				workerThread.start();
			}
			
			String workersMonitor = PiledConfig.serverWorkersMonitor;
			if (workersMonitor != null && workersMonitor.length() > 0) {
				try {
					Class<?> clazz = Class.forName(workersMonitor);
					if (clazz != null) {
						Constructor<?> constructor = clazz.getConstructor(PiledAbstractServer.class, HttpWorker[].class);
						if (constructor != null) {
							Object r = constructor.newInstance(sslServer, sslWorkers);
							if (r instanceof Runnable) {
								Thread pipeThread = new Thread((Runnable) r, "Piled HTTPS Piper");
								pipeThread.setDaemon(true);
								pipeThread.start();
							}
						}
						created = true;
					}
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				} catch (InstantiationException e) {
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					e.printStackTrace();
				}
			}
			
			SSLServerMonitor sslServerMonitor = new SSLServerMonitor(sslServer);
			Thread monitorThread = new Thread(sslServerMonitor, "Piled HTTPS Monitor");
			monitorThread.setDaemon(true);
			monitorThread.start();
			
			SocketCloser ssSocketCloser = new SocketCloser(sslServer);
			Thread sslSocketThread = new Thread(ssSocketCloser, "Piled HTTPS Closer");
			sslSocketThread.setDaemon(true);
			sslSocketThread.start();

			try {
				Thread.currentThread().setPriority(Thread.MAX_PRIORITY);
				Thread.currentThread().setName("Piled HTTPS Server");
			} catch (Throwable e) {
				System.out.println("Update main thread priority failed!");
				e.printStackTrace();
			}
			
			sslServer.runLoop();
		} catch (Throwable e) {
			e.printStackTrace();
		}
		
		sslServer.closeWrapperInstances();
	}

}
