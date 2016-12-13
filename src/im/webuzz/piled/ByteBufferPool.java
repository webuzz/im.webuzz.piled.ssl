package im.webuzz.piled;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class ByteBufferPool {

	private static Map<Integer, LinkedList<ByteBuffer>> pooledList = new HashMap<Integer, LinkedList<ByteBuffer>>();
	private static LinkedList<ByteBuffer> pooledBuffer = new LinkedList<ByteBuffer>();
	
	private static Object lock = new Object();
	
	static int commonBufferSize = 16665;
	
	public static int allocateCount = 0;

	public static int pooledCount = 0;
	
	public static int pooledBufferSpareCount = 3000;
	
	/*
	public static int pooledBufferStartingCount = 200;

	public static void setComonBufferSize(int size) {
		if (size == commonBufferSize) {
			return;
		}
		synchronized (lock) {
			if (size == commonBufferSize) {
				return;
			}
			if (pooledBuffer != null && pooledBuffer.size() > 0) {
				pooledList.put(Integer.valueOf(commonBufferSize), pooledBuffer);
			}
			LinkedList<ByteBuffer> existedPooledBuffer = pooledList.remove(Integer.valueOf(size));
			if (existedPooledBuffer != null) {
				pooledBuffer = existedPooledBuffer;
			} else {
				pooledBuffer = new LinkedList<ByteBuffer>();
				for (int i = 0; i < pooledBufferStartingCount; i++) {
					ByteBuffer buf = ByteBuffer.allocate(size);
					pooledBuffer.add(buf);
				}
				allocateCount = pooledBufferStartingCount;
			}
			commonBufferSize = size;
		}
	}
	// */
	
	public static ByteBuffer getByteBufferFromPool(int size) {
		synchronized (lock) {
			if (size == commonBufferSize) {
				if (pooledBuffer.size() > 0) {
					pooledCount--;
					//return pooledBuffer.remove(0);
					ByteBuffer buf = pooledBuffer.removeFirst();
					buf.clear();
					return buf;
				}
			} else {
				LinkedList<ByteBuffer> pooled = pooledList.get(Integer.valueOf(size));
				if (pooled != null && pooled.size() > 0) {
					pooledCount--;
					//return pooled.remove(0);
					ByteBuffer buf = pooled.removeFirst();
					buf.clear();
					return buf;
				}
			}
			ByteBuffer buf = ByteBuffer.allocate(size);
			allocateCount++;
			buf.clear();
			//System.out.println("buffer count = " + allocateCount);
			return buf;
		}
	}
	
	private static boolean contains(LinkedList<ByteBuffer> pooled, ByteBuffer buf) {
		for (ByteBuffer pb : pooled) {
			if (pb == buf) {
				return true;
			}
		}
		return false;
	}
	
	public static boolean putByteBufferToPool(ByteBuffer buf) {
		buf.clear();
		int size = buf.capacity();
		synchronized (lock) {
			if (size == commonBufferSize) {
				if (pooledBuffer.size() >= pooledBufferSpareCount) {
					return false; // just discard buffer to GC
				}
				//if (!contains(pooledBuffer, buf)) {
					pooledCount++;
					pooledBuffer.add(buf);
					return true;
				//}
			} else {
				Integer key = Integer.valueOf(size);
				LinkedList<ByteBuffer> pooled = pooledList.get(key);
				if (pooled != null) {
					if (pooled.size() >= pooledBufferSpareCount) {
						return false; // just discard buffer to GC
					}
					if (!contains(pooled, buf)) {
						pooledCount++;
						pooled.add(buf);
						return true;
					}
				} else {
					pooled = new LinkedList<ByteBuffer>();
					pooledCount++;
					pooled.add(buf);
					pooledList.put(key, pooled);
					return true;
				}
			}
		}
		return false;
	}

}
