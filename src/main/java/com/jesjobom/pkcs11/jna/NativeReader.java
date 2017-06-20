package com.jesjobom.pkcs11.jna;

import com.jesjobom.pkcs11.SmartCardReader;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import java.nio.ByteBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jesjobom
 */
public class NativeReader extends SmartCardReader {

	private static final Logger LOGGER = LogManager.getLogger(SmartCardReader.class);
	
	public NativeReader(String... libs) {
		super(libs);
	}

	@Override
	public void initialize(String... args) {
		//do nothing
	}

	@Override
	public String getLabel() {
		RuntimeException lastException = null;
		
		for (String lib : libs) {
			try {
				return getLabelCert(lib);
			} catch (RuntimeException ex) {
				lastException = ex;
			}
		}
		
		throw lastException;
	}
	
	/**
	 * Get the label from the last certificate from the smart card using the
	 * native library located in the passed path.
	 * 
	 * @param libPath
	 * @return {@link String} with the label
	 */
	public static String getLabelCert(String libPath) {

		loadNativeLib(libPath);

		try {
			initPkcs11();

			long slotId = getFirstTokenSlotId();

			try {
				long sessionId = beginNewSession(slotId);

				try {
					initFind(sessionId);

					long[] objectIds = findObjects(sessionId);

					String label = null;

					LOGGER.debug("Getting LABEL");
					for (long objectId : objectIds) {
						try {
							label = getObjectLabel(sessionId, objectId);
						} catch (RuntimeException ex) {
							//if an error occur, continue
							//to the next certificate.
						}
					}

					if (label != null) {
						return label.replaceAll("^[^\\p{L}\\p{Digit}]*([\\p{L}\\p{Digit}\\\\\\/\\-\\(\\)\\:\\~ ]+\\)?).*$", "$1");
					}

				} finally {
					endFind(sessionId);
				}

			} finally {
				closeSession(slotId);
			}

		} finally {
			finalizePkcs11();
		}

		return null;
	}

	/**
	 * Load native library into the wrapper class, allowing static calls.
	 * 
	 * @param libPath path to the native library
	 * @see Pkcs11Wrapper
	 */
	private static void loadNativeLib(String libPath) {
		LOGGER.debug("Loading native library " + libPath);
		Native.register(Pkcs11Wrapper.class, libPath);
	}

	/**
	 * Init PKCS11 without parameters.
	 * 
	 * @throws CertificadoException 
	 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024102
	 */
	private static void initPkcs11() {
		LOGGER.debug("Initializing PKCS11");
		int initReturn = Pkcs11Wrapper.C_Initialize(Pointer.NULL);

		if (initReturn != 0) {
			LOGGER.error(initReturn + " : Rerturn INIT");
			throw new RuntimeException("Failed to initialize: " + initReturn);
		}
	}

	/**
	 * Get the ID of the first smart card slot (reader) that contains a token.
	 * There's no known order to the smart card slots.
	 * @return long with the ID for the first slot
	 * @throws CertificadoException 
	 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024105
	 */
	private static long getFirstTokenSlotId() {
		LOGGER.debug("Getting the first smart card slot with a token");
		NativeLongByReference slotsCount = new NativeLongByReference();
		
		int slotReturn = Pkcs11Wrapper.C_GetSlotList(1, Pointer.NULL, slotsCount);
		if (slotReturn != 0) {
			LOGGER.error(slotReturn + " : Return SLOT LENGTH");
			throw new RuntimeException("Failed to Get Slot Length: " + slotReturn);
		}
		
		LOGGER.debug(slotsCount.getValue() + " : Quantity of slots connected");
		if(slotsCount.getValue().longValue() == 0) {
			throw new RuntimeException("No smart card slot detected. Is the reader connected?");
		}
		
		Pointer slotIds = new Memory(slotsCount.getValue().longValue() * NativeLong.SIZE);
		
		slotReturn = Pkcs11Wrapper.C_GetSlotList(1, slotIds, slotsCount);
		if (slotReturn != 0) {
			LOGGER.error(slotReturn + " : Return SLOT LIST");
			throw new RuntimeException("Failed to Get Slot List: " + slotReturn);
		}

		long slotId;
		if(NativeLong.SIZE == 4) {
			slotId = slotIds.getInt(0);
		} else {
			slotId = slotIds.getLong(0);
		}
		
		LOGGER.debug(slotId + " : first slot ID");
		return slotId;
	}

	/**
	 * Begins a new session to access the smart card.
	 * @param slotId
	 * @return long with the ID of the new session
	 * @throws CertificadoException 
	 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc72656119
	 */
	private static long beginNewSession(long slotId) {
		LOGGER.debug("Begining new SESSION for slot " + slotId);
		Pointer pApplication = new Memory(1024);
		NativeLongByReference sessionId = new NativeLongByReference();
		int sessionReturn = Pkcs11Wrapper.C_OpenSession(new NativeLong(slotId), new NativeLong(Pkcs11Wrapper.SERIAL_SESSION), pApplication, Pointer.NULL, sessionId);

		if (sessionReturn != 0) {
			LOGGER.error(sessionReturn + " : Return OPEN SESSION");
			throw new RuntimeException("Failed to Open Session: " + sessionReturn);
		}

		LOGGER.debug(sessionId.getValue() + " : Session ID");
		return sessionId.getValue().longValue();
	}

	/**
	 * Initializes the search mechanism for certificates.
	 * A filter is applied for the future search results.
	 * Only certificates with the attribute CKA_CERTIFICATE_TYPE = 0 will be
	 * returned.
	 * @param sessionId
	 * @throws CertificadoException 
	 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323205460
	 */
	private static void initFind(long sessionId) {
		LOGGER.debug("Initializing SEARCH");
		
		ByteBuffer buffer = ByteBuffer.allocate(NativeLong.SIZE);
		if(NativeLong.SIZE == 4) {
			buffer.putInt(0);
		} else {
			buffer.putLong(0L);
		}
		
		CK_ATTRIBUTE filter = new CK_ATTRIBUTE(0x80L, NativeLong.SIZE);
		filter.pValue = buffer.array();
		CK_ATTRIBUTE[] filters = new CK_ATTRIBUTE[]{filter};
		
		CK_ATTRIBUTE.Native nativeAttr = new CK_ATTRIBUTE.Native(filters);

		int findInitReturn = Pkcs11Wrapper.C_FindObjectsInit(new NativeLong(sessionId), nativeAttr, filters.length);

		if (findInitReturn != 0) {
			LOGGER.error(findInitReturn + " : Return INIT FIND");
			throw new RuntimeException("Failed to Find Init: " + findInitReturn);
		}
	}

	/**
	 * Completes the search and return the results.
	 * @param sessionId
	 * @return array of long with maximum of 30 objects (certificates)
	 * @throws CertificadoException 
	 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323205461
	 */
	private static long[] findObjects(long sessionId) {
		LOGGER.debug("Finding OBJETOS");
		//Max of 30 objects read from the smart card
		Pointer objectIds = new Memory(30 * NativeLong.SIZE);
		NativeLongByReference objectsCount = new NativeLongByReference();
		int findReturn = Pkcs11Wrapper.C_FindObjects(new NativeLong(sessionId), objectIds, 30, objectsCount);

		if (findReturn != 0) {
			LOGGER.error(findReturn + " : Return FIND");
			throw new RuntimeException("Failed to Find: " + findReturn);
		}

		LOGGER.debug(objectsCount.getValue() + " : Quantity of objects returned from the smart card");
		long[] objectIdsArr = new long[(int)objectsCount.getValue().longValue()];
		for(int i = 0; i < objectIdsArr.length; i++) {
			if(NativeLong.SIZE == 4) {
				objectIdsArr[i] = objectIds.getInt(i * NativeLong.SIZE);
			} else {
				objectIdsArr[i] = objectIds.getLong(i * NativeLong.SIZE);
			}
		}
		
		return objectIdsArr;
	}

	/**
	 * Gets the label of the object (certificate) for the informed ID.
	 * The attribute for the label is <em>CKA_LABEL = 0x3L</em>.
	 * @param sessionId
	 * @param objectId
	 * @return {@link String} with the label of the certificate.
	 * @throws CertificadoException 
	 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024125
	 */
	private static String getObjectLabel(long sessionId, long objectId) {
		LOGGER.trace("Getting LABEL obj ID " + objectId);
		//field CKA_LABEL
		CK_ATTRIBUTE attr = new CK_ATTRIBUTE(0x3L);
		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[]{attr};
		
		CK_ATTRIBUTE.Native nativeAttrs = new CK_ATTRIBUTE.Native(attrs);
		
		int attrReturn = Pkcs11Wrapper.C_GetAttributeValue(new NativeLong(sessionId), new NativeLong(objectId), nativeAttrs, attrs.length);

		if (attrReturn != 0) {
			LOGGER.trace(attrReturn + " : Return ATTRIBUTE LENGTH (obj " + objectId + " / size " + attr.ulValueLen + ")");
			throw new RuntimeException("Failed to get Attribute Value (obj " + objectId + "): " + attrReturn);
		}

		attrs = nativeAttrs.refresh();
		attr = attrs[0];
		
		if (attr.ulValueLen == 0) {
			LOGGER.trace(attrReturn + " : Return ATTRIBUTE LENGTH (obj " + objectId + " / size " + attr.ulValueLen + ")");
			throw new RuntimeException("Failed to get Attribute Value (obj " + objectId + "): no return");
		}
		
		attr = new CK_ATTRIBUTE(attr.type, attr.ulValueLen);
		attrs = new CK_ATTRIBUTE[]{attr};
		nativeAttrs = new CK_ATTRIBUTE.Native(attrs);
		
		attrReturn = Pkcs11Wrapper.C_GetAttributeValue(new NativeLong(sessionId), new NativeLong(objectId), nativeAttrs, attrs.length);
		
		if (attrReturn != 0) {
			LOGGER.trace(attrReturn + " : Return ATTRIBUTE VALUE (obj " + objectId + " / size " + attr.ulValueLen + ")");
			throw new RuntimeException("Failed to get Attribute Value (obj " + objectId + "): " + attrReturn);
		}
		
		attrs = nativeAttrs.refresh();
		attr = attrs[0];

		LOGGER.trace(new String(attr.pValue) + " : PVALUE (type " + attr.type + ", size " + attr.ulValueLen + ")");
		return new String(attr.pValue);
	}

	/**
	 * Finalizes the search for objects.
	 * @param sessionId 
	 */
	private static void endFind(long sessionId) {
		LOGGER.debug("Ending FIND");
		int findFinalReturn = Pkcs11Wrapper.C_FindObjectsFinal(new NativeLong(sessionId));
		if (findFinalReturn != 0) {
			LOGGER.error(findFinalReturn + " : Return FIND FINAL");
		}
	}

	/**
	 * Closes the session and the access to the smart card.
	 * @param sessionId 
	 */
	private static void closeSession(long sessionId) {
		LOGGER.debug("Closing SESSION");
		int closeReturn = Pkcs11Wrapper.C_CloseSession(new NativeLong(sessionId));
		if (closeReturn != 0) {
			LOGGER.error(closeReturn + " : Return CLOSE SESSION");
		}
	}

	/**
	 * Finalizes the PKCS11 wrapper.
	 */
	private static void finalizePkcs11() {
		LOGGER.debug("Finalizing LIB");
		int finalizeReturn = Pkcs11Wrapper.C_Finalize(Pointer.NULL);
		if (finalizeReturn != 0) {
			LOGGER.error(finalizeReturn + " : Return FINALIZE");
		}
	}
}
