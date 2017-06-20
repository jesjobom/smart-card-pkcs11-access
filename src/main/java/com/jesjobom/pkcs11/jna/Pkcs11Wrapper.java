package com.jesjobom.pkcs11.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * Java Wrapper for the native PKCS11 library.
 *
 * @author jesjobom
 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
 */
public class Pkcs11Wrapper {

	public static final long READ_ONLY_SESSION = 0L;
	public static final long SERIAL_SESSION = 4L;

	public static native int C_Initialize(Pointer args);

	public static native int C_Finalize(Pointer args);

	public static native int C_GetSlotList(int onlyToken, Pointer slotIds, NativeLongByReference slotsCount);

	public static native int C_OpenSession(NativeLong slotId, NativeLong flags, Pointer app, Pointer notify, NativeLongByReference sessionId);

	public static native int C_CloseSession(NativeLong sessionId);

	public static native int C_FindObjectsInit(NativeLong sessionId, CK_ATTRIBUTE.Native attrs, int attrQuantity);

	public static native int C_FindObjects(NativeLong sessionId, Pointer objectIds, int maxObjCount, NativeLongByReference returnedCount);

	public static native int C_GetAttributeValue(NativeLong sessionId, NativeLong objectId, CK_ATTRIBUTE.Native attrs, int attrCount);

	public static native int C_FindObjectsFinal(NativeLong sessionId);
}
