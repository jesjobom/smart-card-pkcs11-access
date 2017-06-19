package com.jesjobom.pkcs11.utils;

/**
 * Considering only Windows and Unix.
 *
 * @author jairton
 */
public class OsUtils {

	private static String OS = null;

	public static String getOsName() {
		if (OS == null) {
			OS = System.getProperty("os.name");
		}
		return OS;
	}

	public static boolean isWindows() {
		return getOsName().startsWith("Windows");
	}

	public static boolean isUnix() {
		return !isWindows();
	}
}
