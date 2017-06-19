package com.jesjobom.pkcs11.utils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helper to find smart card native librabies in the OS.
 * Actually using a list of known possible libs (.so or .dll).
 *
 * @author jesjobom
 */
public class NativeLibsUtils {
	
	private static final Logger LOGGER = LogManager.getLogger(NativeLibsUtils.class);
	
	private static final String WIN_BASE = "C:/Windows/System32/";
	private static final String UNIX_BASE = "/usr/lib/";

	private static final String[] WIN_LIBS = {"aetpkss1.dll", "asepkcs.dll", "gclib.dll", "pk2priv.dll", "w32pk2ig.dll", "ngp11v211.dll", "eTPkcs11.dll", "eTPKCS11.dll", "acospkcs11.dll", "dkck201.dll", "dkck232.dll", "cryptoki22.dll", "acpkcs.dll", "slbck.dll", "WDPKCS.dll", "cmP11.dll", "WDBraz_P11_CCID_v34.dll"};
	private static final String[] UNIX_LIBS = {"libASEP11.so", "opensc-pkcs11.so", "libaetpkss.so", "libaetpkss.so.3", "libgpkcs11.so", "libgpkcs11.so.2", "libepsng_p11.so", "libepsng_p11.so.1", "libeTPkcs11.so", "libeToken.so", "libeToken.so.4", "libcmP11.so", "libwdpkcs.so", "/usr/local/lib64/libwdpkcs.so", "/usr/local/lib/libwdpkcs.so", "pkcs11/opensc-pkcs11.so", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "ifdokccid.so", "libokbase2.so", "libokbase2.so.3"};
	
	public static List<String> getAvailableLibs() {
		LOGGER.debug("Detected OS: " + OsUtils.getOsName());

		List<String> foundLibs;
		if (OsUtils.isWindows()) {
			foundLibs = findLibs(WIN_BASE, WIN_LIBS);
		} else {
			foundLibs = findLibs(UNIX_BASE, UNIX_LIBS);
		}
                
                LOGGER.debug((foundLibs == null ? 0 : foundLibs.size()) + " libs found.");
		return foundLibs;
	}

	private static List<String> findLibs(String basePath, String... libs) {
		List<String> foundLibs = new ArrayList<>();
		for (String lib : libs) {
			File file;
			if (lib.startsWith("/") || lib.startsWith("C:")) {
				file = new File(lib);
			} else {
				file = new File(basePath + lib);
			}
			if (file.exists()) {
				foundLibs.add(file.getAbsolutePath());
				LOGGER.debug("Found lib: " + file.getAbsolutePath());
			}
		}
		return foundLibs;
	}
}
