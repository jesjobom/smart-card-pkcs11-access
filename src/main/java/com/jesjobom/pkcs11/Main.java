package com.jesjobom.pkcs11;

import com.jesjobom.pkcs11.jna.NativeReader;
import com.jesjobom.pkcs11.sun.SunReader;
import com.jesjobom.pkcs11.utils.NativeLibsUtils;
import java.security.InvalidParameterException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jesjobom
 */
public class Main {
	
	private static final Logger LOGGER = LogManager.getLogger(Main.class);
	
	/**
	 * Test the access to the certificate of the PKCS11 Smart Card.
	 * The Pin code is requested from the Sun's implemention of the PKCS11.
	 * But <code>null</code> is accepted to try the access without PIN.
	 * 
	 * @param args where args[0] should be the PIN
	 */
	public static void main(String[] args) {
		if(args == null || args.length == 0) {
			LOGGER.warn("The PIN Code is expected as a parameter.");
			LOGGER.warn("try 'java Main p123' where p123 is the PIN Code.");
			LOGGER.warn("A 'null' pin will be used now, but it'll fail.");
		}
		
		List<String> libs = NativeLibsUtils.getAvailableLibs();
		if(libs == null || libs.isEmpty()) {
			throw new InvalidParameterException("No PKCS11 native library was found. Check the expected libraries on 'com.jesjobom.pkcs11.NativeLibsUtils'");
		}
		
		LOGGER.info(" === BEGIN SMART CARD ACCESS ===");
		
		LOGGER.info(" === USING SUN'S IMPLEMENTATION ===");
		
		try {
			//Access via Sun's version of PKCS11, for some reason, 
			//hangs the application for some time... dont know why yet
			SmartCardReader reader = new SunReader(libs.toArray(new String[0]));
			reader.initialize(args);
			String label = reader.getLabel();
		
			LOGGER.info(label);
			
		} catch (Exception ex) {
			LOGGER.error("Failed to access the smart card.", ex);
		}
		
		LOGGER.info("");
		LOGGER.info(" === USING JNA ===");
		
		SmartCardReader reader = new NativeReader(libs.toArray(new String[0]));
		reader.initialize(args);
		String label = reader.getLabel();
		
		LOGGER.info(label);
		
		LOGGER.info(" === END OF SMART CARD ACCESS ===");
	}
}
