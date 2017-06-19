package com.jesjobom.pkcs11;

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
	 * 
	 * @param args where args[0] should be the PIN
	 */
	public static void main(String[] args) {
		if(args == null || args.length == 0) {
			LOGGER.info("The PIN Code is expected as a parameter.");
			LOGGER.info("try 'java Main p123' where p123 is the PIN Code.");
			System.exit(0);
		}
		
		List<String> libs = NativeLibsUtils.getAvailableLibs();
		if(libs == null || libs.isEmpty()) {
			throw new InvalidParameterException("No PKCS11 native library was found. Check the expected libraries on 'com.jesjobom.pkcs11.NativeLibsUtils'");
		}
		
		String pinCode = args[0];
		SmartCardReader reader = new SunReader(libs.toArray(new String[0]));
		reader.initialize(pinCode);
		String label = reader.getLabel();
		
		LOGGER.info(label);
		
	}
}
