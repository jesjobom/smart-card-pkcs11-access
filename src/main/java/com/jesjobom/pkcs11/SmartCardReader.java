package com.jesjobom.pkcs11;

import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstraction for smart card readers.
 * Only needs read operations to get the label from the certificate.
 *
 * @author jesjobom
 */
public abstract class SmartCardReader {
	
	private static final Logger LOGGER = LogManager.getLogger(SmartCardReader.class);
	
	protected final List<String> libs;
	
	public SmartCardReader(String... libs) {
		if(libs == null || libs.length == 0) {
			throw new InvalidParameterException("Need native libraries to access the smart card. Use 'com.jesjobom.pkcs11.NativeLibsUtils#getAvailableLibs()' to get them.");
		}
		this.libs = Arrays.asList(libs);
	}
	
	public abstract void initialize(String... args);
	
	public abstract String getLabel();
}
