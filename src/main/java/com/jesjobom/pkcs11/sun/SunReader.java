package com.jesjobom.pkcs11.sun;

import com.jesjobom.pkcs11.SmartCardReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.pkcs11.SunPKCS11;

/**
 * Smart card reader using Sun's implementation. On Windows x64, Java 7 needs to
 * be 32 bits. Java 8+ should be fine either on 32 or 64 bits. Java 7 does not
 * include Sun's implementation for 64 bits since it was not homologated be
 *
 * @author jesjobom
 */
public class SunReader extends SmartCardReader {

	private static final Logger LOGGER = LogManager.getLogger(SunReader.class);

	private String pin;

	public SunReader(String... libs) {
		super(libs);
	}

	@Override
	public void initialize(String... args) {
		if (args == null || args.length == 0) {
			throw new InvalidParameterException("The Smart Card PIN is needed to access the certificates.");
		}

		this.pin = args[0];
	}

	@Override
	public String getLabel() {

		KeyStore keystore = null;
		for (String lib : libs) {
			try {
				keystore = loadKeystore(lib);
			} catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException ex) {
				LOGGER.debug("Failed to load keystore with library " + lib + ". Will try with the next one if available.", ex);
			}
		}

		if (keystore == null) {
			throw new NullPointerException("None of the libraries found were able to load the keystore from the Smart Card.");
		}

		X509Certificate certificate;
		try {
			certificate = getLastCertificateFromKeystore(keystore);
		} catch (KeyStoreException ex) {
			LOGGER.error("Error while trying to load the keystore", ex);
			throw new RuntimeException(ex);
		}
		
		return certificate.getSubjectDN().getName();
	}

	/**
	 * Load the certificates from the smart card using a keystore. Actually
	 * the Sun's implementation defined that these certificates can only be
	 * obtained via a keystore and a PIN code.
	 *
	 * @param lib
	 * @return {@link KeyStore}
	 */
	private KeyStore loadKeystore(String lib) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
		Provider provider = new SunPKCS11(new ByteArrayInputStream(generatePkcs11Config(lib).getBytes()));
		KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
		keyStore.load(null, pin.toCharArray());
		return keyStore;
	}

	/**
	 * Config for the Sun's implementation of PKCS11
	 *
	 * @param lib
	 * @see
	 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html#Config
	 * @return
	 */
	private static String generatePkcs11Config(String lib) {
		StringBuilder builder = new StringBuilder();
		
		builder.append("name=SmartCard\n");
		builder.append("showInfo=");
		builder.append(LOGGER.getLevel().isLessSpecificThan(Level.DEBUG) ? "true\n" : "false\n");
		builder.append("library=");
		builder.append(lib);
		return builder.toString();
	}

	/**
	 * Loads the last certificate from the smart card. By last I mean the
	 * certificate with longest chain. I supose that this will be the user's
	 * certificate.
	 *
	 * @param keyStore
	 * @return {@link X509Certificate}
	 */
	private X509Certificate getLastCertificateFromKeystore(KeyStore keyStore) throws KeyStoreException {

		List<String> aliases = Collections.list(keyStore.aliases());
		X509Certificate certificate = null;
		int chainSize = 0;

		for (String aliase : aliases) {
//			if (!keyStore.isCertificateEntry(aliase)) {
//				continue;
//			}

			int size = keyStore.getCertificateChain(aliase).length;
			if (certificate == null || chainSize < size) {
				chainSize = size;
				certificate = (X509Certificate) keyStore.getCertificate(aliase);
			}
		}

		if (certificate == null) {
			throw new NullPointerException("Not possible to access the certificate from the smart card. Is it a PKCS11 initialized card?");
		}

		//certificate.checkValidity();
		return certificate;
	}
}
