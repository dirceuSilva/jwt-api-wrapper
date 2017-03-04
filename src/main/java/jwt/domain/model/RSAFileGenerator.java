package jwt.domain.model;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.IOUtils;
import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAFileGenerator {

	private static final Logger LOGGER = LoggerFactory.getLogger(RSAFileGenerator.class);

	private RSAFileGenerator() {
		throw new IllegalAccessError("Utility class");
	}

	public static void main(final String[] args) throws JoseException {
		if (args == null || args.length != 1) {
			LOGGER.info("You need to inform the directory where key files will be created");
			return;
		}

		// Generate an RSA key pair, which will be used for signing and
		// verification of the JWT, wrapped in a JWK
		final KeyPair keyPair = new RsaKeyUtil().generateKeyPair(2048);
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		final X509EncodedKeySpec x509ks = new X509EncodedKeySpec(publicKey.getEncoded());
		final String verificationKeyFilename = args[0] + "/verification.key";
		writeFile(verificationKeyFilename, x509ks.getEncoded());

		final PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		final String signKeyFilename = args[0] + "/sign.key";
		writeFile(signKeyFilename, pkcsKeySpec.getEncoded());

		LOGGER.info("Files verification.key and sign.key were created at {}", args[0]);
	}

	private static void writeFile(final String filename, final byte[] contentBytes) {
		try {
			IOUtils.write(contentBytes, new FileOutputStream(filename.replaceAll("//", "")));
		} catch (final IOException e) {
			LOGGER.error("Error writing file {}" + filename, e);
		}
	}
}