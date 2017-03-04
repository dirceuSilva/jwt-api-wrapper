package jwt.domain.model;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;

public class RSAFileGenerator {

	public static void main(final String[] args) throws JoseException, IOException {
		if (args == null || args.length != 1) {
			System.out.println("You need to inform the directory where key files will be created");
			return;
		}

		// Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
		final KeyPair keyPair = new RsaKeyUtil().generateKeyPair(2048);
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		final X509EncodedKeySpec x509ks = new X509EncodedKeySpec(publicKey.getEncoded());
		final String verificationKeyFilename = args[0] + "/verification.key";
		final FileOutputStream fos = new FileOutputStream(verificationKeyFilename.replaceAll("//", ""));
		fos.write(x509ks.getEncoded());
		fos.close();

		final PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		final String signKeyFilename = args[0] + "/sign.key";
		final FileOutputStream pfos = new FileOutputStream(signKeyFilename.replaceAll("//", ""));
		pfos.write(pkcsKeySpec.getEncoded());
		pfos.close();

		System.out.println("Files verification.key and sign.key were created at " + args[0]);
	}
}