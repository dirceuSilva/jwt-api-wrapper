package jwt.domain.model;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.IOUtils;

/**
 * Adapted from https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples#markdown-header-producing-and-consuming-a-signed-jwt
 */
public class RsaJwtVerifier extends AbstractJwtVerifier {

	private PublicKey publicKey;

	public RsaJwtVerifier(final String expectedIssuer, final String expectedAudience, final String verificationKeyResourceName) {
		super(expectedIssuer, expectedAudience);
		try {
			final InputStream input = RsaFileReaderUtil.readFile(verificationKeyResourceName);
			final X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(IOUtils.toByteArray(input));
			publicKey = KeyFactory.getInstance("RSA").generatePublic(pkSpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			throw new IllegalStateException("Cannot initialize JwtVerifier. ", e);
		}
	}

	@Override
	protected Key getVerificationKey() {
		return publicKey;
	}

}