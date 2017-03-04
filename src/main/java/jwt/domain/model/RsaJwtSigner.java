package jwt.domain.model;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.io.IOUtils;
import org.jose4j.jws.AlgorithmIdentifiers;

/**
 * Adapted from https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples#markdown-header-producing-and-consuming-a-signed-jwt
 */
public class RsaJwtSigner extends AbstractJwtSigner {

	private PrivateKey privateKey;

	public RsaJwtSigner(final String issuer, final String audience, final String signKeyResourceName) {
		super(issuer, audience);
		try {
			final InputStream input = RsaFileReaderUtil.readFile(signKeyResourceName);
			final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(input));
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			throw new IllegalStateException("Cannot initialize JwtSigner. ", e);
		}
	}

	@Override
	protected Key getSignKey() {
		return privateKey;
	}

	@Override
	protected String getAlgorithm() {
		return AlgorithmIdentifiers.RSA_USING_SHA256;
	}

}