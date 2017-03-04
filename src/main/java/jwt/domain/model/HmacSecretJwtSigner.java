package jwt.domain.model;

import java.security.Key;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.HmacKey;

public class HmacSecretJwtSigner extends AbstractJwtSigner {

	private final byte[] secretBytes;

	public HmacSecretJwtSigner(final String issuer, final String audience, final String secretKey) {
		super(issuer, audience);
		secretBytes = secretKey.getBytes();
	}

	@Override
	protected Key getSignKey() {
		return new HmacKey(secretBytes);
	}

	@Override
	protected String getAlgorithm() {
		return AlgorithmIdentifiers.HMAC_SHA256;
	}

}