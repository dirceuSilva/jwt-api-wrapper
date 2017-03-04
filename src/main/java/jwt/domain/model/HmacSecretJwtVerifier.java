package jwt.domain.model;

import java.security.Key;

import org.jose4j.keys.HmacKey;

public class HmacSecretJwtVerifier extends AbstractJwtVerifier {

	private final byte[] secretBytes;

	public HmacSecretJwtVerifier(final String expectedIssuer, final String expectedAudience, final String secretKey) {
		super(expectedIssuer, expectedAudience);
		secretBytes = secretKey.getBytes();
	}

	public HmacSecretJwtVerifier(final String expectedIssuer, final String expectedAudience, final byte[] secretBytes) {
		super(expectedIssuer, expectedAudience);
		this.secretBytes = secretBytes;
	}

	@Override
	protected Key getVerificationKey() {
		return new HmacKey(secretBytes);
	}

}