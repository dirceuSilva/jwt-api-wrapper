package jwt.domain.model;

import java.security.Key;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapted from https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples#markdown-header-producing-and-consuming-a-signed-jwt
 */
public abstract class AbstractJwtVerifier implements JwtVerifier {

	private static final Logger LOGGER = LoggerFactory.getLogger(HmacSecretJwtVerifier.class);

	protected final String expectedIssuer;
	protected final String expectedAudience;

	public AbstractJwtVerifier(final String expectedIssuer, final String expectedAudience) {
		super();
		this.expectedIssuer = expectedIssuer;
		this.expectedAudience = expectedAudience;
	}

	protected abstract Key getVerificationKey();
	
	@Override
	public JwtClaims verify(final String jwt) {
		try {
			final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
			.setRequireExpirationTime() // the JWT must have an expiration time
			//					.setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
			.setRequireSubject() // the JWT must have a subject claim
			.setExpectedIssuer(expectedIssuer) // whom the JWT needs to have been issued by
			.setExpectedAudience(expectedAudience) // to whom the JWT is intended for
			.setVerificationKey(getVerificationKey()) // verify the signature with the public key
			.build(); // create the JwtConsumer instance

			//  Validate the JWT and process it to the Claims
			final JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
			LOGGER.debug("JWT validation succeeded! {}", jwtClaims);
			return jwtClaims;
		} catch (final InvalidJwtException e) {
			throw new IllegalArgumentException("Invalid JWT.", e);
		}
	}

}