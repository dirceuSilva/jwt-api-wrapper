package jwt.domain.model;

import java.security.Key;
import java.util.Arrays;
import java.util.List;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapted from
 * https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples#markdown-header-producing-and-consuming-a-signed-jwt
 */
public abstract class AbstractJwtSigner implements JwtSigner {

	private static final Logger LOGGER = LoggerFactory.getLogger(HmacSecretJwtSigner.class);

	protected final String issuer;
	protected final String audience;

	public AbstractJwtSigner(final String issuer, final String audience) {
		super();
		this.issuer = issuer;
		this.audience = audience;
	}

	protected abstract Key getSignKey();

	protected abstract String getAlgorithm();

	private String createClaim() {
		// Create the Claims, which will be the content of the JWT
		final JwtClaims claims = new JwtClaims();
		claims.setIssuer(issuer); // who creates the token and signs it
		claims.setAudience(audience); // to whom the token is intended to be
										// sent
		claims.setExpirationTimeMinutesInTheFuture(0.167f); // time when the
															// token will expire
															// (10 seconds from
															// now)
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow(); // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(2); // time before which the token
												// is not yet valid (2 minutes
												// ago)
		claims.setSubject("subject"); // the subject/principal is whom the token
										// is about
		claims.setClaim("email", "mail@example.com"); // additional
														// claims/attributes
														// about the subject can
														// be added
		final List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
		claims.setStringListClaim("groups", groups); // multi-valued claims work
														// too and will end up
														// as a JSON array
		return claims.toJson();
	}

	@Override
	public String sign() {
		try {
			// A JWT is a JWS and/or a JWE with JSON claims as the payload.
			// In this example it is a JWS so we create a JsonWebSignature
			// object.
			final JsonWebSignature jws = new JsonWebSignature();

			// The payload of the JWS is JSON content of the JWT Claims
			jws.setPayload(createClaim());

			jws.setKey(getSignKey());

			// Set the Key ID (kid) header because it's just the polite thing to
			// do.
			// We only have one key in this example but a using a Key ID helps
			// facilitate a smooth key rollover process
			jws.setKeyIdHeaderValue("k1");

			// Set the signature algorithm on the JWT/JWS that will integrity
			// protect the claims
			jws.setAlgorithmHeaderValue(getAlgorithm());

			// Sign the JWS and produce the compact serialization or the
			// complete JWT/JWS
			// representation, which is a string consisting of three dot ('.')
			// separated
			// base64url-encoded parts in the form Header.Payload.Signature
			// If you wanted to encrypt it, you can simply set this jwt as the
			// payload
			// of a JsonWebEncryption object and set the cty (Content Type)
			// header to "jwt".
			final String jwt = jws.getCompactSerialization();

			// Now you can do something with the JWT. Like send it to some other
			// party
			// over the clouds and through the interwebs.
			LOGGER.debug("JWT: {}", jwt);
			return jwt;
		} catch (final JoseException e) {
			throw new IllegalStateException("Cannot produce JWT. ", e);
		}
	}

}