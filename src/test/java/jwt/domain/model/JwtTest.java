package jwt.domain.model;

import static org.junit.Assert.fail;

import org.junit.Test;


public class JwtTest {

	private static final String THE_AUDIENCE = "CokeCoinsApi";
	private static final String THE_ISSUER = "CokeCoinsAdmin";
	private static final String HMAC_SUPER_SECRET_KEY = "ASDFERESDFSDFCDRERTGASDFERESDFSDFCDRERTG";

	@Test
	public void producingAndConsumingRsaJwt() {
		final JwtSigner signer = new RsaJwtSigner(THE_ISSUER, THE_AUDIENCE, "/jwt/sign.key");
		final JwtVerifier verifier = new RsaJwtVerifier(THE_ISSUER, THE_AUDIENCE, "/jwt/verification.key");

		verifier.verify(signer.sign());
	}

	@Test(expected = IllegalArgumentException.class)
	public void createRsaSignerWithoutKeyFileShouldFail() {
		new RsaJwtSigner(THE_ISSUER, THE_AUDIENCE, "blablabla");
	}

	@Test
	public void producingAndConsumingHmacSecretJwt() {
		final JwtSigner signer = new HmacSecretJwtSigner(THE_ISSUER, THE_AUDIENCE, HMAC_SUPER_SECRET_KEY);
		final JwtVerifier verifier = new HmacSecretJwtVerifier(THE_ISSUER, THE_AUDIENCE, HMAC_SUPER_SECRET_KEY);

		verifier.verify(signer.sign());
	}

	@Test(expected = IllegalArgumentException.class)
	public void consumingExpiredTokenShouldFail() throws InterruptedException {
		final JwtSigner signer = new HmacSecretJwtSigner(THE_ISSUER, THE_AUDIENCE, HMAC_SUPER_SECRET_KEY);
		final JwtVerifier verifier = new HmacSecretJwtVerifier(THE_ISSUER, THE_AUDIENCE, HMAC_SUPER_SECRET_KEY);

		final String sign = signer.sign();
		System.out.println("Sleeping 11s to cause token expiration");
		Thread.sleep(11000);
		verifier.verify(sign);
		fail("JWT should be expired after 10 seconds");
	}

	@Test(expected = IllegalArgumentException.class)
	public void verificationOfExpiredTokenShouldFail() {
		final JwtVerifier verifier = new HmacSecretJwtVerifier(THE_ISSUER, THE_AUDIENCE, HMAC_SUPER_SECRET_KEY);
		verifier.verify("eyJraWQiOiJrMSIsImFsZyI6IkhTMjU2In0.eyJpc3MiOiJDb2tlQ29pbnNBZG1pbiIsImF1ZCI6IkNva2VDb2luc0FwaSIsImV4cCI6MTQ1MTUxMjAyMCwianRpIjoiN04zUkRsR25oMUV6MHVISEhteEJpZyIsImlhdCI6MTQ1MTUxMjAxMCwibmJmIjoxNDUxNTExODkwLCJzdWIiOiJzdWJqZWN0IiwiZW1haWwiOiJtYWlsQGV4YW1wbGUuY29tIiwiZ3JvdXBzIjpbImdyb3VwLW9uZSIsIm90aGVyLWdyb3VwIiwiZ3JvdXAtdGhyZWUiXX0.XUuBz4KH-a7KAeBrBHQSUv7cbjSvJ6xA0Uxgm8mK7jI");
	}

}
