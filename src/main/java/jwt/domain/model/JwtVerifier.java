package jwt.domain.model;

import org.jose4j.jwt.JwtClaims;

@FunctionalInterface
public interface JwtVerifier {

	public JwtClaims verify(String jwt);

}