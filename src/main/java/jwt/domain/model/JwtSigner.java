package jwt.domain.model;

@FunctionalInterface
public interface JwtSigner {

	public String sign();

}