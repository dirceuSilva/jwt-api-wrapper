package jwt.infrastructure.web;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jwt.domain.model.HmacSecretJwtVerifier;
import jwt.domain.model.JwtVerifier;

public class JwtServletFilter implements Filter {

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtServletFilter.class);
	private JwtVerifier verifier;

	@Override
	public void init(final FilterConfig filterConfig) throws ServletException {
		final String expectedIssuer = filterConfig.getInitParameter("issuer");
		final String expectedAudience = filterConfig.getInitParameter("audience");
		final String secretKey = filterConfig.getInitParameter("secretKey");
		verifier = new HmacSecretJwtVerifier(expectedIssuer, expectedAudience, secretKey);
		LOGGER.info("Initialized with Issuer: {}, Audience: {} and Secret: ****", expectedIssuer, expectedAudience);
	}

	@Override
	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
		final HttpServletRequest r = (HttpServletRequest) request;
		final HttpServletResponse e = (HttpServletResponse) response;

		if (r.getMethod().equalsIgnoreCase("options")) {
			LOGGER.trace("OPTIONS method, probably for CORS. You can pass.");
			chain.doFilter(r, e);
			return;
		}

		final String authorizationHeader = r.getHeader("TCS_TOKEN");
		if (authorizationHeader == null) {
			LOGGER.trace("No Authorization header was found");
			e.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		// remove schema from token
		final String authorizationSchema = "Bearer";
		if (authorizationHeader.indexOf(authorizationSchema) == -1) {
			LOGGER.trace("Invalid authorization schema. Expected: Bearer <token>, but was: " + authorizationHeader);
			e.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		try {
			final String jwtToken = authorizationHeader.substring(authorizationSchema.length()).trim();
			verifier.verify(jwtToken);
			chain.doFilter(r, e);
		} catch (final IllegalArgumentException ex) {
			LOGGER.trace("Invalid JWT Token: " + ex.getCause().getMessage());
			e.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		}
	}

	@Override
	public void destroy() {
		// do nothing
	}
}
