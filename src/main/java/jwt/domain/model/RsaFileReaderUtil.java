package jwt.domain.model;

import java.io.InputStream;

public class RsaFileReaderUtil {

	static InputStream readFile(final String resourceName) {
		final InputStream input = RsaFileReaderUtil.class.getResourceAsStream(resourceName);
		if (input == null) {
			throw new IllegalArgumentException("No resource found with name " + resourceName
					+ ". You should have a file with RSA key in the classpath of your application. "
					+ "You can use RSAFileGenerator main function to create these files");
		}
		return input;
	}

}