package com.example.authApi.jwt;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.lang.invoke.MethodHandles;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Service("tokenKeyService")
public class TokenKeyService {

	@Autowired
	private JwkProviderBuilder providerBuilder;

	private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().getClass());

	private static final String JWKS_CMD_KEY = "jwksEndpoint";

	public Algorithm getAlgorithm(String token) {

		try {
			DecodedJWT jwt = JWT.decode(token);
			String issuer = jwt.getIssuer();
			String kid = jwt.getKeyId();
			LOGGER.debug("token issuer: {}, token kid: {}", issuer, kid);

			Jwk jwk = providerBuilder.build(issuer).get(kid);

			return Algorithm.RSA256(new RSAKeyProvider() {

				@Override
				public RSAPublicKey getPublicKeyById(String keyId) {

					try {
						return (RSAPublicKey) jwk.getPublicKey();
					} catch (InvalidPublicKeyException e) {
						LOGGER.error("invalid public key exception: ", e);
					}
					return null;
				}

				@Override
				public RSAPrivateKey getPrivateKey() {
					return null;
				}

				@Override
				public String getPrivateKeyId() {
					return null;
				}});
		}  catch (SignatureVerificationException e) {
			LOGGER.error("Jwk SignatureVerificationException: ", e);
		} 
		catch (SigningKeyNotFoundException e) {
			LOGGER.error("Jwk SigningKeyNotFoundException: ", e);
		} catch (JwkException e) {
			e.printStackTrace();
		}
		return null;
	}


}
