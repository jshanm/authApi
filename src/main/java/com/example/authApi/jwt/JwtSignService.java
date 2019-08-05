package com.example.authApi.jwt;

import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;


@Service
public class JwtSignService {

	private static Logger LOGGER = LoggerFactory.getLogger(JwtSignService.class);

	@Autowired
	TokenKeyService tokenKeyService;

	/**
	 * Method to verify the JWT signature
	 *
	 * Pulls public key from key provider and verifies the JET sing the signature
	 * @param jwt
	 * @return
	 */
	public DecodedJWT verifyJwt(String jwt) throws MalformedURLException, JwkException {

		Algorithm algorithm = tokenKeyService.getAlgorithm(jwt);

		return JWT.require(algorithm).build().verify(jwt);
	}

}
