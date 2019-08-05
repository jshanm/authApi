package com.example.authApi.jwt;

import com.auth0.jwk.JwkProvider;
import org.springframework.stereotype.Service;

@Service
public class JwkProviderBuilder {
	public JwkProvider build(String issuer) {
		return new UrlJwkProvider(issuer);
	}
}
