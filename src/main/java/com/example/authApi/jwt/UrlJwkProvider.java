package com.example.authApi.jwt;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.SigningKeyNotFoundException;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;

public class UrlJwkProvider implements JwkProvider {

    static final String DISPATCHER_JWKS_PATH = "/api/dispatcher/.well-known/jwks.json";
    static final String OIDC_JWKS_PATH = "/api/oidcprovider/jwk";
    static final String WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json";

    public final URL url;
    private final Integer connectTimeout;
    private final Integer readTimeout;

    /**
     * Creates a provider that loads from the given URL
     *
     * @param url to load the jwks
     */
    public UrlJwkProvider(URL url) {
        this(url, null, null);
    }

    /**
     * Creates a provider that loads from the given URL
     *
     * @param url            to load the jwks
     * @param connectTimeout connection timeout in milliseconds (null for default)
     * @param readTimeout    read timeout in milliseconds (null for default)
     */
    public UrlJwkProvider(URL url, Integer connectTimeout, Integer readTimeout) {
        checkArgument(url != null, "A non-null url is required");
        checkArgument(connectTimeout == null || connectTimeout >= 0, "Invalid connect timeout value '" + connectTimeout + "'. Must be a non-negative integer.");
        checkArgument(readTimeout == null || readTimeout >= 0, "Invalid read timeout value '" + readTimeout + "'. Must be a non-negative integer.");

        this.url = url;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    /**
     * Creates a provider that loads from the given domain's well-known directory.
     * <br><br> It can be a url link 'https://samples.auth0.com' or just a domain 'samples.auth0.com'.
     * If the protocol (http or https) is not provided then https is used by default.
     * The default jwks path "/.well-known/jwks.json" is appended to the given string domain.
     * <br><br> For example, when the domain is "samples.auth0.com"
     * the jwks url that will be used is "https://samples.auth0.com/.well-known/jwks.json"
     * <br><br> Use {@link #UrlJwkProvider(URL)} if you need to pass a full URL.
     *
     * @param domain where jwks is published
     */
    public UrlJwkProvider(String domain) {
        this(urlForDomain(domain));
    }

    static URL urlForDomain(String domain) {
        checkArgument(!isNullOrEmpty(domain), "A domain is required");

        if (!domain.startsWith("http")) {
            domain = "https://" + domain;
        }

        try {
            final URL url = new URL(domain);
            if (domain.contains("oidcprovider")) {
            	return new URL(url, OIDC_JWKS_PATH);
            } else if (domain.contains("dispatcher")) {
            	return new URL(url, DISPATCHER_JWKS_PATH);
            } else {
            	return new URL(url, WELL_KNOWN_JWKS_PATH);
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid jwks uri", e);
        }
    }

    private Map<String, Object> getJwks() throws SigningKeyNotFoundException {
    	final JsonFactory factory = new JsonFactory();
    	InputStream inputStream = null;
    	try {
            final URLConnection c = this.url.openConnection();
            if (connectTimeout != null) {
                c.setConnectTimeout(connectTimeout);
            }
            if (readTimeout != null) {
                c.setReadTimeout(readTimeout);
            }
            inputStream = c.getInputStream();
            
            try(final JsonParser parser = factory.createParser(inputStream)) {
            	final TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {
                };
            	return new ObjectMapper().reader().readValue(parser, typeReference);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
        } catch (IOException e) {
            throw new SigningKeyNotFoundException("Cannot obtain jwks from url " + url.toString(), e);
        }
    }

    private List<Jwk> getAll() throws SigningKeyNotFoundException {
        List<Jwk> jwks = Lists.newArrayList();
        @SuppressWarnings("unchecked") final List<Map<String, Object>> keys = (List<Map<String, Object>>) getJwks().get("keys");

        if (keys == null || keys.isEmpty()) {
            throw new SigningKeyNotFoundException("No keys found in " + url.toString(), null);
        }

        try {
            for (Map<String, Object> values : keys) {
                jwks.add(fromValues(values));
            }
        } catch (IllegalArgumentException e) {
            throw new SigningKeyNotFoundException("Failed to parse jwk from json", e);
        }
        return jwks;
    }

    @Override
    public Jwk get(String keyId) throws JwkException {
        final List<Jwk> jwks = getAll();
        if (keyId == null && jwks.size() == 1) {
            return jwks.get(0);
        }
        if (keyId != null) {
            for (Jwk jwk : jwks) {
                if (keyId.equals(jwk.getId())) {
                    return jwk;
                }
            }
        }
        throw new SigningKeyNotFoundException("No key found in " + url.toString() + " with kid " + keyId, null);
    }
    
    @SuppressWarnings("unchecked")
    protected static Jwk fromValues(Map<String, Object> map) {
        Map<String, Object> values = Maps.newHashMap(map);
        String kid = (String) values.remove("kid");
        String kty = (String) values.remove("kty");
        String alg = (String) values.remove("alg");
        String use = (String) values.remove("use");
        Object keyOps = values.remove("key_ops");
        String x5u = (String) values.remove("x5u");
        List<String> x5c = (List<String>) values.remove("x5c");
        String x5t = (String) values.remove("x5t");
        if (kty == null) {
            throw new IllegalArgumentException("Attributes " + map + " are not from a valid jwk");
        }
        if(keyOps instanceof String) {
            return new Jwk(kid, kty, alg, use, (String) keyOps, x5u, x5c, x5t, values);
        } else {
            return new Jwk(kid, kty, alg, use, (List<String>) keyOps, x5u, x5c, x5t, values);
        }
    }
}