package com.example.authApi.config;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.authApi.exception.CustomException;
import com.example.authApi.jwt.JwtSignService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author Jay Shan
 */
@Component
public class TokenAuthenticationProvider implements AuthenticationProvider {

    private static Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Autowired
    JwtSignService jwtSignService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {

            LOGGER.info("TokenAuthenticationProvider: authenticate");

            String token  = (String) authentication.getDetails();

            DecodedJWT decodedJWT = jwtSignService.verifyJwt(token);

            Claim subject = decodedJWT.getClaim("sub");

            Collection<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
            grantedAuthorities.add(new SimpleGrantedAuthority("user"));

            return new UsernamePasswordAuthenticationToken(subject.asString(), "", grantedAuthorities);

        } catch (Exception e) {
            throw new CustomException(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {

        LOGGER.info("TokenAuthenticationProvider: supports");

        //return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
        return true;
    }
}
