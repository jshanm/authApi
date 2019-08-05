package com.example.authApi.config;


import com.example.authApi.exception.CustomException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.invoke.MethodHandles;

/**
 * @author Jay Shan
 */
public class JwtTokenFilter extends OncePerRequestFilter{


    private static Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());


    private AuthenticationManager authenticationManager;

    public JwtTokenFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;

    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        LOGGER.info("Authenticating for path {}", request.getRequestURI());

        String token = resolveToken(request);
        try {

            Authentication authentication = new UsernamePasswordAuthenticationToken("dummy", token);

            Authentication updatedAuthentication = authenticationManager.authenticate(authentication);

            LOGGER.info("Token validation success");
            SecurityContextHolder.getContext().setAuthentication(updatedAuthentication);

        } catch (CustomException ex) {
            SecurityContextHolder.clearContext();

            LOGGER.error("Error in Authorizing request: {}, the exception is {}",request.getRequestURI(),  ex.getMessage());

            response.sendError(ex.getHttpStatus().value(), ex.getMessage());
            return;
        }
        filterChain.doFilter(request, response);
    }

    public String resolveToken(HttpServletRequest request) {

        //TODO: Need to decide where token is extracted from (may be Auhorization header: Bearer)
        return request.getHeader("x-eis-access");
    }
}
