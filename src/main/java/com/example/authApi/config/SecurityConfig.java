package com.example.authApi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;


/**
 * @author Jay Shan
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${username}")
    private String username;

    @Value("${password}")
    private String password;

    @Autowired
    PathConfig pathConfig;

    @Autowired
    AuthenticationProvider tokenAuthenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests()
                .anyRequest()
                .authenticated();

        http.addFilterBefore(tokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) {

        web.ignoring()
                .antMatchers(pathConfig.getExclude().toArray(new String[pathConfig.getExclude().size()]));
    }

    private GenericFilterBean tokenFilter() throws Exception {
        return new JwtTokenFilter(authenticationManager());
    }


    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

     @Override
    protected void configure(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(tokenAuthenticationProvider);

     }


}
