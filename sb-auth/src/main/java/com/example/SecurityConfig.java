package com.example;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomJwtAuthConverter customJwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // OAuth2ResourceServerConfigurer::jwt is deprecated therefore i used withDefaults, but withDefaults is ok only
                //when we do not care about authorization using roles from token, if we care though then we need to
                //implement custom converter -> CustomJwtAuthConverter
                //.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                //.oauth2ResourceServer(Customizer.withDefaults())
                .oauth2ResourceServer(it -> it.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(customJwtAuthConverter)))

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    // Worth to add is that in keycloak user has role named ROLE_CUSTOM but for @PreAuthorize and @RolesAllowed
    // I'm adding role "CUSTOM" it's because of default implementation of DefaultMethodSecurityExpressionHandler which
    // add prefix ROLE_ to existing role name defined on method and then makes comparison. To change that
    // stupid behaviour I need to modify DefaultMethodSecurityExpressionHandler, After it i have same mapping in keycloak and app
    @Bean
    public DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler() {
        final var defaultMethodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        defaultMethodSecurityExpressionHandler.setDefaultRolePrefix("");
        return defaultMethodSecurityExpressionHandler;
    }
}