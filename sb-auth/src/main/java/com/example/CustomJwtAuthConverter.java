package com.example;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class CustomJwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    //this custom implementation changes default behaviour of converter. by default springboot takes
    //scope claim string, splits it up to array of string and add SCOPE_ prefix to each of them. And those are roles.
    //What i want is to have roles from realm_access and resource_access claim to be taken, and this is what this impl does

    @Override
    public AbstractAuthenticationToken convert(final @NonNull Jwt jwt) {
        final Map<String, List<String>> realmAccessClaim = jwt.getClaim("realm_access");
        final List<String> realmRoles = realmAccessClaim.get("roles");

        final var rolesAsString = new ArrayList<String>(realmRoles);

        final Map<String, Map<String, List<String>>> resourceAccessClaim = jwt.getClaim("resource_access");

        final var clientRoles = resourceAccessClaim.values().stream()
                .map(client -> client.get("roles"))
                .flatMap(List::stream)
                .toList();

        rolesAsString.addAll(clientRoles);

        final var roles = rolesAsString.stream().map(SimpleGrantedAuthority::new).toList();

        return new JwtAuthenticationToken(jwt, roles);
    }
}
