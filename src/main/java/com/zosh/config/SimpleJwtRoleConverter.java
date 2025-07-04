package com.zosh.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * CONVERTIDOR PARA JWT SIMPLE (ACTUAL)
 * Extrae roles del JWT simple que generas en tu aplicación
 */
public class SimpleJwtRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        // ===========================================
        // JWT SIMPLE: Extraer rol del claim "role"
        // ===========================================
        String role = jwt.getClaimAsString("role");
        if (role != null && !role.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
        }

        // ===========================================
        // JWT SIMPLE: Extraer roles múltiples si los tienes
        // ===========================================
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null && !roles.isEmpty()) {
            roles.forEach(r -> 
                authorities.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
            );
        }

        // ===========================================
        // JWT SIMPLE: Extraer authorities si los tienes
        // ===========================================
        List<String> auths = jwt.getClaimAsStringList("authorities");
        if (auths != null && !auths.isEmpty()) {
            auths.forEach(auth -> 
                authorities.add(new SimpleGrantedAuthority(auth))
            );
        }

        // ===========================================
        // FALLBACK: Si no hay roles, asignar por defecto
        // ===========================================
        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_CUSTOMER"));
        }

        return authorities;
    }
}

/*
===========================================
ESTRUCTURA ESPERADA DE TU JWT SIMPLE:
===========================================
{
  "sub": "user@example.com",
  "email": "user@example.com", 
  "role": "SALON_OWNER",
  "roles": ["SALON_OWNER", "CUSTOMER"],
  "authorities": ["ROLE_SALON_OWNER"],
  "exp": 1234567890,
  "iat": 1234567890
}

Este convertidor buscará:
1. "role" (string único)
2. "roles" (array de strings)
3. "authorities" (array de strings)
*/