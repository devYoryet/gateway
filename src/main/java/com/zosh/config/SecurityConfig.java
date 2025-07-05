// ============================================================================
// GATEWAY - SecurityConfig.java CORREGIDO
// ============================================================================
package com.zosh.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

        @Value("${jwt.secret}")
        private String jwtSecret;

        @Bean
        public ReactiveJwtDecoder jwtDecoder() {
                SecretKeySpec secretKey = new SecretKeySpec(jwtSecret.getBytes(), "HmacSHA256");
                return NimbusReactiveJwtDecoder.withSecretKey(secretKey).build();
        }

        @Bean
        public Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
                JwtAuthenticationConverter authoritiesExtractor = new JwtAuthenticationConverter();
                return new ReactiveJwtAuthenticationConverterAdapter(authoritiesExtractor);
        }

        @Bean
        public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity serverHttpSecurity) {
                return serverHttpSecurity
                                .authorizeExchange(exchanges -> exchanges
                                                // ENDPOINTS PÚBLICOS
                                                .pathMatchers("/auth/**").permitAll()
                                                .pathMatchers("/actuator/**").permitAll()
                                                .pathMatchers("/health").permitAll()
                                                .pathMatchers("/test/**").permitAll()
                                                .pathMatchers("/error").permitAll()
                                                // 🚨 IMPORTANTE: Permitir preflight requests (OPTIONS)
                                                .pathMatchers("OPTIONS", "/**").permitAll()
                                                // Endpoints específicos que requieren roles
                                                .pathMatchers("/api/admin/**").hasRole("ADMIN")
                                                .pathMatchers("/api/bookings/salon-owner/**",
                                                                "/api/notifications/salon-owner/**",
                                                                "/api/service-offering/salon-owner/**")
                                                .hasRole("SALON_OWNER")
                                                // Todos los demás endpoints requieren autenticación
                                                .anyExchange().authenticated())
                                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                                                .jwt(jwtSpec -> jwtSpec
                                                                .jwtDecoder(jwtDecoder())
                                                                .jwtAuthenticationConverter(
                                                                                grantedAuthoritiesExtractor())))
                                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                                // 🚨 NO configurar CORS aquí - se maneja en application.yml
                                .build();
        }

        // 🚨 ELIMINAR cualquier corsConfigurationSource() del Gateway
        // La configuración CORS debe estar SOLO en application.yml
}