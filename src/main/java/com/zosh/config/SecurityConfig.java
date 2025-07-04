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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

        // ===========================================
        // CONFIGURACIÓN ACTUAL: JWT SIMPLE (ACTIVO)
        // ===========================================
        @Value("${jwt.secret}")
        private String jwtSecret;

        @Bean
        public ReactiveJwtDecoder jwtDecoder() {
                // ===========================================
                // CONFIGURACIÓN ACTUAL: JWT SIMPLE (ACTIVO)
                // ===========================================
                SecretKeySpec secretKey = new SecretKeySpec(jwtSecret.getBytes(), "HmacSHA256");
                return NimbusReactiveJwtDecoder.withSecretKey(secretKey).build();

                // ===========================================
                // CONFIGURACIÓN FUTURA: AWS COGNITO (COMENTADO)
                // PARA ACTIVAR COGNITO: Comentar líneas de arriba y descomentar esta
                // ===========================================
                // return
                // NimbusReactiveJwtDecoder.withJwkSetUri("https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json").build();
        }

        @Bean
        public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity serverHttpSecurity) {
                serverHttpSecurity.authorizeExchange(
                                exchanges -> exchanges
                                                .pathMatchers("/auth/**").permitAll()
                                                .pathMatchers("/api/notifications/ws/**").permitAll()
                                                .pathMatchers("/actuator/**").permitAll()
                                                .pathMatchers(
                                                                "/api/salons/**",
                                                                "/api/categories/**",
                                                                "/api/notifications/**",
                                                                "/api/bookings/**",
                                                                "/api/payments/**",
                                                                "/api/service-offering/**",
                                                                "/api/users/**",
                                                                "/api/reviews/**")
                                                .hasAnyRole("CUSTOMER", "SALON_OWNER", "ADMIN")
                                                .pathMatchers("/api/categories/salon-owner/**",
                                                                "/api/notifications/salon-owner/**",
                                                                "/api/service-offering/salon-owner/**")
                                                .hasRole("SALON_OWNER")
                                                .anyExchange().authenticated())
                                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                                                .jwt(jwtSpec -> jwtSpec
                                                                .jwtDecoder(jwtDecoder())
                                                                .jwtAuthenticationConverter(
                                                                                grantedAuthoritiesExtractor())));

                serverHttpSecurity.csrf(ServerHttpSecurity.CsrfSpec::disable)
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

                return serverHttpSecurity.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(Arrays.asList(
                                "http://localhost:3000",
                                "http://localhost:5173",
                                "https://salon-booking-three.vercel.app"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
                JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

                // ===========================================
                // CONFIGURACIÓN ACTUAL: JWT SIMPLE (ACTIVO)
                // ===========================================
                jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new SimpleJwtRoleConverter());

                // ===========================================
                // CONFIGURACIÓN FUTURA: AWS COGNITO (COMENTADO)
                // PARA ACTIVAR COGNITO: Comentar línea de arriba y descomentar esta
                // ===========================================
                // jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new
                // CognitoRoleConverter());

                return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
        }
}