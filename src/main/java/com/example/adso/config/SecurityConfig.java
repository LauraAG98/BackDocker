package com.example.adso.config;

import lombok.RequiredArgsConstructor;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Configuración principal de Spring Security.
 * Define qué rutas están protegidas y cómo.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Deshabilitamos CSRF (Cross-Site Request Forgery) porque usamos JWT
                // (stateless)
                .csrf(csrf -> csrf.disable())

                // Definimos las reglas de autorización
                .authorizeHttpRequests(authz -> authz
                        // Endpoints públicos (registro y login)
                        .requestMatchers("/api/auth/**").permitAll()

                        // Endpoints de productos:
                        // Solo ADMIN puede crear productos (POST)
                        .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/products")
                        .hasAuthority(com.example.adso.model.Role.ADMIN.name())
                        // USER y ADMIN pueden ver productos (GET)
                        .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/products")
                        .hasAnyAuthority(com.example.adso.model.Role.ADMIN.name(),
                                com.example.adso.model.Role.USER.name())

                        // Todas las demás peticiones deben estar autenticadas
                        .anyRequest().authenticated())

                // Configuramos la gestión de sesiones como STATELESS (sin estado)
                // Spring Security no creará ni usará sesiones HTTP.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Definimos el proveedor de autenticación
                .authenticationProvider(authenticationProvider)

                // Añadimos nuestro filtro de JWT ANTES del filtro estándar de autenticación
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 1. CORREGIR EL ORIGEN: Debe ser solo el dominio del frontend.
        configuration.setAllowedOrigins(List.of("https://practica-frontend-pi.vercel.app"));

        // 2. Permitir los métodos
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // 3. Permitir las cabeceras (esencial para JWT)
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        // Permitir credenciales si fuera necesario
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}