package com.example.adso.config;

import com.example.adso.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro que se ejecuta una vez por cada petición.
 * Se encarga de validar el token JWT y establecer la autenticación.
 */
@Component
@RequiredArgsConstructor // Inyecta las dependencias finales
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; // Implementación de Spring Security

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Obtenemos el encabezado "Authorization"
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // 2. Verificamos si el encabezado es nulo o no empieza con "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // Continuamos con el siguiente filtro
            return;
        }

        // 3. Extraemos el token (después de "Bearer ")
        jwt = authHeader.substring(7);

        // 4. Extraemos el nombre de usuario del token
        username = jwtService.extractUsername(jwt);

        // 5. Verificamos si el usuario no está ya autenticado en el contexto de seguridad
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Cargamos los detalles del usuario desde nuestra implementación (ApplicationConfig)
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // 6. Validamos el token
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Creamos un token de autenticación
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // No usamos credenciales (password) aquí
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // 7. Establecemos la autenticación en el Contexto de Seguridad
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 8. Continuamos con el siguiente filtro
        filterChain.doFilter(request, response);
    }
}