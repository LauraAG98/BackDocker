package com.example.adso.config;

import com.example.adso.model.Role;
import com.example.adso.model.User;
import com.example.adso.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuración de Beans de la aplicación.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    /**
     * Define cómo Spring Security debe cargar los detalles de un usuario.
     * Le decimos que use nuestro UserRepository.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
    }

    /**
     * Define el "Proveedor de Autenticación".
     * Le decimos que use nuestro UserDetailsService y el PasswordEncoder.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder()); // Usa el encriptador de contraseñas
        return authProvider;
    }

    /**
     * Define el gestor de autenticación que usará el AuthService.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Define el encriptador de contraseñas (BCrypt).
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * (IMPORTANTE) Crea el usuario ADMIN al iniciar la aplicación.
     * Como el ADMIN solo tiene login (no registro), lo creamos aquí.
     */
    @Bean
    public CommandLineRunner createAdminUser(PasswordEncoder passwordEncoder) {
        return args -> {
            if (!userRepository.existsByUsername("admin")) {
                User adminUser = User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin123")) // Contraseña hardcodeada
                        .role(Role.ADMIN)
                        .build();
                userRepository.save(adminUser);
                System.out.println(">>> Usuario ADMIN creado (admin/admin123) <<<");
            }
        };
    }
}