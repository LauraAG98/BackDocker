package com.example.adso.service;


import com.example.adso.model.Role;
import com.example.adso.model.User;
import com.example.adso.dto.AuthResponse;
import com.example.adso.dto.LoginRequest;
import com.example.adso.dto.RegisterRequest;
import com.example.adso.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // Para encriptar la contraseña
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager; // Para gestionar la autenticación

    /**
     * Registra un nuevo usuario (solo rol USER).
     */
    public AuthResponse register(RegisterRequest request) {
        // Verificamos si el usuario ya existe
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Error: El nombre de usuario ya está en uso.");
        }

        // Creamos el nuevo usuario
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword())) // Encriptamos la contraseña
                .role(Role.USER) // Todos los registros son como USER
                .build();

        // Guardamos el usuario en el "repositorio" en memoria
        userRepository.save(user);

        // Generamos el token JWT
        String jwtToken = jwtService.generateToken(user);

        // Devolvemos la respuesta con el token
        return AuthResponse.builder().token(jwtToken).build();
    }

    /**
     * Autentica un usuario (USER o ADMIN) y devuelve un token.
     */
    public AuthResponse login(LoginRequest request) {
        // Spring Security (AuthenticationManager) se encarga de verificar si el usuario
        // y la contraseña son correctos (usando el UserDetailsService y PasswordEncoder)
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        // Si la autenticación fue exitosa, buscamos al usuario
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        // Generamos el token JWT
        String jwtToken = jwtService.generateToken(user);

        // Devolvemos la respuesta con el token
        return AuthResponse.builder().token(jwtToken).build();
    }
}