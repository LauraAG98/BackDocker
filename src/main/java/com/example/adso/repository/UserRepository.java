package com.example.adso.repository;

import com.example.adso.model.User;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Repository
public class UserRepository {

    // Usamos ConcurrentHashMap para seguridad en hilos
    private final Map<String, User> userByUsername = new ConcurrentHashMap<>();
    private final Map<Long, User> userById = new ConcurrentHashMap<>();
    private final AtomicLong idCounter = new AtomicLong();

    // Guardamos un usuario. Si es nuevo, le asigna un ID.
    public User save(User user) {
        if (user.getId() == null) {
            user.setId(idCounter.incrementAndGet());
        }
        userByUsername.put(user.getUsername(), user);
        userById.put(user.getId(), user);
        return user;
    }

    // Buscamos un usuario por su nombre de usuario
    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(userByUsername.get(username));
    }

    // Verificamos si un nombre de usuario ya existe
    public boolean existsByUsername(String username) {
        return userByUsername.containsKey(username);
    }
}