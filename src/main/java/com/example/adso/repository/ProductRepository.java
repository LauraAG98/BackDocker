package com.example.adso.repository;

import com.example.adso.model.Product;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Repository
public class ProductRepository {

    private final Map<Long, Product> products = new ConcurrentHashMap<>();
    private final AtomicLong idCounter = new AtomicLong();

    // Guardamos un producto. Si es nuevo, le asigna un ID.
    public Product save(Product product) {
        if (product.getId() == null) {
            product.setId(idCounter.incrementAndGet());
        }
        products.put(product.getId(), product);
        return product;
    }

    // Buscamos un producto por ID
    public Optional<Product> findById(Long id) {
        return Optional.ofNullable(products.get(id));
    }

    // Devolvemos todos los productos
    public Collection<Product> findAll() {
        return products.values();
    }
}
