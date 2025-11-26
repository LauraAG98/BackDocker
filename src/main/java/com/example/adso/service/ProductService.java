package com.example.adso.service;

import com.example.adso.model.Product;
import com.example.adso.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;

    /**
     * Devuelve todos los productos.
     */
    public Collection<Product> getAllProducts() {
        return productRepository.findAll();
    }

    /**
     * Crea un nuevo producto.
     */
    public Product createProduct(Product product) {
        // En una aplicación real, aquí validaríamos los datos del producto
        return productRepository.save(product);
    }
}
