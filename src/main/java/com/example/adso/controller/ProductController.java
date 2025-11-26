package com.example.adso.controller;

import com.example.adso.model.Product;
import com.example.adso.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    /**
     * Endpoint para obtener todos los productos.
     * Protegido: Requiere rol USER o ADMIN.
     */
    @GetMapping
    public ResponseEntity<Collection<Product>> getAllProducts() {
        return ResponseEntity.ok(productService.getAllProducts());
    }

    /**
     * Endpoint para crear un nuevo producto.
     * Protegido: Requiere rol ADMIN.
     */
    @PostMapping
    public ResponseEntity<Product> createProduct(@RequestBody Product product) {
        // (Aquí se podrían inicializar datos del producto o validar)
        Product newProduct = Product.builder()
                .name(product.getName())
                .price(product.getPrice())
                .stock(product.getStock())
                .build();
                
        return ResponseEntity.ok(productService.createProduct(newProduct));
    }
}
