package com.example.springsec.productapi;

import java.net.URI;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/products")
public class ProductApi {
	@Autowired ProductRepository repo;
	
	@GetMapping
	public List<Product> list(){
		
		return repo.findAll();
	}
	@PostMapping
	public ResponseEntity<Product> create(@RequestBody @Valid Product product){
		
		Product savedProduct = repo.save(product);
		URI productURI = URI.create("/products/" + savedProduct.getId());
		return ResponseEntity.created(productURI).body(savedProduct);
		
	}
	
//	@GetMapping("/{id}")
//	public Product product() {
//		
//		return repo.getById(product.id);
//	}
//	

}
