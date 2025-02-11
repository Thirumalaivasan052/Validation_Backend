package com.example.demo.security;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.example.demo.entity.Role;
import com.example.demo.repository.RoleRepository;

	@Component
	public class RoleInitilizer {

	    @Autowired
	    private RoleRepository roleRepository;

	    @PostConstruct
	    public void initRoles() {
	        if (!roleRepository.findByName("USER").isPresent()) {
	            Role userRole = new Role();
	            userRole.setName("USER");
	            roleRepository.save(userRole);
	        }
	        if (!roleRepository.findByName("ADMIN").isPresent()) {
	            Role adminRole = new Role();
	            adminRole.setName("ADMIN");
	            roleRepository.save(adminRole);
	        }
	    }
	}

