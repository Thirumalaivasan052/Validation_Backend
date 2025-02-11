package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.demo.security.JwtUtil;

import java.util.Set;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${role.admin}")
    private String roleAdmin;

    @Value("${role.user}")
    private String roleUser;

    @GetMapping("/protected-data")
    public ResponseEntity<String> getProtectedData(@RequestHeader(value = "Authorization", required = false) String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization header is missing or invalid");
        }

        String jwtToken = token.substring(7);
        try {
            if (!jwtUtil.isTokenValid(jwtToken)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid token or expired");
            }

            String username = jwtUtil.extractUsername(jwtToken);
            Set<String> roles = jwtUtil.extractRoles(jwtToken);

            if (roles.contains(roleAdmin)) {
                return ResponseEntity.ok("Welcome " + username + "! Here is the Admin-specific data.");
            } else if (roles.contains(roleUser)) {
                return ResponseEntity.ok("Welcome " + username + "! Here is the User-specific data.");
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied: You don't have the necessary role");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error processing token: " + ex.getMessage());
        }
    }
}
