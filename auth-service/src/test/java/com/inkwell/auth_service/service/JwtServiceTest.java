package com.inkwell.auth_service.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        // 256-bit key for HMAC-SHA
        String secret = "Yn2kjibddFAWtnPJ2AFlL8WXpoujmE3NWuzsP9XQyYM="; 
        long expirationMs = 3600000; // 1 hour
        
        ReflectionTestUtils.setField(jwtService, "secret", secret);
        ReflectionTestUtils.setField(jwtService, "expirationMs", expirationMs);
    }

    @Test
    void generateAndValidateToken() {
        String token = jwtService.generateToken(1L, "test@test.com", "AUTHOR");
        assertNotNull(token);

        Claims claims = jwtService.validateToken(token);
        assertEquals("test@test.com", claims.getSubject());
        assertEquals(1, claims.get("userId", Integer.class).longValue());
        assertEquals("AUTHOR", claims.get("role", String.class));
    }
}
