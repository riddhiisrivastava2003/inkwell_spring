package com.inkwell.auth_service.controller;

import com.inkwell.auth_service.audit.AuditLog;
import com.inkwell.auth_service.audit.AuditLogService;
import com.inkwell.auth_service.dto.*;
import com.inkwell.auth_service.model.User;
import com.inkwell.auth_service.model.UserRole;
import com.inkwell.auth_service.repository.UserRepository;
import com.inkwell.auth_service.service.AuthService;
import io.jsonwebtoken.impl.DefaultClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditLogService auditLogService;

    @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
    private WebClient webClient;

    @InjectMocks
    private AuthController authController;

    @Test
    void register() {
        RegisterRequest req = new RegisterRequest();
        AuthResponse resp = AuthResponse.builder().email("test@test.com").build();
        when(authService.register(any())).thenReturn(resp);
        
        ResponseEntity<AuthResponse> res = authController.register(req);
        assertEquals("test@test.com", res.getBody().getEmail());
    }

    @Test
    void registerAdmin() {
        RegisterRequest req = new RegisterRequest();
        AuthResponse resp = AuthResponse.builder().email("admin@test.com").build();
        when(authService.registerAdmin(any())).thenReturn(resp);
        
        ResponseEntity<AuthResponse> res = authController.registerAdmin(req);
        assertEquals("admin@test.com", res.getBody().getEmail());
    }

    @Test
    void login() {
        LoginRequest req = new LoginRequest();
        AuthResponse resp = AuthResponse.builder().email("login@test.com").build();
        when(authService.login(any())).thenReturn(resp);
        
        ResponseEntity<AuthResponse> res = authController.login(req);
        assertEquals("login@test.com", res.getBody().getEmail());
    }

    @Test
    void forgotPassword() {
        ForgotPasswordRequest req = new ForgotPasswordRequest();
        ResponseEntity<Map<String, String>> res = authController.forgotPassword(req);
        verify(authService).requestPasswordReset(req);
        assertNotNull(res.getBody());
    }

    @Test
    void resetPassword() {
        ResetPasswordRequest req = new ResetPasswordRequest();
        ResponseEntity<Map<String, String>> res = authController.resetPassword(req);
        verify(authService).resetPassword(req);
        assertNotNull(res.getBody());
    }

    @Test
    void validate() {
        io.jsonwebtoken.Claims claims = mock(io.jsonwebtoken.Claims.class);
        when(claims.get("userId")).thenReturn(1L);
        when(claims.getSubject()).thenReturn("test@test.com");
        when(claims.get("role")).thenReturn("AUTHOR");
        
        when(authService.validateToken("token123")).thenReturn(claims);
        ResponseEntity<Map<String, Object>> res = authController.validate("token123", null);
        assertEquals(1L, res.getBody().get("userId"));
        assertEquals("test@test.com", res.getBody().get("email"));
    }

    @Test
    void users() {
        when(authService.getAll()).thenReturn(List.of(UserResponse.builder().id(1L).build()));
        ResponseEntity<List<UserResponse>> res = authController.users();
        assertEquals(1, res.getBody().size());
    }

    @Test
    void search() {
        when(authService.searchUsers("test")).thenReturn(List.of(UserResponse.builder().id(1L).build()));
        ResponseEntity<List<UserResponse>> res = authController.search("test");
        assertEquals(1, res.getBody().size());
    }

    @Test
    void userById() {
        when(authService.getById(1L)).thenReturn(UserResponse.builder().id(1L).build());
        ResponseEntity<UserResponse> res = authController.userById(1L);
        assertEquals(1L, res.getBody().getId());
    }

    @Test
    void usersByRole() {
        when(authService.usersByRole(UserRole.AUTHOR)).thenReturn(List.of(UserResponse.builder().id(1L).build()));
        ResponseEntity<List<UserResponse>> res = authController.usersByRole(UserRole.AUTHOR);
        assertEquals(1, res.getBody().size());
    }

    @Test
    void updateProfile() {
        UpdateProfileRequest req = new UpdateProfileRequest();
        when(authService.updateProfile(1L, req)).thenReturn(UserResponse.builder().id(1L).build());
        ResponseEntity<UserResponse> res = authController.updateProfile(1L, req);
        assertEquals(1L, res.getBody().getId());
    }

    @Test
    void changePassword() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        ResponseEntity<Map<String, String>> res = authController.changePassword(1L, req);
        verify(authService).changePassword(1L, req);
        assertNotNull(res.getBody());
    }

    @Test
    void changeRole() {
        ChangeRoleRequest req = new ChangeRoleRequest();
        when(authService.changeRole(1L, req, 2L)).thenReturn(UserResponse.builder().id(1L).build());
        ResponseEntity<UserResponse> res = authController.changeRole(1L, 2L, req);
        assertEquals(1L, res.getBody().getId());
    }

    @Test
    void setStatus() {
        when(authService.setActive(1L, true, 2L)).thenReturn(UserResponse.builder().id(1L).build());
        ResponseEntity<UserResponse> res = authController.setStatus(1L, true, 2L);
        assertEquals(1L, res.getBody().getId());
    }

    @Test
    void deleteUser() {
        ResponseEntity<Map<String, String>> res = authController.deleteUser(1L, 2L);
        verify(authService).deleteUser(1L, 2L);
        assertNotNull(res.getBody());
    }

    @Test
    void follow() {
        when(authService.follow(2L, 1L)).thenReturn(Map.of("following", true));
        ResponseEntity<Map<String, Object>> res = authController.follow(1L, 2L);
        assertTrue((Boolean) res.getBody().get("following"));
    }

    @Test
    void unfollow() {
        when(authService.unfollow(2L, 1L)).thenReturn(Map.of("following", false));
        ResponseEntity<Map<String, Object>> res = authController.unfollow(1L, 2L);
        assertFalse((Boolean) res.getBody().get("following"));
    }

    @Test
    void internalAuditLog() {
        AuditLogRequest req = new AuditLogRequest();
        req.setActorUserId(1L);
        ResponseEntity<Map<String, String>> res = authController.internalAuditLog(req);
        verify(auditLogService).log(eq(1L), any(), any(), any(), any());
        assertNotNull(res.getBody());
    }
}
