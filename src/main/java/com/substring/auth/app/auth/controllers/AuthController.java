package com.substring.auth.app.auth.controllers;

import com.substring.auth.app.auth.payload.*;
import com.substring.auth.app.auth.services.AuthService;
import com.substring.auth.app.auth.services.VerificationTokenService;
import com.substring.auth.app.auth.services.impl.CookieService;
import com.substring.auth.app.auth.services.impl.JwtService;
import com.substring.auth.app.core.context.AuthContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final VerificationTokenService verificationTokenService;
    private final JwtService jwtService;
    private final CookieService cookieService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@Valid @RequestBody RegisterRequest request) {
        UserDto dto = new UserDto();
        dto.setEmail(request.getEmail());
        dto.setPassword(request.getPassword());
        dto.setName(request.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(dto));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest,
                                               HttpServletRequest request,
                                               HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(
                loginRequest.email(), loginRequest.password(), request, response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = readRefreshToken(body, request)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token is missing"));
        return ResponseEntity.ok(authService.refreshTokens(refreshToken, request, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = readRefreshToken(null, request).orElse(null);
        authService.logout(refreshToken, response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, Object>> logoutAll(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = readRefreshToken(null, request).orElse(null);
        authService.logoutAll(refreshToken, response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("message", "All sessions terminated"));
    }

    // Email Verification
    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam String token) {
        verificationTokenService.verifyEmail(token);
        return ResponseEntity.ok(Map.of("message", "Email verified successfully. You can now login."));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerification(@RequestBody EmailRequest request) {
        verificationTokenService.createAndSendEmailVerification(request.getEmail());
        return ResponseEntity.ok(Map.of("message", "Verification email sent (if account exists and is unverified)."));
    }

    // Password Reset
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody EmailRequest request) {
        verificationTokenService.createAndSendPasswordReset(request.getEmail());
        // Always same response — no enumeration
        return ResponseEntity.ok(Map.of("message", "If that email is registered, a reset link has been sent."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        verificationTokenService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(Map.of("message", "Password reset successful. Please login with your new password."));
    }

    @PatchMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        String userId = AuthContext.getCurrentUserId().toString();
        verificationTokenService.changePassword(userId, request.getCurrentPassword(), request.getNewPassword());
        return ResponseEntity.ok(Map.of("message", "Password changed. All other sessions have been logged out."));
    }

    private Optional<String> readRefreshToken(RefreshTokenRequest body, HttpServletRequest request) {
        if (request.getCookies() != null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();
            if (fromCookie.isPresent()) return fromCookie;
        }

        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader != null && !refreshHeader.isBlank()) return Optional.of(refreshHeader.trim());

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String candidate = authHeader.substring(7).trim();
            if (!candidate.isEmpty()) {
                try {
                    if (jwtService.isRefreshToken(candidate)) return Optional.of(candidate);
                } catch (Exception ignored) {}
            }
        }

        return Optional.empty();
    }

    @Getter @Setter
    public static class EmailRequest {
        @Email @NotBlank
        private String email;
    }

    @Getter @Setter
    public static class ResetPasswordRequest {
        @NotBlank
        private String token;
        @NotBlank @Size(min = 8, max = 128)
        private String newPassword;
    }

    @Getter @Setter
    public static class ChangePasswordRequest {
        @NotBlank
        private String currentPassword;
        @NotBlank @Size(min = 8, max = 128)
        private String newPassword;
    }
}
