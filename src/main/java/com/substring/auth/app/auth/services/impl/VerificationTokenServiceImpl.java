package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.entities.UserStatus;
import com.substring.auth.app.auth.entities.VerificationToken;
import com.substring.auth.app.auth.repositories.RefreshTokenRepository;
import com.substring.auth.app.auth.repositories.UserRepository;
import com.substring.auth.app.auth.repositories.VerificationTokenRepository;
import com.substring.auth.app.auth.services.VerificationTokenService;
import com.substring.auth.app.core.config.AuthCoreProperties;
import com.substring.auth.app.events.*;
import com.substring.auth.app.exceptions.ResourceNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VerificationTokenServiceImpl implements VerificationTokenService {

    private final VerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final AuthCoreProperties properties;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    private void validatePasswordComplexity(String password) {
        AuthCoreProperties.Password cfg = properties.getPassword();
        if (password.length() < cfg.getMinLength() || password.length() > cfg.getMaxLength())
            throw new IllegalArgumentException(
                    "Password must be between " + cfg.getMinLength() + " and " + cfg.getMaxLength() + " characters");
        if (cfg.isRequireUppercase() && password.chars().noneMatch(Character::isUpperCase))
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        if (cfg.isRequireDigit() && password.chars().noneMatch(Character::isDigit))
            throw new IllegalArgumentException("Password must contain at least one digit");
        if (cfg.isRequireSpecialChar() && password.chars().noneMatch(c -> "!@#$%^&*()_+-=[]{}|;':\",./<>?".indexOf(c) >= 0))
            throw new IllegalArgumentException("Password must contain at least one special character");
    }

    @Override
    @Transactional
    public void createAndSendEmailVerification(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Invalidate any previous tokens
        tokenRepository.invalidatePreviousTokens(user.getId(), VerificationToken.Type.EMAIL_VERIFY);

        String rawToken = generateToken();
        String hash = sha256(rawToken);
        int expiryHours = properties.getEmailVerification().getTokenExpiryHours();
        Instant expiresAt = Instant.now().plusSeconds(expiryHours * 3600L);

        tokenRepository.save(VerificationToken.builder()
                .userId(user.getId())
                .tokenHash(hash)
                .type(VerificationToken.Type.EMAIL_VERIFY)
                .expiresAt(expiresAt)
                .build());

        String verificationLink = properties.getBaseUrl() + "/api/v1/auth/verify-email?token=" + rawToken;

        eventPublisher.publishEvent(new EmailVerificationRequestedEvent(
                this, user.getId(), user.getEmail(), user.getName(),
                rawToken, verificationLink, expiresAt
        ));
    }

    @Override
    @Transactional
    public void verifyEmail(String rawToken) {
        String hash = sha256(rawToken);
        VerificationToken token = tokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new BadCredentialsException("Invalid or expired verification link"));

        if (token.isUsed()) throw new BadCredentialsException("Verification link has already been used");
        if (token.isExpired()) throw new BadCredentialsException("Verification link has expired. Please request a new one.");
        if (token.getType() != VerificationToken.Type.EMAIL_VERIFY) throw new BadCredentialsException("Invalid token type");

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setStatus(UserStatus.ACTIVE);
        user.setEmailVerified(true);
        userRepository.save(user);

        eventPublisher.publishEvent(new EmailVerifiedEvent(this, user.getId(), user.getEmail()));
    }

    @Override
    @Transactional
    public void createAndSendPasswordReset(String email) {
        // Always return success — no enumeration
        userRepository.findByEmail(email).ifPresent(user -> {
            if (user.getStatus() != UserStatus.ACTIVE) return;

            tokenRepository.invalidatePreviousTokens(user.getId(), VerificationToken.Type.PASSWORD_RESET);

            String rawToken = generateToken();
            String hash = sha256(rawToken);
            Instant expiresAt = Instant.now().plusSeconds(3600); // 1 hour

            tokenRepository.save(VerificationToken.builder()
                    .userId(user.getId())
                    .tokenHash(hash)
                    .type(VerificationToken.Type.PASSWORD_RESET)
                    .expiresAt(expiresAt)
                    .build());

            String resetLink = properties.getBaseUrl() + "/reset-password?token=" + rawToken;

            eventPublisher.publishEvent(new PasswordResetRequestedEvent(
                    this, user.getId(), user.getEmail(), user.getName(),
                    rawToken, resetLink, expiresAt
            ));
        });
    }

    @Override
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        String hash = sha256(rawToken);
        VerificationToken token = tokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new BadCredentialsException("Invalid or expired reset link"));

        if (token.isUsed()) throw new BadCredentialsException("Reset link has already been used");
        if (token.isExpired()) throw new BadCredentialsException("Reset link has expired. Please request a new one.");
        if (token.getType() != VerificationToken.Type.PASSWORD_RESET) throw new BadCredentialsException("Invalid token type");

        validatePasswordComplexity(newPassword);

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke ALL sessions — force re-login on all devices
        refreshTokenRepository.revokeAllByUserId(user.getId());

        eventPublisher.publishEvent(new PasswordChangedEvent(
                this, user.getId(), user.getEmail(),
                PasswordChangedEvent.Source.RESET_FLOW, null
        ));
        eventPublisher.publishEvent(new AllSessionsRevokedEvent(
                this, user.getId(), user.getEmail(),
                AllSessionsRevokedEvent.Reason.PASSWORD_CHANGED, -1
        ));
    }

    @Override
    @Transactional
    public void changePassword(String userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new BadCredentialsException("Current password is incorrect");
        }

        validatePasswordComplexity(newPassword);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke all sessions
        refreshTokenRepository.revokeAllByUserId(user.getId());

        eventPublisher.publishEvent(new PasswordChangedEvent(
                this, user.getId(), user.getEmail(),
                PasswordChangedEvent.Source.USER_INITIATED, null
        ));
    }

    private String generateToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return String.format("%064x", new BigInteger(1, hash));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
