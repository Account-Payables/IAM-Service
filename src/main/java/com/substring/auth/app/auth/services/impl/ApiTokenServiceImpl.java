package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.ApiToken;
import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.repositories.ApiTokenRepository;
import com.substring.auth.app.auth.repositories.UserRepository;
import com.substring.auth.app.auth.services.ApiTokenService;
import com.substring.auth.app.events.ApiTokenCreatedEvent;
import com.substring.auth.app.events.ApiTokenRevokedEvent;
import com.substring.auth.app.exceptions.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ApiTokenServiceImpl implements ApiTokenService {

    private static final String TOKEN_PREFIX = "ac_live_";
    private static final int TOKEN_RANDOM_BYTES = 36;
    private static final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private final ApiTokenRepository apiTokenRepository;
    private final UserRepository userRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public ApiTokenCreateResult create(UUID userId, String name, List<String> scopes, Instant expiresAt) {
        String rawToken = generateRawToken();
        String hash = sha256(rawToken);
        String prefix = rawToken.substring(0, Math.min(rawToken.length(), 12));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        ApiToken token = ApiToken.builder()
                .userId(userId)
                .name(name)
                .tokenHash(hash)
                .tokenPrefix(prefix)
                .scopes(scopes)
                .expiresAt(expiresAt)
                .build();

        ApiToken saved = apiTokenRepository.save(token);

        eventPublisher.publishEvent(new ApiTokenCreatedEvent(
                this, userId, user.getEmail(), saved.getId(),
                name, prefix, scopes, expiresAt
        ));

        return new ApiTokenCreateResult(saved, rawToken);
    }

    @Override
    public List<ApiToken> listByUser(UUID userId) {
        return apiTokenRepository.findByUserId(userId);
    }

    @Override
    public void revoke(UUID tokenId, UUID requestingUserId) {
        ApiToken token = apiTokenRepository.findById(tokenId)
                .orElseThrow(() -> new ResourceNotFoundException("API token not found"));

        // IDOR check: token must belong to requesting user
        if (!token.getUserId().equals(requestingUserId)) {
            throw new AccessDeniedException("Cannot revoke another user's API token");
        }

        token.setRevoked(true);
        apiTokenRepository.save(token);

        userRepository.findById(requestingUserId).ifPresent(user ->
                eventPublisher.publishEvent(new ApiTokenRevokedEvent(
                        this, requestingUserId, user.getEmail(),
                        tokenId, token.getName(), requestingUserId.toString()
                ))
        );
    }

    @Override
    public User authenticate(String rawToken) {
        return authenticateWithScopes(rawToken).user();
    }

    @Override
    public ApiTokenService.AuthResult authenticateWithScopes(String rawToken) {
        String hash = sha256(rawToken);
        ApiToken token = apiTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new BadCredentialsException("Invalid API token"));

        if (token.isRevoked()) {
            throw new BadCredentialsException("API token has been revoked");
        }
        if (token.isExpired()) {
            throw new BadCredentialsException("API token has expired");
        }

        token.setLastUsedAt(Instant.now());
        apiTokenRepository.save(token);

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new BadCredentialsException("Token owner not found"));

        List<String> scopes = token.getScopes() != null ? token.getScopes() : List.of();
        return new ApiTokenService.AuthResult(user, scopes);
    }

    private String generateRawToken() {
        byte[] bytes = new byte[TOKEN_RANDOM_BYTES];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(TOKEN_PREFIX);
        for (byte b : bytes) {
            sb.append(BASE62.charAt(Math.abs(b % BASE62.length())));
        }
        return sb.toString();
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
