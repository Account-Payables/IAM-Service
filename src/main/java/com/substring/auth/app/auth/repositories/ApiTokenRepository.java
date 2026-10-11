package com.substring.auth.app.auth.repositories;

import com.substring.auth.app.auth.entities.ApiToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApiTokenRepository extends JpaRepository<ApiToken, UUID> {
    Optional<ApiToken> findByTokenHash(String tokenHash);
    List<ApiToken> findByUserIdAndRevokedFalse(UUID userId);
    List<ApiToken> findByUserId(UUID userId);
}
