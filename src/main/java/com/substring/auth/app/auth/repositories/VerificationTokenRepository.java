package com.substring.auth.app.auth.repositories;

import com.substring.auth.app.auth.entities.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {
    Optional<VerificationToken> findByTokenHash(String tokenHash);

    @Modifying
    @Query("UPDATE VerificationToken t SET t.usedAt = CURRENT_TIMESTAMP WHERE t.userId = :userId AND t.type = :type AND t.usedAt IS NULL")
    void invalidatePreviousTokens(UUID userId, VerificationToken.Type type);
}
