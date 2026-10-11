package com.substring.auth.app.auth.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "af_verification_tokens", indexes = {
        @Index(name = "idx_vt_token_hash", columnList = "tokenHash", unique = true),
        @Index(name = "idx_vt_user_type", columnList = "userId, type"),
        @Index(name = "idx_vt_expires", columnList = "expiresAt")
})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class VerificationToken {

    public enum Type { EMAIL_VERIFY, PASSWORD_RESET }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID userId;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Type type;

    @Column(nullable = false)
    private Instant expiresAt;

    private Instant usedAt;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isUsed() {
        return usedAt != null;
    }
}
