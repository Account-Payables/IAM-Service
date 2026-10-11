package com.substring.auth.app.auth.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "af_api_tokens", indexes = {
        @Index(name = "idx_at_token_hash", columnList = "tokenHash", unique = true),
        @Index(name = "idx_at_user", columnList = "userId"),
        @Index(name = "idx_at_revoked", columnList = "revoked")
})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ApiToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID userId;

    @Column(nullable = false, length = 200)
    private String name;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(nullable = false, length = 20)
    private String tokenPrefix;

    @ElementCollection
    @CollectionTable(name = "af_api_token_scopes", joinColumns = @JoinColumn(name = "token_id"))
    @Column(name = "scope")
    private List<String> scopes;

    @Column(nullable = false)
    private boolean revoked = false;

    private Instant lastUsedAt;

    @Column(length = 45)
    private String lastUsedIp;

    private Instant expiresAt;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }
}
