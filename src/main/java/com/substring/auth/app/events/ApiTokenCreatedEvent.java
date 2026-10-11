package com.substring.auth.app.events;

import lombok.Getter;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Getter
public class ApiTokenCreatedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final UUID tokenId;
    private final String tokenName;
    private final String tokenPrefix;
    private final List<String> scopes;
    private final Instant expiresAt;

    public ApiTokenCreatedEvent(Object source, UUID userId, String email, UUID tokenId,
                                String tokenName, String tokenPrefix, List<String> scopes, Instant expiresAt) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.tokenId = tokenId;
        this.tokenName = tokenName;
        this.tokenPrefix = tokenPrefix;
        this.scopes = scopes;
        this.expiresAt = expiresAt;
    }
}
