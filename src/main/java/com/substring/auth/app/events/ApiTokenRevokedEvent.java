package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class ApiTokenRevokedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final UUID tokenId;
    private final String tokenName;
    private final String revokedByUserId;

    public ApiTokenRevokedEvent(Object source, UUID userId, String email,
                                UUID tokenId, String tokenName, String revokedByUserId) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.tokenId = tokenId;
        this.tokenName = tokenName;
        this.revokedByUserId = revokedByUserId;
    }
}
