package com.substring.auth.app.events;

import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

@Getter
public class AccountLockedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String ipAddress;
    private final Instant lockedUntil;
    private final int failedAttempts;

    public AccountLockedEvent(Object source, UUID userId, String email,
                              String ipAddress, Instant lockedUntil, int failedAttempts) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.ipAddress = ipAddress;
        this.lockedUntil = lockedUntil;
        this.failedAttempts = failedAttempts;
    }
}
