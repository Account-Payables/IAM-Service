package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class SuspiciousActivityEvent extends AuthCoreEvent {

    public enum ActivityType {
        REFRESH_TOKEN_REUSE,
        LOGIN_FROM_NEW_LOCATION,
        LOGIN_AFTER_LONG_INACTIVITY
    }

    private final UUID userId;
    private final String email;
    private final ActivityType type;
    private final String ipAddress;
    private final String details;
    private final boolean allSessionsRevoked;

    public SuspiciousActivityEvent(Object source, UUID userId, String email, ActivityType type,
                                   String ipAddress, String details, boolean allSessionsRevoked) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.type = type;
        this.ipAddress = ipAddress;
        this.details = details;
        this.allSessionsRevoked = allSessionsRevoked;
    }
}
