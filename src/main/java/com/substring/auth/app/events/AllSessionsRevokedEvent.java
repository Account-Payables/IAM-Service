package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class AllSessionsRevokedEvent extends AuthCoreEvent {

    public enum Reason {
        USER_REQUESTED, PASSWORD_CHANGED, SUSPICIOUS_ACTIVITY, ADMIN_ACTION
    }

    private final UUID userId;
    private final String email;
    private final Reason reason;
    private final int sessionsRevoked;

    public AllSessionsRevokedEvent(Object source, UUID userId, String email,
                                   Reason reason, int sessionsRevoked) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.reason = reason;
        this.sessionsRevoked = sessionsRevoked;
    }
}
