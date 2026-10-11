package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class UserLoggedOutEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String sessionId;

    public UserLoggedOutEvent(Object source, UUID userId, String email, String sessionId) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.sessionId = sessionId;
    }
}
