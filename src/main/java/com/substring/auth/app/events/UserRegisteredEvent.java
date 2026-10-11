package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class UserRegisteredEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String name;
    private final boolean emailVerificationRequired;

    public UserRegisteredEvent(Object source, UUID userId, String email, String name, boolean emailVerificationRequired) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.name = name;
        this.emailVerificationRequired = emailVerificationRequired;
    }
}
