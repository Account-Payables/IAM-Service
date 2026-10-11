package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class EmailVerifiedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;

    public EmailVerifiedEvent(Object source, UUID userId, String email) {
        super(source);
        this.userId = userId;
        this.email = email;
    }
}
