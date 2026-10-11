package com.substring.auth.app.events;

import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

@Getter
public class EmailVerificationRequestedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String name;
    private final String verificationToken;
    private final String verificationLink;
    private final Instant expiresAt;

    public EmailVerificationRequestedEvent(Object source, UUID userId, String email, String name,
                                           String verificationToken, String verificationLink, Instant expiresAt) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.name = name;
        this.verificationToken = verificationToken;
        this.verificationLink = verificationLink;
        this.expiresAt = expiresAt;
    }
}
