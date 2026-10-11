package com.substring.auth.app.events;

import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

@Getter
public class PasswordResetRequestedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String name;
    private final String resetToken;
    private final String resetLink;
    private final Instant expiresAt;

    public PasswordResetRequestedEvent(Object source, UUID userId, String email, String name,
                                       String resetToken, String resetLink, Instant expiresAt) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.name = name;
        this.resetToken = resetToken;
        this.resetLink = resetLink;
        this.expiresAt = expiresAt;
    }
}
