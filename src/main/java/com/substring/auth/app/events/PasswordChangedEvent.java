package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class PasswordChangedEvent extends AuthCoreEvent {

    public enum Source { RESET_FLOW, USER_INITIATED }

    private final UUID userId;
    private final String email;
    private final Source source;
    private final String ipAddress;

    public PasswordChangedEvent(Object source, UUID userId, String email, Source changeSource, String ipAddress) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.source = changeSource;
        this.ipAddress = ipAddress;
    }
}
