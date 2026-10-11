package com.substring.auth.app.events;

import com.substring.auth.app.auth.entities.UserStatus;
import lombok.Getter;

import java.util.UUID;

@Getter
public class UserStatusChangedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final UserStatus previousStatus;
    private final UserStatus newStatus;
    private final UUID changedByUserId;

    public UserStatusChangedEvent(Object source, UUID userId, String email,
                                  UserStatus previousStatus, UserStatus newStatus, UUID changedByUserId) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.previousStatus = previousStatus;
        this.newStatus = newStatus;
        this.changedByUserId = changedByUserId;
    }
}
