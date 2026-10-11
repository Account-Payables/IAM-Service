package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class RoleRemovedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String roleName;
    private final UUID removedByUserId;
    private final String orgId;

    public RoleRemovedEvent(Object source, UUID userId, String email,
                            String roleName, UUID removedByUserId, String orgId) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.roleName = roleName;
        this.removedByUserId = removedByUserId;
        this.orgId = orgId;
    }
}
