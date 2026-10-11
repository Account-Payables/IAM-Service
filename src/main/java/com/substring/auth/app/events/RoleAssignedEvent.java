package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class RoleAssignedEvent extends AuthCoreEvent {

    private final UUID userId;
    private final String email;
    private final String roleName;
    private final UUID assignedByUserId;
    private final String orgId;

    public RoleAssignedEvent(Object source, UUID userId, String email,
                             String roleName, UUID assignedByUserId, String orgId) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.roleName = roleName;
        this.assignedByUserId = assignedByUserId;
        this.orgId = orgId;
    }
}
