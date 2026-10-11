package com.substring.auth.app.events;

import lombok.Getter;

import java.util.UUID;

@Getter
public class LoginSuccessEvent extends AuthCoreEvent {

    public enum LoginMethod { PASSWORD, GOOGLE, GITHUB, FACEBOOK, API_TOKEN }

    private final UUID userId;
    private final String email;
    private final LoginMethod method;
    private final String ipAddress;
    private final String userAgent;
    private final boolean isNewDevice;

    public LoginSuccessEvent(Object source, UUID userId, String email, LoginMethod method,
                             String ipAddress, String userAgent, boolean isNewDevice) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.method = method;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.isNewDevice = isNewDevice;
    }
}
