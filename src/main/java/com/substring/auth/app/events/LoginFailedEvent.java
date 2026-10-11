package com.substring.auth.app.events;

import lombok.Getter;

@Getter
public class LoginFailedEvent extends AuthCoreEvent {

    public enum Reason {
        INVALID_CREDENTIALS, ACCOUNT_LOCKED, ACCOUNT_DISABLED,
        EMAIL_NOT_VERIFIED, ACCOUNT_NOT_FOUND
    }

    private final String attemptedEmail;
    private final Reason reason;
    private final String ipAddress;
    private final int currentAttemptCount;
    private final int lockThreshold;

    public LoginFailedEvent(Object source, String attemptedEmail, Reason reason,
                            String ipAddress, int currentAttemptCount, int lockThreshold) {
        super(source);
        this.attemptedEmail = attemptedEmail;
        this.reason = reason;
        this.ipAddress = ipAddress;
        this.currentAttemptCount = currentAttemptCount;
        this.lockThreshold = lockThreshold;
    }
}
