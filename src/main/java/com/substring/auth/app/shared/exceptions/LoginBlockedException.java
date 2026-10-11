package com.substring.auth.app.shared.exceptions;

import lombok.Getter;

@Getter
public class LoginBlockedException extends RuntimeException {

    private final String errorCode;

    public LoginBlockedException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
