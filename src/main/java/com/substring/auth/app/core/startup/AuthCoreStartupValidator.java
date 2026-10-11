package com.substring.auth.app.core.startup;

import com.substring.auth.app.core.config.AuthCoreProperties;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(0)
@RequiredArgsConstructor
public class AuthCoreStartupValidator implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AuthCoreStartupValidator.class);
    private static final int MIN_SECRET_LENGTH = 64;

    @Value("${security.jwt.secret:}")
    private String jwtSecret;

    private final AuthCoreProperties properties;

    @Override
    public void run(ApplicationArguments args) {
        validateJwtSecret();
        validateConfig();
        log.info("AuthCore startup validation passed.");
    }

    private void validateJwtSecret() {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new IllegalStateException(
                    "JWT secret is not configured. Set security.jwt.secret (min 64 chars). " +
                    "For production, use the JWT_SECRET environment variable."
            );
        }
        if (jwtSecret.length() < MIN_SECRET_LENGTH) {
            throw new IllegalStateException(
                    "JWT secret is too short (" + jwtSecret.length() + " chars). " +
                    "Minimum required: " + MIN_SECRET_LENGTH + " chars for HMAC-SHA512."
            );
        }
    }

    private void validateConfig() {
        if (properties.getDefaultRole() == null || properties.getDefaultRole().isBlank()) {
            throw new IllegalStateException("auth.default-role must be configured.");
        }
        if (properties.getSecurity().getMaxLoginAttempts() < 1) {
            throw new IllegalStateException("auth.security.max-login-attempts must be >= 1.");
        }
    }
}
