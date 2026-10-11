package com.substring.auth.app.core.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "auth")
@Getter
@Setter
public class AuthCoreProperties {

    private String baseUrl = "http://localhost:8080";
    private String defaultRole = "USER";

    private Jwt jwt = new Jwt();
    private Security security = new Security();
    private EmailVerification emailVerification = new EmailVerification();
    private Password password = new Password();
    private List<RoleConfig> roles = new ArrayList<>();

    @Getter @Setter
    public static class Jwt {
        private String secret;
        private long accessTtlSeconds = 600;
        private long refreshTtlSeconds = 86400;
    }

    @Getter @Setter
    public static class Security {
        private int maxLoginAttempts = 5;
        private int lockoutDurationMinutes = 15;
        private RateLimit rateLimit = new RateLimit();
    }

    @Getter @Setter
    public static class RateLimit {
        private int loginRpm = 10;
        private int registerRpm = 5;
        private int forgotPasswordRpm = 5;
        private int resendVerificationRpm = 3;
    }

    @Getter @Setter
    public static class EmailVerification {
        private boolean required = false;
        private int tokenExpiryHours = 24;
    }

    @Getter @Setter
    public static class Password {
        private int minLength = 8;
        private int maxLength = 128;
        private boolean requireUppercase = false;
        private boolean requireDigit = false;
        private boolean requireSpecialChar = false;
    }

    @Getter @Setter
    public static class RoleConfig {
        private String name;
        private List<String> permissions = new ArrayList<>();
    }
}
