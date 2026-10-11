package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.*;
import com.substring.auth.app.auth.payload.TokenResponse;
import com.substring.auth.app.auth.payload.UserDto;
import com.substring.auth.app.auth.repositories.RefreshTokenRepository;
import com.substring.auth.app.auth.repositories.UserRepository;
import com.substring.auth.app.auth.services.AuthService;
import com.substring.auth.app.auth.services.BruteForceService;
import com.substring.auth.app.auth.services.UserService;
import com.substring.auth.app.core.config.AuthCoreProperties;
import com.substring.auth.app.events.*;
import com.substring.auth.app.extension.LoginValidator;
import com.substring.auth.app.extension.PostLoginHook;
import com.substring.auth.app.extension.RegistrationHook;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserService userService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final BruteForceService bruteForceService;
    private final ModelMapper modelMapper;
    private final ApplicationEventPublisher eventPublisher;
    private final AuthCoreProperties properties;
    private final PasswordEncoder passwordEncoder;

    // Extension hooks (no-op defaults via NoOpExtensions if not implemented by project)
    private final List<LoginValidator> loginValidators;
    private final PostLoginHook postLoginHook;
    private final RegistrationHook registrationHook;

    @Override
    public UserDto registerUser(UserDto userDto) {
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        UserDto created = userService.createUser(userDto);

        userRepository.findById(created.getId()).ifPresent(user -> {
            boolean verificationRequired = properties.getEmailVerification().isRequired();

            // Extension hook — project can create profile, workspace, etc.
            try {
                registrationHook.onUserCreated(user, RegistrationHook.RegistrationSource.EMAIL_PASSWORD);
            } catch (Exception e) {
                log.error("RegistrationHook failed for user {}: {}", user.getId(), e.getMessage());
            }

            eventPublisher.publishEvent(new UserRegisteredEvent(
                    this, user.getId(), user.getEmail(), user.getName(), verificationRequired
            ));
        });

        return created;
    }

    @Override
    @Transactional
    public TokenResponse login(String email, String password, HttpServletRequest request, HttpServletResponse response) {
        // Authenticate credentials
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password));
        } catch (LockedException e) {
            publishLoginFailed(email, LoginFailedEvent.Reason.ACCOUNT_LOCKED, request, 0);
            throw e;
        } catch (DisabledException e) {
            publishLoginFailed(email, LoginFailedEvent.Reason.ACCOUNT_DISABLED, request, 0);
            throw e;
        } catch (Exception e) {
            // Single DB fetch — eliminates race condition from double findByEmail
            userRepository.findByEmail(email).ifPresentOrElse(
                    user -> {
                        bruteForceService.recordFailedAttempt(user, request);
                        publishLoginFailed(email, LoginFailedEvent.Reason.INVALID_CREDENTIALS,
                                request, user.getLoginAttempts());
                    },
                    () -> publishLoginFailed(email, LoginFailedEvent.Reason.ACCOUNT_NOT_FOUND,
                            request, 0)
            );
            // Always same message — no enumeration
            throw new BadCredentialsException("Invalid email or password");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new BadCredentialsException("Invalid email or password");
        }

        // Brute force check
        if (bruteForceService.isLocked(user)) {
            publishLoginFailed(email, LoginFailedEvent.Reason.ACCOUNT_LOCKED, request, user.getLoginAttempts());
            throw new LockedException("Account is temporarily locked. Please try again later.");
        }

        // Run project's custom validators (Chain of Responsibility)
        for (LoginValidator validator : loginValidators) {
            validator.validate(user, request);
        }

        // Reset brute force counter on success
        bruteForceService.resetAttempts(user);

        // Update last login info
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(request.getRemoteAddr());
        userRepository.save(user);

        // Create session
        String jti = UUID.randomUUID().toString();
        String userAgent = request.getHeader("User-Agent");
        String deviceInfo = parseDeviceInfo(userAgent);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .jti(jti).user(user).revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .deviceInfo(deviceInfo)
                .ipAddress(request.getRemoteAddr())
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, jti);

        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        // Post-login hook — project can add extra metadata
        Map<String, Object> meta;
        try {
            meta = postLoginHook.onLoginSuccess(user, request);
        } catch (Exception e) {
            log.error("PostLoginHook failed for user {}: {}", user.getId(), e.getMessage());
            meta = Map.of();
        }

        // Publish login success event
        eventPublisher.publishEvent(new LoginSuccessEvent(
                this, user.getId(), user.getEmail(),
                LoginSuccessEvent.LoginMethod.PASSWORD,
                request.getRemoteAddr(),
                userAgent, false
        ));

        UserDto userDto = modelMapper.map(user, UserDto.class);
        return TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTtlSeconds(), userDto);
    }

    @Override
    @Transactional
    public TokenResponse refreshTokens(String refreshToken, HttpServletRequest request, HttpServletResponse response) {
        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token type");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);

        RefreshToken stored = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException("Refresh token not recognized"));

        if (stored.isRevoked()) {
            // Token reuse detected — this is a theft indicator
            log.warn("Refresh token reuse detected for user {}! Revoking all sessions.", userId);
            int revoked = refreshTokenRepository.revokeAllByUserId(userId);

            User user = stored.getUser();
            eventPublisher.publishEvent(new SuspiciousActivityEvent(
                    this, userId, user.getEmail(),
                    SuspiciousActivityEvent.ActivityType.REFRESH_TOKEN_REUSE,
                    request.getRemoteAddr(),
                    "Revoked refresh token was used again — possible token theft",
                    true
            ));
            eventPublisher.publishEvent(new AllSessionsRevokedEvent(
                    this, userId, user.getEmail(),
                    AllSessionsRevokedEvent.Reason.SUSPICIOUS_ACTIVITY, revoked
            ));

            throw new BadCredentialsException("Token reuse detected. All sessions have been terminated for security.");
        }

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token expired");
        }
        if (!stored.getUser().getId().equals(userId)) {
            throw new BadCredentialsException("Token does not belong to this user");
        }

        // Rotate token
        stored.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        stored.setReplacedByToken(newJti);
        refreshTokenRepository.save(stored);

        User user = stored.getUser();
        RefreshToken newToken = RefreshToken.builder()
                .jti(newJti).user(user).revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .deviceInfo(stored.getDeviceInfo())
                .ipAddress(request.getRemoteAddr())
                .build();
        refreshTokenRepository.save(newToken);

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user, newJti);

        cookieService.attachRefreshCookie(response, newRefreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        return TokenResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTtlSeconds(),
                modelMapper.map(user, UserDto.class));
    }

    @Override
    public void logout(String refreshToken, HttpServletResponse response) {
        if (refreshToken != null) {
            try {
                if (jwtService.isRefreshToken(refreshToken)) {
                    String jti = jwtService.getJti(refreshToken);
                    refreshTokenRepository.findByJti(jti).ifPresent(rt -> {
                        UUID userId = rt.getUser().getId();
                        String email = rt.getUser().getEmail();
                        rt.setRevoked(true);
                        refreshTokenRepository.save(rt);
                        eventPublisher.publishEvent(new UserLoggedOutEvent(this, userId, email, jti));
                    });
                }
            } catch (JwtException ignored) {}
        }
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);
    }

    @Override
    @Transactional
    public void logoutAll(String currentRefreshToken, HttpServletResponse response) {
        UUID userId = null;
        String email = null;

        if (currentRefreshToken != null) {
            try {
                userId = jwtService.getUserId(currentRefreshToken);
                email = jwtService.getEmail(currentRefreshToken);
            } catch (Exception ignored) {}
        }

        int revoked = 0;
        if (userId != null) {
            revoked = refreshTokenRepository.revokeAllByUserId(userId);
            eventPublisher.publishEvent(new AllSessionsRevokedEvent(
                    this, userId, email,
                    AllSessionsRevokedEvent.Reason.USER_REQUESTED, revoked
            ));
        }

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);
    }

    private void publishLoginFailed(String email, LoginFailedEvent.Reason reason,
                                    HttpServletRequest request, int attemptCount) {
        eventPublisher.publishEvent(new LoginFailedEvent(
                this, email, reason, request.getRemoteAddr(),
                attemptCount, properties.getSecurity().getMaxLoginAttempts()
        ));
    }

    private String parseDeviceInfo(String userAgent) {
        if (userAgent == null) return "Unknown Device";
        if (userAgent.length() > 490) return userAgent.substring(0, 490);
        return userAgent;
    }
}
