package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.entities.UserStatus;
import com.substring.auth.app.auth.repositories.UserRepository;
import com.substring.auth.app.auth.services.BruteForceService;
import com.substring.auth.app.core.config.AuthCoreProperties;
import com.substring.auth.app.events.AccountLockedEvent;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class BruteForceServiceImpl implements BruteForceService {

    private static final Logger log = LoggerFactory.getLogger(BruteForceServiceImpl.class);

    private final UserRepository userRepository;
    private final AuthCoreProperties properties;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    public void recordFailedAttempt(User user, HttpServletRequest request) {
        user.setLoginAttempts(user.getLoginAttempts() + 1);
        int maxAttempts = properties.getSecurity().getMaxLoginAttempts();

        if (user.getLoginAttempts() >= maxAttempts) {
            int lockMinutes = properties.getSecurity().getLockoutDurationMinutes();
            Instant lockedUntil = Instant.now().plusSeconds(lockMinutes * 60L);
            user.setLockedUntil(lockedUntil);
            user.setStatus(UserStatus.LOCKED);
            userRepository.save(user);

            String ip = request != null ? request.getRemoteAddr() : "unknown";
            log.warn("Account locked for user {} after {} failed attempts", user.getEmail(), user.getLoginAttempts());
            eventPublisher.publishEvent(new AccountLockedEvent(
                    this, user.getId(), user.getEmail(), ip, lockedUntil, user.getLoginAttempts()
            ));
        } else {
            userRepository.save(user);
        }
    }

    @Override
    public boolean isLocked(User user) {
        if (user.getStatus() == UserStatus.LOCKED) {
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                // Auto-unlock
                user.setStatus(UserStatus.ACTIVE);
                user.setLoginAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public void resetAttempts(User user) {
        user.setLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }
}
