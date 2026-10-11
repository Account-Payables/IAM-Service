package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.entities.UserStatus;
import com.substring.auth.app.auth.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        checkAccountStatus(user);
        return user;
    }

    private void checkAccountStatus(User user) {
        if (user.getStatus() == UserStatus.DELETED) {
            throw new BadCredentialsException("Invalid email or password");
        }
        if (user.getStatus() == UserStatus.DISABLED) {
            throw new DisabledException("Account has been disabled. Please contact support.");
        }
        if (user.getStatus() == UserStatus.LOCKED) {
            if (user.getLockedUntil() != null && Instant.now().isBefore(user.getLockedUntil())) {
                throw new LockedException("Account is temporarily locked due to too many failed login attempts.");
            }
        }
        if (user.getStatus() == UserStatus.PENDING_VERIFICATION) {
            throw new DisabledException("Please verify your email address before logging in.");
        }
    }
}
