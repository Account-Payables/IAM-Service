package com.substring.auth.app.auth.controllers;

import com.substring.auth.app.auth.entities.RefreshToken;
import com.substring.auth.app.auth.repositories.RefreshTokenRepository;
import com.substring.auth.app.auth.services.impl.CookieService;
import com.substring.auth.app.auth.services.impl.JwtService;
import com.substring.auth.app.core.context.AuthContext;
import com.substring.auth.app.events.AllSessionsRevokedEvent;
import com.substring.auth.app.events.UserLoggedOutEvent;
import com.substring.auth.app.exceptions.ResourceNotFoundException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/sessions")
@RequiredArgsConstructor
public class SessionController {

    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final JwtService jwtService;
    private final CookieService cookieService;

    @GetMapping
    public ResponseEntity<List<SessionDto>> listSessions() {
        UUID userId = AuthContext.getCurrentUserId();
        List<RefreshToken> sessions = refreshTokenRepository.findByUserIdAndRevokedFalse(userId)
                .stream()
                .filter(rt -> rt.getExpiresAt().isAfter(Instant.now()))
                .toList();

        return ResponseEntity.ok(sessions.stream().map(SessionDto::from).toList());
    }

    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> revokeSession(@PathVariable UUID sessionId, HttpServletRequest request) {
        UUID userId = AuthContext.getCurrentUserId();
        boolean isAdmin = AuthContext.hasRole("SUPER_ADMIN");

        RefreshToken session = refreshTokenRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found"));

        // IDOR protection
        if (!isAdmin && !session.getUser().getId().equals(userId)) {
            throw new AccessDeniedException("Cannot revoke another user's session");
        }

        session.setRevoked(true);
        refreshTokenRepository.save(session);

        eventPublisher.publishEvent(new UserLoggedOutEvent(
                this, userId, AuthContext.getCurrentUserEmail(), session.getJti()
        ));

        return ResponseEntity.noContent().build();
    }

    @DeleteMapping
    public ResponseEntity<Map<String, Object>> revokeAllSessions(HttpServletRequest request, HttpServletResponse response) {
        UUID userId = AuthContext.getCurrentUserId();
        String email = AuthContext.getCurrentUserEmail();

        // Keep current session alive, revoke all others
        String currentJti = getCurrentJti(request);

        List<RefreshToken> sessions = refreshTokenRepository.findByUserIdAndRevokedFalse(userId);
        int revoked = 0;
        for (RefreshToken session : sessions) {
            if (!session.getJti().equals(currentJti)) {
                session.setRevoked(true);
                refreshTokenRepository.save(session);
                revoked++;
            }
        }

        eventPublisher.publishEvent(new AllSessionsRevokedEvent(
                this, userId, email, AllSessionsRevokedEvent.Reason.USER_REQUESTED, revoked
        ));

        return ResponseEntity.ok(Map.of("sessionsRevoked", revoked));
    }

    private String getCurrentJti(HttpServletRequest request) {
        if (request.getCookies() == null) return "";
        Optional<String> refreshToken = Arrays.stream(request.getCookies())
                .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
        if (refreshToken.isPresent()) {
            try {
                return jwtService.getJti(refreshToken.get());
            } catch (Exception ignored) {}
        }
        return "";
    }

    @Getter @Setter
    public static class SessionDto {
        private UUID id;
        private String deviceInfo;
        private String ipAddress;
        private Instant createdAt;
        private Instant lastUsedAt;

        public static SessionDto from(RefreshToken rt) {
            SessionDto dto = new SessionDto();
            dto.setId(rt.getId());
            dto.setDeviceInfo(rt.getDeviceInfo());
            dto.setIpAddress(rt.getIpAddress());
            dto.setCreatedAt(rt.getCreatedAt());
            dto.setLastUsedAt(rt.getLastUsedAt());
            return dto;
        }
    }
}
