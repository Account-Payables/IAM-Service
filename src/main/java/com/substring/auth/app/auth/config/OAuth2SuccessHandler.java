package com.substring.auth.app.auth.config;

import com.substring.auth.app.auth.entities.Provider;
import com.substring.auth.app.auth.entities.RefreshToken;
import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.entities.UserStatus;
import com.substring.auth.app.auth.repositories.RefreshTokenRepository;
import com.substring.auth.app.auth.repositories.RoleRepository;
import com.substring.auth.app.auth.repositories.UserRepository;
import com.substring.auth.app.auth.services.impl.CookieService;
import com.substring.auth.app.auth.services.impl.JwtService;
import com.substring.auth.app.core.config.AuthCoreProperties;
import com.substring.auth.app.events.LoginSuccessEvent;
import com.substring.auth.app.extension.RegistrationHook;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final RegistrationHook registrationHook;
    private final AuthCoreProperties properties;

    @Value("${app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        log.info("OAuth2 login via provider: {}", registrationId);

        boolean isNewUser = false;
        User user;
        RegistrationHook.RegistrationSource hookSource;

        switch (registrationId) {
            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();

                final boolean[] created = {false};
                User newUser = buildOAuthUser(email, name, picture, Provider.GOOGLE, googleId);
                user = userRepository.findByEmail(email).orElseGet(() -> {
                    created[0] = true;
                    return userRepository.save(newUser);
                });
                isNewUser = created[0];
                hookSource = RegistrationHook.RegistrationSource.OAUTH2_GOOGLE;
            }
            case "github" -> {
                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("login", "").toString();
                String image = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();
                String email = (String) oAuth2User.getAttributes().get("email");
                if (email == null || email.isBlank()) {
                    // GitHub users with private emails don't expose their email.
                    // Use a deterministic internal address scoped to GitHub to avoid collisions
                    // with real emails. This address is never used for sending — only for identity.
                    email = "github_" + githubId + "@auth.internal";
                }

                String finalEmail = email;
                final boolean[] created = {false};
                User newUser = buildOAuthUser(email, name, image, Provider.GITHUB, githubId);
                user = userRepository.findByEmail(finalEmail).orElseGet(() -> {
                    created[0] = true;
                    return userRepository.save(newUser);
                });
                isNewUser = created[0];
                hookSource = RegistrationHook.RegistrationSource.OAUTH2_GITHUB;
            }
            default -> throw new RuntimeException("Unsupported OAuth2 provider: " + registrationId);
        }

        if (isNewUser) {
            try {
                registrationHook.onUserCreated(user, hookSource);
            } catch (Exception e) {
                log.error("RegistrationHook failed for OAuth2 user {}: {}", user.getId(), e.getMessage());
            }
        }

        // Create session
        String jti = UUID.randomUUID().toString();
        String userAgent = request.getHeader("User-Agent");

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .jti(jti).user(user).revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .deviceInfo(userAgent)
                .ipAddress(request.getRemoteAddr())
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, jti);

        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());

        eventPublisher.publishEvent(new LoginSuccessEvent(
                this, user.getId(), user.getEmail(),
                LoginSuccessEvent.LoginMethod.valueOf(
                        registrationId.equalsIgnoreCase("google") ? "GOOGLE" : "GITHUB"),
                request.getRemoteAddr(), userAgent, isNewUser
        ));

        response.sendRedirect(frontEndSuccessUrl);
    }

    private User buildOAuthUser(String email, String name, String image, Provider provider, String providerId) {
        String defaultRoleName = properties.getDefaultRole();
        User user = User.builder()
                .email(email).name(name).image(image)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .provider(provider).providerId(providerId)
                .build();
        roleRepository.findByName(defaultRoleName).ifPresent(role -> user.getRoles().add(role));
        return user;
    }
}
