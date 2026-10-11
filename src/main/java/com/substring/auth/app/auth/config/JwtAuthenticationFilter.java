package com.substring.auth.app.auth.config;

import com.substring.auth.app.auth.services.impl.JwtService;
import com.substring.auth.app.auth.repositories.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                if (!jwtService.isAccessToken(token)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                Jws<Claims> parsed = jwtService.parse(token);
                Claims payload = parsed.getPayload();
                String userId = payload.getSubject();
                UUID userUuid = UUID.fromString(userId);

                userRepository.findById(userUuid).ifPresent(user -> {
                    if (user.isActive()) {
                        List<GrantedAuthority> authorities = buildAuthorities(user.getRoles().stream()
                                .map(r -> r.getName()).toList(),
                                jwtService.getPermissions(token));

                        UsernamePasswordAuthenticationToken auth =
                                new UsernamePasswordAuthenticationToken(user.getEmail(), userId, authorities);

                        // Store userId and tokenSource in details for AuthContext
                        Map<String, Object> details = new HashMap<>();
                        details.put("userId", userId);
                        details.put("tokenSource", "JWT");
                        auth.setDetails(details);

                        if (SecurityContextHolder.getContext().getAuthentication() == null) {
                            SecurityContextHolder.getContext().setAuthentication(auth);
                        }
                    }
                });

            } catch (ExpiredJwtException e) {
                request.setAttribute("error", "Token expired");
            } catch (Exception e) {
                request.setAttribute("error", "Invalid token");
            }
        }

        filterChain.doFilter(request, response);
    }

    private List<GrantedAuthority> buildAuthorities(List<String> roles, List<String> permissions) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority(r)));
        if (permissions != null) {
            permissions.forEach(p -> authorities.add(new SimpleGrantedAuthority("PERMISSION_" + p)));
        }
        return authorities;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
