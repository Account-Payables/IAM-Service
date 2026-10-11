package com.substring.auth.app.core.config;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.services.ApiTokenService;
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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class ApiTokenAuthFilter extends OncePerRequestFilter {

    private static final String API_KEY_HEADER = "X-API-Key";
    private static final Logger log = LoggerFactory.getLogger(ApiTokenAuthFilter.class);

    private final ApiTokenService apiTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String apiKey = request.getHeader(API_KEY_HEADER);

        if (apiKey != null && !apiKey.isBlank() &&
                SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                ApiTokenService.AuthResult result = apiTokenService.authenticateWithScopes(apiKey);
                User user = result.user();
                List<String> scopes = result.scopes();

                List<GrantedAuthority> authorities = new ArrayList<>();
                // Role-based authorities from the user's roles
                user.getRoles().forEach(r -> authorities.add(new SimpleGrantedAuthority(r.getName())));
                // Permission-based authorities — intersected with token scopes
                user.getPermissionNames().forEach(p -> {
                    // If token has wildcard scope "*" or explicitly lists this permission, grant it
                    if (scopes.contains("*") || scopes.contains(p)) {
                        authorities.add(new SimpleGrantedAuthority("PERMISSION_" + p));
                    }
                });

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(user.getEmail(), user.getId().toString(), authorities);

                Map<String, Object> details = new HashMap<>();
                details.put("userId", user.getId().toString());
                details.put("tokenSource", "API_TOKEN");
                details.put("scopes", scopes);
                auth.setDetails(details);

                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                log.debug("API token authentication failed: {}", e.getMessage());
                request.setAttribute("error", "Invalid API token");
            }
        }

        filterChain.doFilter(request, response);
    }
}
