package com.substring.auth.app.core.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Prevent MIME-type sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Prevent clickjacking
        response.setHeader("X-Frame-Options", "DENY");

        // Legacy XSS filter (still useful for older browsers)
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // Limit referrer info leakage
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Disable browser features not needed by this API
        response.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

        // Force HTTPS for 1 year (only meaningful when served over HTTPS)
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

        // Content Security Policy — API-only backend, no HTML served
        // Blocks any attempt to render injected content in a browser context
        response.setHeader("Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");

        // Prevent caching of auth responses
        String uri = request.getRequestURI();
        if (uri.contains("/auth/") || uri.contains("/users/")) {
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");
        }

        filterChain.doFilter(request, response);
    }
}
