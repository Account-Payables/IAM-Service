package com.substring.auth.app.core.aspects;

import com.substring.auth.app.core.annotations.RequiresPermission;
import com.substring.auth.app.core.annotations.RequiresRole;
import com.substring.auth.app.core.context.AuthContext;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
public class PermissionAspect {

    @Before("@annotation(requiresPermission)")
    public void checkPermission(RequiresPermission requiresPermission) {
        String required = requiresPermission.value();
        if (!AuthContext.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        if (!AuthContext.hasPermission(required)) {
            log.debug("Access denied: missing permission '{}'", required);
            throw new AccessDeniedException("Access denied: missing permission '" + required + "'");
        }
    }

    @Before("@annotation(requiresRole)")
    public void checkRole(RequiresRole requiresRole) {
        String required = requiresRole.value();
        if (!AuthContext.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        if (!AuthContext.hasRole(required)) {
            log.debug("Access denied: missing role '{}'", required);
            throw new AccessDeniedException("Access denied: missing role '" + required + "'");
        }
    }
}
