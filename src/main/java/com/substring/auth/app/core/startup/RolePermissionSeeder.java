package com.substring.auth.app.core.startup;

import com.substring.auth.app.auth.entities.Permission;
import com.substring.auth.app.auth.entities.Role;
import com.substring.auth.app.auth.repositories.PermissionRepository;
import com.substring.auth.app.auth.repositories.RoleRepository;
import com.substring.auth.app.core.config.AuthCoreProperties;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@Order(1)
@RequiredArgsConstructor
public class RolePermissionSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(RolePermissionSeeder.class);

    private final AuthCoreProperties properties;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        log.info("Seeding roles and permissions from config...");

        for (AuthCoreProperties.RoleConfig roleConfig : properties.getRoles()) {
            Set<Permission> permissions = new HashSet<>();

            for (String permName : roleConfig.getPermissions()) {
                if ("*".equals(permName)) {
                    // Wildcard — store as-is, handled at runtime
                    Permission wildcard = permissionRepository.findByName("*")
                            .orElseGet(() -> permissionRepository.save(
                                    Permission.builder().name("*").description("All permissions").build()
                            ));
                    permissions.add(wildcard);
                } else {
                    Permission perm = permissionRepository.findByName(permName)
                            .orElseGet(() -> {
                                log.info("Creating permission: {}", permName);
                                return permissionRepository.save(Permission.builder().name(permName).build());
                            });
                    permissions.add(perm);
                }
            }

            roleRepository.findByName(roleConfig.getName()).ifPresentOrElse(
                    existing -> log.debug("Role already exists, skipping: {}", roleConfig.getName()),
                    () -> {
                        log.info("Creating role: {}", roleConfig.getName());
                        roleRepository.save(Role.builder()
                                .name(roleConfig.getName())
                                .permissions(permissions)
                                .build());
                    }
            );
        }

        log.info("Role/permission seeding complete.");
    }
}
