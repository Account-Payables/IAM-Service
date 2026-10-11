package com.substring.auth.app.auth.entities;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;

@Getter @Setter @AllArgsConstructor @NoArgsConstructor @Builder
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_users_status", columnList = "status"),
        @Index(name = "idx_users_deleted_at", columnList = "deletedAt")
})
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID id;

    @Column(name = "user_email", unique = true, length = 300)
    private String email;

    @Column(name = "user_name", length = 500)
    private String name;

    private String password;
    private String image;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @Column(nullable = false)
    @Builder.Default
    private int loginAttempts = 0;

    private Instant lockedUntil;
    private Instant lastLoginAt;

    @Column(length = 45)
    private String lastLoginIp;

    @Column(nullable = false)
    @Builder.Default
    private boolean emailVerified = false;

    @Builder.Default
    private Instant createdAt = Instant.now();

    @Builder.Default
    private Instant updatedAt = Instant.now();

    private Instant deletedAt;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Provider provider = Provider.LOCAL;

    private String providerId;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @PrePersist
    protected void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).toList();
    }

    @Override public String getUsername() { return this.email; }
    @Override public boolean isAccountNonExpired() { return status != UserStatus.DELETED; }
    @Override public boolean isAccountNonLocked() {
        if (status == UserStatus.LOCKED) {
            // Auto-unlock if duration has passed
            return lockedUntil != null && Instant.now().isAfter(lockedUntil);
        }
        return true;
    }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() {
        // PENDING_VERIFICATION users cannot login — CustomUserDetailService throws DisabledException for them.
        // Returning false here as a safety net so Spring Security's own checks also block them.
        return status == UserStatus.ACTIVE;
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE;
    }

    public List<String> getPermissionNames() {
        if (roles == null) return List.of();
        return roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .distinct()
                .toList();
    }
}
