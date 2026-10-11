package com.substring.auth.app.auth.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter @Setter @AllArgsConstructor @Builder @NoArgsConstructor
@Entity
@Table(name = "af_roles")
public class Role {

    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID();

    @Column(unique = true, nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String description;

    @Column(nullable = false)
    @Builder.Default
    private boolean isSystem = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "af_role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();
}
