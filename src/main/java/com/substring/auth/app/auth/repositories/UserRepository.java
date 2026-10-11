package com.substring.auth.app.auth.repositories;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.entities.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    Page<User> findByStatusNot(UserStatus status, Pageable pageable);
}
