package com.securevault.vault.repository;

import com.securevault.vault.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    // Powers GET /api/admin/users?search= (partial, case-insensitive)
    List<User> findByUsernameContainingIgnoreCase(String username);
}
