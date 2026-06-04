package com.securevault.vault.controller;

import com.securevault.vault.entity.User;
import com.securevault.vault.repository.UserRepository;
import com.securevault.vault.security.JwtUtil;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ---------------- LOGIN ----------------
    @PostMapping("/login")
    public String login(@RequestBody User user) {

        User dbUser = userRepository.findByUsername(user.getUsername())
                .orElse(null);

        if (dbUser == null) {
            return "User not found";
        }

        if (!dbUser.getPassword().equals(user.getPassword())) {
            return "Invalid password";
        }

        return JwtUtil.generateToken(dbUser.getUsername());
    }
}