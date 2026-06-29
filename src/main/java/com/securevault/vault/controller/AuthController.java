package com.securevault.vault.controller;
import com.securevault.vault.entity.User;
import com.securevault.vault.repository.UserRepository;
import com.securevault.vault.security.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ---------------- REGISTER ----------------
    @PostMapping("/register")
    public String register(@RequestBody User user) {

        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return "User already exists";
        }

        // IMPORTANT: encode password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("USER");
        userRepository.save(user);


        return "User registered successfully";
    }

    // ---------------- LOGIN ----------------
    @PostMapping("/login")
    public String login(@RequestBody User user) {

        User dbUser = userRepository.findByUsername(user.getUsername())
                .orElse(null);

        if (dbUser == null) {
            return "User not found";
        }

        if (!passwordEncoder.matches(user.getPassword(), dbUser.getPassword())) {
            return "Invalid password";
        }

        return JwtUtil.generateToken(dbUser.getUsername(), dbUser.getRole());
    }
}


