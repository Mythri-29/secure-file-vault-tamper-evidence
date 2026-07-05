package com.securevault.vault.controller;

import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.entity.User;
import com.securevault.vault.repository.AuditLogRepository;
import com.securevault.vault.repository.FileRepository;
import com.securevault.vault.repository.UserRepository;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;

    public AdminController(FileRepository fileRepository,
                           AuditLogRepository auditLogRepository,
                           UserRepository userRepository) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
    }

    // ── existing endpoints (unchanged) ──────────────────────────────

    @GetMapping("/files")
    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }

    @GetMapping("/audit")
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    // ── user management (new) ────────────────────────────────────────

    /**
     * GET /api/admin/users
     * GET /api/admin/users?search=alice
     *
     * Returns id, username, role only — password hash is never included.
     */
    @GetMapping("/users")
    public List<Map<String, Object>> getUsers(
            @RequestParam(required = false) String search) {

        List<User> users = (search != null && !search.isBlank())
                ? userRepository.findByUsernameContainingIgnoreCase(search)
                : userRepository.findAll();

        return users.stream().map(this::safeUser).toList();
    }

    /**
     * PUT /api/admin/users/{id}/role
     * Body: { "role": "ADMIN" } or { "role": "USER" }
     *
     * Rules:
     *  - role must be ADMIN or USER (case-sensitive)
     *  - admin cannot demote themselves
     */
    @PutMapping("/users/{id}/role")
    public ResponseEntity<?> updateRole(@PathVariable Long id,
                                        @RequestBody Map<String, String> body) {

        String newRole = body.get("role");
        if (newRole == null || (!newRole.equals("ADMIN") && !newRole.equals("USER"))) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "role must be ADMIN or USER"));
        }

        User user = userRepository.findById(id).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "User not found"));
        }

        // Prevent admin from removing their own admin role
        String callerUsername = SecurityContextHolder.getContext()
                .getAuthentication().getName();
        if (user.getUsername().equals(callerUsername) && newRole.equals("USER")) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "You cannot remove your own admin role"));
        }

        user.setRole(newRole);
        userRepository.save(user);

        return ResponseEntity.ok(safeUser(user));
    }

    /**
     * DELETE /api/admin/users/{id}
     *
     * Rules:
     *  - admin cannot delete their own account
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {

        User user = userRepository.findById(id).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "User not found"));
        }

        String callerUsername = SecurityContextHolder.getContext()
                .getAuthentication().getName();
        if (user.getUsername().equals(callerUsername)) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "You cannot delete your own account"));
        }

        userRepository.delete(user);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    // ── helper ───────────────────────────────────────────────────────

    private Map<String, Object> safeUser(User u) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", u.getId());
        map.put("username", u.getUsername());
        map.put("role", u.getRole());
        return map;
    }
}