package com.securevault.vault.controller;

import com.securevault.vault.dto.AdminStatsDTO;
import com.securevault.vault.dto.RoleUpdateRequestDTO;
import com.securevault.vault.dto.UserResponseDTO;
import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.repository.AuditLogRepository;
import com.securevault.vault.repository.FileRepository;
import com.securevault.vault.repository.UserRepository;
import com.securevault.vault.service.UserService;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin-only REST controller.
 *
 * All endpoints under /api/admin/** are protected by SecurityConfig
 * which requires ROLE_ADMIN. No per-method security annotations are
 * needed here — SecurityConfig handles it at the URL pattern level.
 *
 * Design principle: this controller is intentionally thin.
 * It receives the HTTP request, delegates to UserService for
 * user-management business logic, and returns the result.
 * It does not contain if-statement validation, null checks for
 * user existence, or role string comparisons — those all live in
 * UserService and are covered by GlobalExceptionHandler.
 *
 * Endpoints preserved from the original controller (URLs unchanged):
 *   GET  /api/admin/files
 *   GET  /api/admin/audit
 *   GET  /api/admin/users
 *   GET  /api/admin/users?search=
 *   PUT  /api/admin/users/{id}/role
 *   DELETE /api/admin/users/{id}
 *
 * New endpoint added in Phase 2:
 *   GET  /api/admin/stats
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;
    private final UserService userService;

    /**
     * Constructor injection.
     * UserService is added as a new dependency alongside the existing
     * repositories. The existing repositories are kept because
     * /api/admin/files, /api/admin/audit, and /api/admin/stats
     * still use them directly — no service layer wraps those yet.
     */
    public AdminController(FileRepository fileRepository,
                           AuditLogRepository auditLogRepository,
                           UserRepository userRepository,
                           UserService userService) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
        this.userService = userService;
    }

    // ── File endpoint (unchanged from original) ───────────────────────

    /**
     * GET /api/admin/files
     *
     * Returns every file in the system regardless of which user
     * uploaded it. Used by admin-dashboard.html to count total
     * files and tampered files.
     *
     * Response: JSON array of FileEntity objects.
     * URL, method, and response format are identical to the original.
     */
    @GetMapping("/files")
    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }

    // ── Audit endpoint (unchanged from original) ──────────────────────

    /**
     * GET /api/admin/audit
     *
     * Returns every audit log entry in the system regardless of
     * which user or file it belongs to. Used by admin-dashboard.html
     * to count total audit events and show recent activity.
     *
     * Response: JSON array of AuditLog objects.
     * URL, method, and response format are identical to the original.
     */
    @GetMapping("/audit")
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    // ── User endpoints (refactored to use UserService + DTOs) ─────────

    /**
     * GET /api/admin/users
     * GET /api/admin/users?search=alice
     *
     * Returns a list of all users, or a filtered list when a search
     * query is provided. The search is case-insensitive and partial —
     * "ali" matches "alice", "ALICE", "malice".
     *
     * Response structure per user:
     *   { "id": 1, "username": "alice", "role": "USER" }
     *
     * The password field is never included. This is enforced by
     * UserResponseDTO which only has id, username, and role fields.
     *
     * Frontend compatibility: admin-users.html reads u.id, u.username,
     * and u.role from each object. UserResponseDTO produces exactly
     * those three fields. The previous Map<String,Object> safeUser()
     * approach produced the same three fields. The frontend sees no
     * difference.
     *
     * Replaces: the original manual repo call + safeUser() helper.
     */
    @GetMapping("/users")
    public List<UserResponseDTO> getUsers(
            @RequestParam(required = false) String search) {

        if (search != null && !search.isBlank()) {
            return userService.searchUsers(search);
        }
        return userService.getAllUsers();
    }

    /**
     * PUT /api/admin/users/{id}/role
     *
     * Changes the role of the specified user.
     *
     * Request body:
     *   { "role": "ADMIN" }   or   { "role": "USER" }
     *   Case-insensitive: "admin", "Admin", "ADMIN" are all accepted.
     *
     * On success: HTTP 200 with the updated user as UserResponseDTO.
     *
     * On failure (handled automatically by GlobalExceptionHandler):
     *   400 — blank role, invalid role value, or self-demotion attempt
     *   404 — user with the given id does not exist
     *
     * The @Valid annotation on the parameter activates Jakarta Validation
     * on RoleUpdateRequestDTO before this method body runs. If the role
     * field is blank or not ADMIN/USER, Spring throws
     * MethodArgumentNotValidException, which GlobalExceptionHandler
     * catches and returns as HTTP 400 with a descriptive message.
     * This method body is only reached with a valid role value.
     *
     * The authenticated admin's username is read from Spring Security —
     * never from any request parameter or request body value.
     *
     * Replaces: the original manual if-statement validation and
     * Map-based error responses.
     */
    @PutMapping("/users/{id}/role")
    public ResponseEntity<UserResponseDTO> updateRole(
            @PathVariable Long id,
            @Valid @RequestBody RoleUpdateRequestDTO body) {

        String callerUsername = currentUsername();
        UserResponseDTO updated = userService.updateRole(
                id,
                body.getNormalizedRole(),
                callerUsername
        );

        return ResponseEntity.ok(updated);
    }

    /**
     * DELETE /api/admin/users/{id}
     *
     * Deletes the specified user account permanently.
     *
     * On success: HTTP 200 with { "message": "User deleted successfully." }
     *
     * On failure (handled automatically by GlobalExceptionHandler):
     *   400 — admin attempting to delete their own account
     *   404 — user with the given id does not exist
     *
     * The authenticated admin's username is read from Spring Security —
     * never from any request parameter.
     *
     * Frontend compatibility: admin-users.html calls
     *   DELETE /api/admin/users/${id}
     * and reads data.error on failure (falls back to a default string
     * if data.error is undefined, which is acceptable).
     * The success path triggers a toast without reading the response body.
     * This endpoint is fully compatible.
     *
     * Replaces: the original manual null check and Map-based responses.
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable Long id) {

        String callerUsername = currentUsername();
        userService.deleteUser(id, callerUsername);

        return ResponseEntity.ok(Map.of("message", "User deleted successfully."));
    }

    // ── Statistics endpoint (new in Phase 2) ─────────────────────────

    /**
     * GET /api/admin/stats
     *
     * Returns aggregate statistics calculated from existing repositories.
     * No new database tables or columns are needed.
     *
     * Response:
     * {
     *   "totalUsers":        5,
     *   "totalFiles":        12,
     *   "totalAuditLogs":    48,
     *   "totalAdmins":       1,
     *   "totalRegularUsers": 4
     * }
     *
     * totalAdmins and totalRegularUsers use countByRole(String) which
     * was added to UserRepository in Checkpoint 5.
     *
     * Note: admin-dashboard.html currently does NOT call this endpoint.
     * It derives stats client-side from /api/admin/files and
     * /api/admin/audit. This endpoint is additive — it does not affect
     * any existing page and is available for future use.
     */
    @GetMapping("/stats")
    public AdminStatsDTO getStats() {
        return new AdminStatsDTO(
                userRepository.count(),
                fileRepository.count(),
                auditLogRepository.count(),
                userRepository.countByRole("ADMIN"),
                userRepository.countByRole("USER")
        );
    }

    // ── Private helper ────────────────────────────────────────────────

    /**
     * Returns the username of the currently authenticated user
     * from the Spring Security context.
     *
     * This value comes from the verified JWT token processed by
     * JwtFilter. It is never read from a request parameter, a
     * request header set by the client, or the request body.
     * This prevents a malicious client from spoofing the caller
     * identity for self-action checks.
     */
    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getName();
    }
}