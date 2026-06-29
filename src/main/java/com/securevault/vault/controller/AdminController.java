package com.securevault.vault.controller;

import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.repository.AuditLogRepository;
import com.securevault.vault.repository.FileRepository;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * All endpoints here are restricted to ROLE_ADMIN by SecurityConfig
 * (.requestMatchers("/api/admin/**").hasRole("ADMIN")).
 *
 * Intentionally minimal for this pass: just "view all files" and "view
 * all audit logs," per the current RBAC-only scope. No dashboard stats,
 * no user management — those are separate features you haven't
 * greenlit yet.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;

    public AdminController(FileRepository fileRepository,
                           AuditLogRepository auditLogRepository) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
    }

    // View all files in the system, regardless of owner.
    @GetMapping("/files")
    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }

    // View all audit logs in the system, regardless of owner.
    @GetMapping("/audit")
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }
}
