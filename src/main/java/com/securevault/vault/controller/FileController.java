package com.securevault.vault.controller;

import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.repository.AuditLogRepository;
import com.securevault.vault.repository.FileRepository;
import com.securevault.vault.service.FileService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/files")
public class FileController {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;
    private final FileService fileService;

    public FileController(FileRepository fileRepository,
                          AuditLogRepository auditLogRepository,
                          FileService fileService) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
        this.fileService = fileService;
    }

    // ---------- RBAC helpers ----------

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getName();
    }

    private boolean currentUserIsAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    private void requireOwnerOrAdmin(FileEntity f) {
        if (currentUserIsAdmin()) return;
        if (!f.getUploadedBy().equals(currentUsername())) {
            throw new RuntimeException("Access denied: you do not own this file");
        }
    }

    // LIST FILES
    // ROLE_USER  -> only files they uploaded
    // ROLE_ADMIN -> all files
    @GetMapping
    public List<FileEntity> getAllFiles() {
        if (currentUserIsAdmin()) {
            return fileRepository.findAll();
        }
        return fileRepository.findByUploadedBy(currentUsername());
    }

    // UPLOAD FILE
    // "uploadedBy" is taken from the authenticated JWT identity, not from
    // any client-supplied field.
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file) throws Exception {
        return fileService.uploadFile(file, currentUsername());
    }

    // DOWNLOAD — owner or admin only
    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> download(@PathVariable Long id) throws Exception {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Not found"));

        requireOwnerOrAdmin(f);

        File file = new File(f.getFilePath());

        auditLogRepository.save(new AuditLog(
                id, f.getFileName(), "DOWNLOAD", currentUsername(), LocalDateTime.now()
        ));

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=" + f.getFileName())
                .body(Files.readAllBytes(file.toPath()));
    }

    // VERIFY — owner or admin only.
    // Response text format is UNCHANGED ("FILE SAFE" / "TAMPERED FILE
    // DETECTED") so the existing files.html scan UI keeps working.
    @GetMapping("/verify/{id}")
    public String verify(@PathVariable Long id) throws Exception {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Not found"));

        requireOwnerOrAdmin(f);

        File file = new File(f.getFilePath());
        byte[] bytes = Files.readAllBytes(file.toPath());

        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(bytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }

        boolean tampered = !sb.toString().equals(f.getFileHash());

        f.setStatus(tampered ? "TAMPERED" : "SAFE");
        fileRepository.save(f);

        auditLogRepository.save(new AuditLog(
                id,
                f.getFileName(),
                tampered ? "TAMPER" : "VERIFY",
                currentUsername(),
                LocalDateTime.now()
        ));

        return tampered ? "TAMPERED FILE DETECTED" : "FILE SAFE";
    }

    // AUDIT LOGS for one file — owner or admin only.
    // ROLE_USER can only see logs for a file they actually own.
    @GetMapping("/audit/{fileId}")
    public List<AuditLog> audit(@PathVariable Long fileId) {

        FileEntity f = fileRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));

        requireOwnerOrAdmin(f);

        return auditLogRepository.findByFileId(fileId);
    }

    @GetMapping("/details/{id}")
    public FileEntity getFileDetails(@PathVariable Long id) {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));

        requireOwnerOrAdmin(f);

        return f;
    }

    @GetMapping("/preview/{id}")
    public ResponseEntity<byte[]> preview(@PathVariable Long id) throws Exception {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));

        requireOwnerOrAdmin(f);

        File file = new File(f.getFilePath());

        return ResponseEntity.ok()
                .header("Content-Type", f.getFileType())
                .body(Files.readAllBytes(file.toPath()));
    }
}