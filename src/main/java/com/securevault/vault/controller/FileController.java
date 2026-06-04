package com.securevault.vault.controller;

import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.repository.AuditLogRepository;
import com.securevault.vault.repository.FileRepository;
import com.securevault.vault.service.FileService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
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

    // ---------------- TEST ----------------
    @GetMapping("/test")
    public String test() {
        return "Secure Vault API is working!";
    }

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    // ---------------- LIST FILES ----------------
    @GetMapping
    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }

    // ---------------- UPLOAD (FIXED) ----------------
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file) throws Exception {
        return fileService.uploadFile(file);
    }

    // ---------------- VERIFY ----------------
    @GetMapping("/verify/{id}")
    public String verifyFile(@PathVariable Long id) throws Exception {

        FileEntity fileEntity = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));

        File file = new File(fileEntity.getFilePath());

        byte[] fileBytes = Files.readAllBytes(file.toPath());

        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);

        StringBuilder currentHash = new StringBuilder();
        for (byte b : hashBytes) {
            currentHash.append(String.format("%02x", b));
        }

        auditLogRepository.save(new AuditLog(id, "VERIFY"));

        if (currentHash.toString().equals(fileEntity.getFileHash())) {
            return "File is authentic. No tampering detected.";
        } else {
            return "WARNING: File has been tampered with!";
        }
    }

    // ---------------- DOWNLOAD ----------------
    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable Long id) throws Exception {

        FileEntity fileEntity = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));

        File file = new File(fileEntity.getFilePath());

        byte[] fileContent = Files.readAllBytes(file.toPath());

        auditLogRepository.save(new AuditLog(id, "DOWNLOAD"));

        return ResponseEntity.ok()
                .header("Content-Disposition",
                        "attachment; filename=" + fileEntity.getFileName())
                .header("Content-Type",
                        fileEntity.getFileType())
                .body(fileContent);
    }

    // ---------------- AUDIT TEST ----------------
    @GetMapping("/audit-test")
    public String auditTest() {
        auditLogRepository.save(new AuditLog(999L, "TEST"));
        return "Audit test inserted";
    }

    // ---------------- AUDIT LOGS ----------------
    @GetMapping("/audit/{fileId}")
    public List<String> getAuditLogs(@PathVariable Long fileId) {

        return auditLogRepository.findAll()
                .stream()
                .filter(log -> log.getFileId().equals(fileId))
                .map(AuditLog::getAction)
                .toList();
    }
}