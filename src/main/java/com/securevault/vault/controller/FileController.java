package com.securevault.vault.controller;

import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.repository.AuditLogRepository;
import com.securevault.vault.repository.FileRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.List;

@RestController
@RequestMapping("/files")
public class FileController {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;

    public FileController(FileRepository fileRepository,
                          AuditLogRepository auditLogRepository) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
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

    // ---------------- UPLOAD ----------------
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file) throws Exception {

        String uploadDir = System.getProperty("user.dir") + "/uploads/";

        File dir = new File(uploadDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        String filePath = uploadDir + file.getOriginalFilename();

        File savedFile = new File(filePath);
        file.transferTo(savedFile);

        byte[] fileBytes = Files.readAllBytes(savedFile.toPath());

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);

        StringBuilder hashString = new StringBuilder();
        for (byte b : hashBytes) {
            hashString.append(String.format("%02x", b));
        }

        FileEntity fileEntity = new FileEntity();
        fileEntity.setFileName(file.getOriginalFilename());
        fileEntity.setFileType(file.getContentType());
        fileEntity.setFilePath(filePath);
        fileEntity.setFileHash(hashString.toString());

        // SAVE FILE FIRST (IMPORTANT)
        fileRepository.save(fileEntity);

        // THEN LOG
        auditLogRepository.save(
                new AuditLog(fileEntity.getId(), "UPLOAD")
        );

        return "File uploaded successfully! SHA-256: " + hashString;
    }

    // ---------------- VERIFY ----------------
    @GetMapping("/verify/{id}")
    public String verifyFile(@PathVariable Long id) throws Exception {

        FileEntity fileEntity = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));

        File file = new File(fileEntity.getFilePath());

        byte[] fileBytes = Files.readAllBytes(file.toPath());

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);

        StringBuilder currentHash = new StringBuilder();
        for (byte b : hashBytes) {
            currentHash.append(String.format("%02x", b));
        }

        // LOG FIRST (important)
        auditLogRepository.save(
                new AuditLog(id, "VERIFY")
        );

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

        // LOG AFTER FILE FETCH
        auditLogRepository.save(
                new AuditLog(id, "DOWNLOAD")
        );

        return ResponseEntity.ok()
                .header("Content-Disposition",
                        "attachment; filename=" + fileEntity.getFileName())
                .header("Content-Type",
                        fileEntity.getFileType())
                .body(fileContent);
    }

    // ---------------- DEBUG ENDPOINT ----------------
    @GetMapping("/audit-test")
    public String auditTest() {
        auditLogRepository.save(new AuditLog(999L, "TEST"));
        return "Audit test inserted";
    }
    @GetMapping("/audit/{fileId}")
    public List<String> getAuditLogs(@PathVariable Long fileId) {

        return auditLogRepository.findAll()
                .stream()
                .filter(log -> log.getFileId().equals(fileId))
                .map(AuditLog::getAction)
                .toList();
    }
}