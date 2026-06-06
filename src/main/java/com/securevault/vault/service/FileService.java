package com.securevault.vault.service;

import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.entity.AuditLog;
import com.securevault.vault.repository.FileRepository;
import com.securevault.vault.repository.AuditLogRepository;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;

@Service
public class FileService {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;

    public FileService(FileRepository fileRepository,
                       AuditLogRepository auditLogRepository) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
    }

    // ---------------- UPLOAD FILE ----------------
    public String uploadFile(MultipartFile file) throws Exception {

        String uploadDir = System.getProperty("user.dir") + "/uploads/";

        File dir = new File(uploadDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        String filePath = uploadDir + file.getOriginalFilename();

        File savedFile = new File(filePath);
        file.transferTo(savedFile);

        // ---------------- SHA-256 HASH ----------------
        byte[] fileBytes = Files.readAllBytes(savedFile.toPath());

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);

        StringBuilder hashString = new StringBuilder();
        for (byte b : hashBytes) {
            hashString.append(String.format("%02x", b));
        }

        // ---------------- SAVE FILE ENTITY ----------------
        // ---------------- SAVE FILE ENTITY ----------------
        FileEntity fileEntity = new FileEntity();

        fileEntity.setFileName(file.getOriginalFilename());
        fileEntity.setFileType(file.getContentType());
        fileEntity.setFilePath(filePath);

        fileEntity.setFileHash(hashString.toString());

// NEW METADATA
        fileEntity.setUploadedBy("admin");
        fileEntity.setUploadTime(java.time.LocalDateTime.now());
        fileEntity.setStatus("SAFE");

        fileRepository.save(fileEntity);

        // ---------------- AUDIT LOG ----------------
        auditLogRepository.save(
                new AuditLog(fileEntity.getId(), "UPLOAD")
        );

        return "File uploaded successfully! SHA-256: " + hashString;
    }
}