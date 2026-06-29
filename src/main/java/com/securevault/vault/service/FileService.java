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
import java.time.LocalDateTime;

@Service
public class FileService {

    private final FileRepository fileRepository;
    private final AuditLogRepository auditLogRepository;

    public FileService(FileRepository fileRepository,
                       AuditLogRepository auditLogRepository) {
        this.fileRepository = fileRepository;
        this.auditLogRepository = auditLogRepository;
    }

    public String uploadFile(MultipartFile file, String uploadedBy) throws Exception {

        String dirPath = System.getProperty("user.dir") + "/uploads/";

        File dir = new File(dirPath);
        if (!dir.exists()) dir.mkdirs();

        String filePath = dirPath + file.getOriginalFilename();

        File saved = new File(filePath);
        file.transferTo(saved);

        byte[] bytes = Files.readAllBytes(saved.toPath());

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(bytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }

        FileEntity f = new FileEntity();
        f.setFileName(file.getOriginalFilename());
        f.setFileType(file.getContentType());
        f.setFilePath(filePath);
        f.setFileHash(sb.toString());
        f.setUploadedBy(uploadedBy);
        f.setUploadTime(LocalDateTime.now());
        f.setStatus("SAFE");

        fileRepository.save(f);

        auditLogRepository.save(new AuditLog(
                f.getId(),
                f.getFileName(),
                "UPLOAD",
                uploadedBy,
                LocalDateTime.now()
        ));

        return "Uploaded successfully";
    }
}