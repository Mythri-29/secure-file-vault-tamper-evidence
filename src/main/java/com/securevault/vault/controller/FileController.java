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
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

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

    // LIST FILES
    @GetMapping
    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }

    // UPLOAD FILE
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                             @RequestParam("uploadedBy") String uploadedBy) throws Exception {

        return fileService.uploadFile(file, uploadedBy);
    }

    // DOWNLOAD
    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> download(@PathVariable Long id) throws Exception {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Not found"));

        File file = new File(f.getFilePath());

        auditLogRepository.save(new AuditLog(
                id, "DOWNLOAD", LocalDateTime.now()
        ));

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=" + f.getFileName())
                .body(Files.readAllBytes(file.toPath()));
    }

    // VERIFY
    @GetMapping("/verify/{id}")
    public String verify(@PathVariable Long id) throws Exception {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Not found"));

        File file = new File(f.getFilePath());

        byte[] bytes = Files.readAllBytes(file.toPath());

        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(bytes);

        StringBuilder sb = new StringBuilder();
        for(byte b : hash){
            sb.append(String.format("%02x", b));
        }

        boolean tampered = !sb.toString().equals(f.getFileHash());

        auditLogRepository.save(new AuditLog(
                id,
                "VERIFY",
                LocalDateTime.now()
        ));

        return tampered ? "TAMPERED FILE DETECTED" : "FILE SAFE";
    }

    // AUDIT LOGS
    @GetMapping("/audit/{fileId}")
    public List<AuditLog> audit(@PathVariable Long fileId) {

        return auditLogRepository.findAll()
                .stream()
                .filter(a -> a.getFileId().equals(fileId))
                .collect(Collectors.toList());
    }
    @GetMapping("/details/{id}")
    public FileEntity getFileDetails(@PathVariable Long id) {

        return fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));
    }
    @GetMapping("/preview/{id}")
    public ResponseEntity<byte[]> preview(@PathVariable Long id) throws Exception {

        FileEntity f = fileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("File not found"));

        File file = new File(f.getFilePath());

        return ResponseEntity.ok()
                .header("Content-Type", f.getFileType())
                .body(Files.readAllBytes(file.toPath()));
    }
}