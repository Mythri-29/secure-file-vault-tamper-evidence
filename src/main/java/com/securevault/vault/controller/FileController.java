package com.securevault.vault.controller;

import com.securevault.vault.entity.FileEntity;
import com.securevault.vault.repository.FileRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.List;

@RestController
@RequestMapping("/files")
public class FileController {

    private final FileRepository fileRepository;

    public FileController(FileRepository fileRepository) {
        this.fileRepository = fileRepository;
    }

    @GetMapping("/test")
    public String test() {
        return "Secure Vault API is working!";
    }

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    @GetMapping
    public List<FileEntity> getAllFiles() {
        return fileRepository.findAll();
    }

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

        // Generate SHA-256 hash
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

        fileRepository.save(fileEntity);

        return "File uploaded successfully! SHA-256: " + hashString;
    }

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

        if (currentHash.toString().equals(fileEntity.getFileHash())) {
            return "File is authentic. No tampering detected.";
        } else {
            return "WARNING: File has been tampered with!";
        }
    }
}