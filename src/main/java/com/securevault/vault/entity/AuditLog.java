package com.securevault.vault.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long fileId;
    private String fileName;
    private String action;
    private String username;
    private LocalDateTime timestamp;

    public AuditLog() {}

    public AuditLog(Long fileId, String action, LocalDateTime timestamp) {
        this.fileId = fileId;
        this.action = action;
        this.timestamp = timestamp;
    }

    public AuditLog(Long fileId, String fileName, String action, String username, LocalDateTime timestamp) {
        this.fileId = fileId;
        this.fileName = fileName;
        this.action = action;
        this.username = username;
        this.timestamp = timestamp;
    }

    public Long getId() { return id; }
    public Long getFileId() { return fileId; }
    public void setFileId(Long fileId) { this.fileId = fileId; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}