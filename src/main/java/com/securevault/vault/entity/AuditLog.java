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

    private String action;

    private LocalDateTime timestamp;

    public AuditLog() {}

    public AuditLog(Long fileId, String action, LocalDateTime timestamp) {
        this.fileId = fileId;
        this.action = action;
        this.timestamp = timestamp;
    }

    public Long getId() {
        return id;
    }

    public Long getFileId() {
        return fileId;
    }

    public void setFileId(Long fileId) {
        this.fileId = fileId;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}