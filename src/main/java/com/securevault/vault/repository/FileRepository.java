package com.securevault.vault.repository;

import com.securevault.vault.entity.FileEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FileRepository extends JpaRepository<FileEntity, Long> {
    List<FileEntity> findByUploadedBy(String uploadedBy);
}