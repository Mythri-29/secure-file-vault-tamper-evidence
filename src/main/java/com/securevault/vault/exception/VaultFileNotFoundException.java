package com.securevault.vault.exception;

public class VaultFileNotFoundException extends RuntimeException {

    public VaultFileNotFoundException(Long id) {
        super("File not found with id: " + id);
    }
}
