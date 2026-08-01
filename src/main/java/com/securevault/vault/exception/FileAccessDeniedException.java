package com.securevault.vault.exception;

public class FileAccessDeniedException extends RuntimeException {

    public FileAccessDeniedException() {
        super("Access denied: you do not own this file.");
    }
}