package com.securevault.vault.exception;

public class InvalidRoleException extends RuntimeException {

    public InvalidRoleException(String role) {
        super("Invalid role '" + role + "'. Accepted values are ADMIN and USER.");
    }
}
