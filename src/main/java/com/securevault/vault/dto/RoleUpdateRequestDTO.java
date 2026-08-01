package com.securevault.vault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Locale;

@Data
@NoArgsConstructor
public class RoleUpdateRequestDTO {

    @NotBlank(message = "role must not be blank")
    @Pattern(
            regexp = "(?i)ADMIN|USER",
            message = "role must be ADMIN or USER"
    )
    private String role;

    public String getNormalizedRole() {
        return role == null ? null : role.toUpperCase(Locale.ROOT);
    }
}
