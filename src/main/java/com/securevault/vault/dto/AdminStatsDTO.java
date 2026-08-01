package com.securevault.vault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminStatsDTO {

    private long totalUsers;
    private long totalFiles;
    private long totalAuditLogs;
    private long totalAdmins;
    private long totalRegularUsers;
}
