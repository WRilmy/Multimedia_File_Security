package org.example.multimedia_file_security.dto;


import lombok.Data;

import java.time.LocalDateTime;

@Data
public class FileDownloadDTO {
    private Long fileId;
    private String originalFilename;
    private byte[] fileData;
    private String fileType;
    private Integer fileSize;
    private LocalDateTime downloadTime;
    private Boolean signatureValid;
    private Boolean hashValid;
    private String verificationMessage;
    private String message;
    private Boolean isSuccess;
}
