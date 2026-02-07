package org.example.multimedia_file_security.service;

import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.pojo.FileRecord;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface FileService {
    Result uploadFile(MultipartFile file, Long userId, String encryptionMode) throws Exception;
    Result downloadFile(Long fileId, Long userId);
    boolean deleteFile(Long fileId, Long userId);
    List<FileRecord> getUserFiles(Long userId);
}