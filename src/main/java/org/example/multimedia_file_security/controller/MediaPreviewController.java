package org.example.multimedia_file_security.controller;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.pojo.FileRecord;
import org.example.multimedia_file_security.service.FileService;
import org.example.multimedia_file_security.threadLocal.UserThreadLocal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.LocalDateTime;

@RestController
@Slf4j
public class MediaPreviewController {

    @Autowired
    private FileService fileService;

    @GetMapping("/{fileId}/audio-preview")
    public ResponseEntity<byte[]> previewAudio(@PathVariable Long fileId) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401).build();
            }

            FileRecord fileRecord = fileService.getFileRecordById(fileId);
            if (fileRecord == null) {
                return ResponseEntity.notFound().build();
            }

            if (!isAudioFile(fileRecord.getFileType(), fileRecord.getOriginalFilename())) {
                return ResponseEntity.badRequest().build();
            }

            byte[] audioData = fileService.getEncryptedFileData(fileId);
            if (audioData == null || audioData.length == 0) {
                return ResponseEntity.notFound().build();
            }

            String contentType = getAudioContentType(fileRecord.getOriginalFilename(), fileRecord.getFileType());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(contentType));
            headers.setContentLength(audioData.length);
            headers.setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).cachePublic());

            log.info("音频预览成功: fileId={}, filename={}, size={}, contentType={}",
                    fileId, fileRecord.getOriginalFilename(), audioData.length, contentType);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(audioData);

        } catch (Exception e) {
            log.error("音频预览失败", e);
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/{fileId}/video-preview")
    public ResponseEntity<byte[]> previewVideo(@PathVariable Long fileId) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401).build();
            }

            FileRecord fileRecord = fileService.getFileRecordById(fileId);
            if (fileRecord == null) {
                return ResponseEntity.notFound().build();
            }

            if (!isVideoFile(fileRecord.getFileType(), fileRecord.getOriginalFilename())) {
                return ResponseEntity.badRequest().build();
            }

            byte[] videoData = fileService.getEncryptedFileData(fileId);
            if (videoData == null || videoData.length == 0) {
                return ResponseEntity.notFound().build();
            }

            String contentType = getVideoContentType(fileRecord.getOriginalFilename(), fileRecord.getFileType());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(contentType));
            headers.setContentLength(videoData.length);
            headers.setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).cachePublic());

            log.info("视频预览成功: fileId={}, filename={}, size={}, contentType={}",
                    fileId, fileRecord.getOriginalFilename(), videoData.length, contentType);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(videoData);

        } catch (Exception e) {
            log.error("视频预览失败", e);
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/{fileId}/media-info")
    public ResponseEntity<MediaInfoDTO> getMediaInfo(@PathVariable Long fileId) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401).build();
            }

            FileRecord fileRecord = fileService.getFileRecordById(fileId);
            if (fileRecord == null) {
                return ResponseEntity.notFound().build();
            }

            boolean isAudio = isAudioFile(fileRecord.getFileType(), fileRecord.getOriginalFilename());
            boolean isVideo = isVideoFile(fileRecord.getFileType(), fileRecord.getOriginalFilename());

            if (!isAudio && !isVideo) {
                return ResponseEntity.badRequest().build();
            }

            MediaInfoDTO info = new MediaInfoDTO();
            info.setFileId(fileId);
            info.setFilename(fileRecord.getOriginalFilename());
            info.setFileSize(fileRecord.getFileSize());
            info.setFileType(fileRecord.getFileType());
            info.setUploadTime(fileRecord.getUploadTime());
            info.setEncryptionMode(fileRecord.getEncryptionMode());
            info.setMediaType(isAudio ? "AUDIO" : "VIDEO");
            info.setFormat(getMediaFormat(fileRecord.getOriginalFilename()));

            if (isAudio) {
                info.setPreviewUrl("/api/files/" + fileId + "/audio-preview");
            } else {
                info.setPreviewUrl("/api/files/" + fileId + "/video-preview");
            }
            info.setDownloadUrl("/api/files/" + fileId + "/download");

            return ResponseEntity.ok(info);

        } catch (Exception e) {
            log.error("获取媒体信息失败", e);
            return ResponseEntity.status(500).build();
        }
    }

    private boolean isAudioFile(String contentType, String filename) {
        if (contentType != null && contentType.startsWith("audio/")) {
            return true;
        }
        if (filename != null) {
            String lower = filename.toLowerCase();
            return lower.endsWith(".mp3") || lower.endsWith(".wav") ||
                    lower.endsWith(".aac") || lower.endsWith(".flac") ||
                    lower.endsWith(".ogg") || lower.endsWith(".m4a") ||
                    lower.endsWith(".wma");
        }
        return false;
    }

    private boolean isVideoFile(String contentType, String filename) {
        if (contentType != null && contentType.startsWith("video/")) {
            return true;
        }
        if (filename != null) {
            String lower = filename.toLowerCase();
            return lower.endsWith(".mp4") || lower.endsWith(".avi") ||
                    lower.endsWith(".mov") || lower.endsWith(".mkv") ||
                    lower.endsWith(".webm") || lower.endsWith(".flv") ||
                    lower.endsWith(".wmv");
        }
        return false;
    }

    private String getAudioContentType(String filename, String originalType) {
        if (originalType != null && originalType.startsWith("audio/")) {
            return originalType;
        }
        if (filename != null) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".mp3")) return "audio/mpeg";
            if (lower.endsWith(".wav")) return "audio/wav";
            if (lower.endsWith(".aac")) return "audio/aac";
            if (lower.endsWith(".flac")) return "audio/flac";
            if (lower.endsWith(".ogg")) return "audio/ogg";
            if (lower.endsWith(".m4a")) return "audio/mp4";
            if (lower.endsWith(".wma")) return "audio/x-ms-wma";
        }
        return "application/octet-stream";
    }

    private String getVideoContentType(String filename, String originalType) {
        if (originalType != null && originalType.startsWith("video/")) {
            return originalType;
        }
        if (filename != null) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".mp4")) return "video/mp4";
            if (lower.endsWith(".avi")) return "video/x-msvideo";
            if (lower.endsWith(".mov")) return "video/quicktime";
            if (lower.endsWith(".mkv")) return "video/x-matroska";
            if (lower.endsWith(".webm")) return "video/webm";
            if (lower.endsWith(".flv")) return "video/x-flv";
            if (lower.endsWith(".wmv")) return "video/x-ms-wmv";
        }
        return "application/octet-stream";
    }

    private String getMediaFormat(String filename) {
        if (filename == null) return "UNKNOWN";
        String lower = filename.toLowerCase();
        if (lower.endsWith(".mp3")) return "MP3";
        if (lower.endsWith(".wav")) return "WAV";
        if (lower.endsWith(".aac")) return "AAC";
        if (lower.endsWith(".flac")) return "FLAC";
        if (lower.endsWith(".ogg")) return "OGG";
        if (lower.endsWith(".m4a")) return "M4A";
        if (lower.endsWith(".wma")) return "WMA";
        if (lower.endsWith(".mp4")) return "MP4";
        if (lower.endsWith(".avi")) return "AVI";
        if (lower.endsWith(".mov")) return "MOV";
        if (lower.endsWith(".mkv")) return "MKV";
        if (lower.endsWith(".webm")) return "WEBM";
        return "UNKNOWN";
    }

    @Data
    public static class MediaInfoDTO {
        private Long fileId;
        private String filename;
        private Long fileSize;
        private String fileType;
        private String format;
        private String mediaType;
        private String encryptionMode;
        private String previewUrl;
        private String downloadUrl;
        private LocalDateTime uploadTime;
    }
}
