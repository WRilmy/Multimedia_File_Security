package org.example.multimedia_file_security.controller;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.pojo.FileRecord;
import org.example.multimedia_file_security.service.FileService;
import org.example.multimedia_file_security.threadLocal.UserThreadLocal;
import org.example.multimedia_file_security.utils.Sm4EncryptionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

@RestController
@Slf4j
public class ImagePreviewController {

    @Autowired
    private FileService fileService;

    @Autowired
    private Sm4EncryptionUtil sm4EncryptionUtil;

    /**
     * 文件预览接口 - 直接返回加密后的文件数据
     * 图片：浏览器直接显示雪花图；音频：浏览器/Postman直接播放
     */
    @GetMapping("/{fileId}/preview")
    public ResponseEntity<byte[]> previewFile(
            @PathVariable Long fileId,
            @RequestParam(required = false) Integer width,
            @RequestParam(required = false) Integer height,
            @RequestParam(required = false, defaultValue = "false") boolean original) {

        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401).build();
            }

            FileRecord fileRecord = fileService.getFileRecordById(fileId);
            if (fileRecord == null) {
                return ResponseEntity.notFound().build();
            }

            if (!isPreviewableFile(fileRecord.getFileType(), fileRecord.getOriginalFilename())) {
                return ResponseEntity.badRequest().build();
            }

            byte[] fileData = fileService.getEncryptedFileData(fileId);
            if (fileData == null || fileData.length == 0) {
                return ResponseEntity.notFound().build();
            }

            String contentType = getFileContentType(fileRecord.getOriginalFilename(),
                    fileRecord.getFileType());

            byte[] responseData = fileData;
            if ((width != null || height != null) && isImageFile(fileRecord.getFileType(), fileRecord.getOriginalFilename())) {
                responseData = generateThumbnail(fileData,
                        fileRecord.getOriginalFilename(),
                        width != null ? width : 300,
                        height != null ? height : 300);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(contentType));
            headers.setContentLength(responseData.length);
            headers.setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).cachePublic());

            log.info("文件预览成功: fileId={}, filename={}, size={}, contentType={}",
                    fileId, fileRecord.getOriginalFilename(), responseData.length, contentType);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(responseData);

        } catch (Exception e) {
            log.error("文件预览失败", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * 获取图片信息（元数据）
     */
    @GetMapping("/{fileId}/image-info")
    public ResponseEntity<ImageInfoDTO> getImageInfo(@PathVariable Long fileId) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401).build();
            }

            FileRecord fileRecord = fileService.getFileRecordById(fileId);
            if (fileRecord == null) {
                return ResponseEntity.notFound().build();
            }

            if (!isImageFile(fileRecord.getFileType(), fileRecord.getOriginalFilename())) {
                return ResponseEntity.badRequest().build();
            }

            // 获取加密后的图片数据
            byte[] imageData = fileService.getEncryptedFileData(fileId);

            ImageInfoDTO info = new ImageInfoDTO();
            info.setFileId(fileId);
            info.setFilename(fileRecord.getOriginalFilename());
            info.setFileSize(fileRecord.getFileSize());
            info.setFileType(fileRecord.getFileType());
            info.setUploadTime(fileRecord.getUploadTime());
            info.setEncryptionMode(fileRecord.getEncryptionMode());

            // 分析图片尺寸
            ImageDimensions dimensions = analyzeImageDimensions(imageData,
                    fileRecord.getOriginalFilename());
            info.setWidth(dimensions.getWidth());
            info.setHeight(dimensions.getHeight());
            info.setFormat(dimensions.getFormat());

            // 预览URL
            info.setPreviewUrl("/api/files/" + fileId + "/preview");
            info.setThumbnailUrl("/api/files/" + fileId + "/preview/thumbnail");
            info.setDownloadUrl("/api/files/" + fileId + "/download");

            return ResponseEntity.ok(info);

        } catch (Exception e) {
            log.error("获取图片信息失败", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * 获取缩略图
     */
    @GetMapping("/{fileId}/preview/thumbnail")
    public ResponseEntity<byte[]> getThumbnail(
            @PathVariable Long fileId,
            @RequestParam(defaultValue = "150") int size) {

        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401).build();
            }

            FileRecord fileRecord = fileService.getFileRecordById(fileId);
            if (fileRecord == null) {
                return ResponseEntity.notFound().build();
            }

            if (!isImageFile(fileRecord.getFileType(), fileRecord.getOriginalFilename())) {
                return ResponseEntity.badRequest().build();
            }

            byte[] imageData = fileService.getEncryptedFileData(fileId);
            byte[] thumbnail = generateThumbnail(imageData,
                    fileRecord.getOriginalFilename(), size, size);

            if (thumbnail == null) {
                return ResponseEntity.notFound().build();
            }

            HttpHeaders headers = new HttpHeaders();
            String contentType = getImageContentType(fileRecord.getOriginalFilename(),
                    fileRecord.getFileType());
            headers.setContentType(MediaType.parseMediaType(contentType));

            // 缩略图缓存更长
            headers.setCacheControl(CacheControl.maxAge(Duration.ofDays(30)).cachePublic());
            headers.set("X-Thumbnail-Size", size + "x" + size);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(thumbnail);

        } catch (Exception e) {
            log.error("生成缩略图失败", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * 检查是否为图片文件
     */
    private boolean isImageFile(String contentType, String filename) {
        if (contentType != null && contentType.startsWith("image/")) {
            return true;
        }

        if (filename != null) {
            String lower = filename.toLowerCase();
            return lower.endsWith(".jpg") || lower.endsWith(".jpeg") ||
                    lower.endsWith(".png") || lower.endsWith(".gif") ||
                    lower.endsWith(".bmp") || lower.endsWith(".webp") ||
                    lower.endsWith(".tiff") || lower.endsWith(".svg");
        }

        return false;
    }

    /**
     * 检查是否为音频文件
     */
    private boolean isAudioFile(String contentType, String filename) {
        if (contentType != null && contentType.startsWith("audio/")) {
            return true;
        }

        if (filename != null) {
            String lower = filename.toLowerCase();
            return lower.endsWith(".mp3") || lower.endsWith(".wav") ||
                    lower.endsWith(".ogg") || lower.endsWith(".flac") ||
                    lower.endsWith(".aac") || lower.endsWith(".m4a") ||
                    lower.endsWith(".wma");
        }

        return false;
    }

    /**
     * 检查是否为支持预览的文件类型
     */
    private boolean isPreviewableFile(String contentType, String filename) {
        return isImageFile(contentType, filename) || isAudioFile(contentType, filename);
    }

    /**
     * 获取文件Content-Type
     */
    private String getFileContentType(String filename, String originalType) {
        if (originalType != null && (originalType.startsWith("image/") || originalType.startsWith("audio/"))) {
            return originalType;
        }

        if (filename != null) {
            String lower = filename.toLowerCase();
            // 图片类型
            if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
                return "image/jpeg";
            } else if (lower.endsWith(".png")) {
                return "image/png";
            } else if (lower.endsWith(".gif")) {
                return "image/gif";
            } else if (lower.endsWith(".bmp")) {
                return "image/bmp";
            } else if (lower.endsWith(".webp")) {
                return "image/webp";
            } else if (lower.endsWith(".svg")) {
                return "image/svg+xml";
            }
            // 音频类型
            else if (lower.endsWith(".mp3")) {
                return "audio/mpeg";
            } else if (lower.endsWith(".wav")) {
                return "audio/wav";
            } else if (lower.endsWith(".ogg")) {
                return "audio/ogg";
            } else if (lower.endsWith(".flac")) {
                return "audio/flac";
            } else if (lower.endsWith(".aac")) {
                return "audio/aac";
            } else if (lower.endsWith(".m4a")) {
                return "audio/mp4";
            } else if (lower.endsWith(".wma")) {
                return "audio/x-ms-wma";
            }
        }

        return "application/octet-stream";
    }

    /**
     * 获取图片Content-Type
     */
    private String getImageContentType(String filename, String originalType) {
        if (originalType != null && originalType.startsWith("image/")) {
            return originalType;
        }

        if (filename != null) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
                return "image/jpeg";
            } else if (lower.endsWith(".png")) {
                return "image/png";
            } else if (lower.endsWith(".gif")) {
                return "image/gif";
            } else if (lower.endsWith(".bmp")) {
                return "image/bmp";
            } else if (lower.endsWith(".webp")) {
                return "image/webp";
            } else if (lower.endsWith(".svg")) {
                return "image/svg+xml";
            }
        }

        return "application/octet-stream";
    }

    /**
     * 分析图片尺寸
     */
    private ImageDimensions analyzeImageDimensions(byte[] imageData, String filename) {
        ImageDimensions dimensions = new ImageDimensions();
        dimensions.setFormat(getImageFormat(filename));

        try {
            // 尝试解析常见图片格式获取尺寸
            if (filename.toLowerCase().endsWith(".bmp")) {
                dimensions = parseBmpDimensions(imageData);
            } else if (filename.toLowerCase().endsWith(".png")) {
                dimensions = parsePngDimensions(imageData);
            } else if (filename.toLowerCase().endsWith(".jpg") ||
                    filename.toLowerCase().endsWith(".jpeg")) {
                dimensions = parseJpegDimensions(imageData);
            }
        } catch (Exception e) {
            log.warn("解析图片尺寸失败: {}", e.getMessage());
        }

        return dimensions;
    }

    /**
     * 解析BMP图片尺寸
     */
    private ImageDimensions parseBmpDimensions(byte[] data) {
        ImageDimensions dim = new ImageDimensions();
        dim.setFormat("BMP");

        if (data.length >= 18) {
            int width = ((data[18] & 0xFF) |
                    ((data[19] & 0xFF) << 8) |
                    ((data[20] & 0xFF) << 16) |
                    ((data[21] & 0xFF) << 24));

            int height = ((data[22] & 0xFF) |
                    ((data[23] & 0xFF) << 8) |
                    ((data[24] & 0xFF) << 16) |
                    ((data[25] & 0xFF) << 24));

            dim.setWidth(Math.abs(width));
            dim.setHeight(Math.abs(height));
        }

        return dim;
    }

    /**
     * 解析PNG图片尺寸
     */
    private ImageDimensions parsePngDimensions(byte[] data) {
        ImageDimensions dim = new ImageDimensions();
        dim.setFormat("PNG");

        // PNG: 查找IHDR块
        for (int i = 0; i < data.length - 20; i++) {
            if (data[i] == 'I' && data[i+1] == 'H' &&
                    data[i+2] == 'D' && data[i+3] == 'R') {

                int width = ((data[i+4] & 0xFF) << 24) |
                        ((data[i+5] & 0xFF) << 16) |
                        ((data[i+6] & 0xFF) << 8) |
                        (data[i+7] & 0xFF);

                int height = ((data[i+8] & 0xFF) << 24) |
                        ((data[i+9] & 0xFF) << 16) |
                        ((data[i+10] & 0xFF) << 8) |
                        (data[i+11] & 0xFF);

                dim.setWidth(width);
                dim.setHeight(height);
                break;
            }
        }

        return dim;
    }

    /**
     * 解析JPEG图片尺寸
     */
    private ImageDimensions parseJpegDimensions(byte[] data) {
        ImageDimensions dim = new ImageDimensions();
        dim.setFormat("JPEG");

        int i = 0;
        while (i < data.length - 1) {
            // JPEG标记以0xFF开始
            if ((data[i] & 0xFF) == 0xFF) {
                int marker = data[i+1] & 0xFF;

                // SOF0, SOF2标记包含尺寸信息
                if (marker >= 0xC0 && marker <= 0xC3) {
                    int height = ((data[i+5] & 0xFF) << 8) | (data[i+6] & 0xFF);
                    int width = ((data[i+7] & 0xFF) << 8) | (data[i+8] & 0xFF);

                    dim.setWidth(width);
                    dim.setHeight(height);
                    break;
                }

                // 跳过标记段
                int length = ((data[i+2] & 0xFF) << 8) | (data[i+3] & 0xFF);
                i += length + 2;
            } else {
                i++;
            }
        }

        return dim;
    }

    /**
     * 获取图片格式
     */
    private String getImageFormat(String filename) {
        if (filename == null) return "UNKNOWN";

        String lower = filename.toLowerCase();
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "JPEG";
        } else if (lower.endsWith(".png")) {
            return "PNG";
        } else if (lower.endsWith(".gif")) {
            return "GIF";
        } else if (lower.endsWith(".bmp")) {
            return "BMP";
        } else if (lower.endsWith(".webp")) {
            return "WEBP";
        } else if (lower.endsWith(".svg")) {
            return "SVG";
        } else {
            return "UNKNOWN";
        }
    }

    /**
     * 生成缩略图
     */
    private byte[] generateThumbnail(byte[] originalImage, String filename,
                                     int maxWidth, int maxHeight) {
        try {

            if (originalImage.length < 10240 * 10240) { // 小于10MB的图片直接返回
                return originalImage;
            }

            // 对于大图片，返回一个占位图
            return createPlaceholderImage(maxWidth, maxHeight, filename);

        } catch (Exception e) {
            log.error("生成缩略图失败", e);
            return createPlaceholderImage(maxWidth, maxHeight, filename);
        }
    }

    /**
     * 创建占位图
     */
    private byte[] createPlaceholderImage(int width, int height, String filename) {
        // 创建一个简单的SVG占位图
        String svg = String.format(
                "<svg width=\"%d\" height=\"%d\" xmlns=\"http://www.w3.org/2000/svg\">" +
                        "<rect width=\"100%%\" height=\"100%%\" fill=\"#f0f0f0\"/>" +
                        "<text x=\"50%%\" y=\"50%%\" text-anchor=\"middle\" dy=\".3em\" " +
                        "font-family=\"Arial\" font-size=\"20\" fill=\"#999\">" +
                        "预览: %s</text>" +
                        "</svg>",
                width, height, filename
        );

        return svg.getBytes(StandardCharsets.UTF_8);
    }

    // DTO类
    @Data
    public static class ImageInfoDTO {
        private Long fileId;
        private String filename;
        private Long fileSize;
        private String fileType;
        private String format; // JPEG, PNG, etc
        private Integer width;
        private Integer height;
        private String encryptionMode;
        private String previewUrl;
        private String thumbnailUrl;
        private String downloadUrl;
        private java.time.LocalDateTime uploadTime;
    }

    @Data
    public static class ImageDimensions {
        private int width = 0;
        private int height = 0;
        private String format = "UNKNOWN";
    }
}