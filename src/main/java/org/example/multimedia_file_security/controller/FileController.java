package org.example.multimedia_file_security.controller;

import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.dto.FileDownloadDTO;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.service.FileService;
import org.example.multimedia_file_security.threadLocal.UserThreadLocal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@Slf4j
public class FileController {

    @Autowired
    private FileService fileService;

    /**
     * 文件上传接口
     * @param file 上传的文件
     * @param encryptionMode 加密模式：FULL-全文件加密，SELECTIVE-选择性加密
     * @return 上传结果
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Result<?> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "encryptionMode", defaultValue = "FULL")
            String encryptionMode) {

        try {
            // 从请求中获取当前用户ID（这里需要您实现获取用户ID的逻辑）
            Long userId = UserThreadLocal.getCurrentId();

            if (userId == null) {
                return Result.error(401, "用户未登录");
            }

            // 记录上传日志
            log.info("用户[{}]开始上传文件: {}, 加密模式: {}",
                    userId, file.getOriginalFilename(), encryptionMode);

            // 调用服务层处理文件上传
            Result<?> result = fileService.uploadFile(file, userId, encryptionMode);

            // 记录上传结果
            if (result.getCode() == 200) {
                log.info("用户[{}]文件上传成功: {}", userId, file.getOriginalFilename());
            } else {
                log.warn("用户[{}]文件上传失败: {}, 原因: {}",
                        userId, file.getOriginalFilename(), result.getMessage());
            }

            return result;

        } catch (Exception e) {
            log.error("文件上传异常", e);
            return Result.error(500, "系统异常: " + e.getMessage());
        }
    }

    @GetMapping("/download/{fileId}")
    public ResponseEntity<byte[]> downloadFile(
            @PathVariable Long fileId) {

        try {
            // 1. 获取当前用户ID
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return ResponseEntity.status(401)
                        .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                        .body("用户未登录".getBytes(StandardCharsets.UTF_8));
            }

            // 3. 调用服务层下载文件
            Result result = fileService.downloadFile(fileId, userId);

            if (result.getCode() != 200) {
                return ResponseEntity.status(result.getCode())
                        .body(result.getMessage().getBytes(StandardCharsets.UTF_8));
            }

            // 4. 获取下载结果
            FileDownloadDTO downloadResult = (FileDownloadDTO) result.getData();

            // 5. 准备数据
            String originalFilename = downloadResult.getOriginalFilename();
            byte[] fileData = downloadResult.getFileData();
            String fileType = downloadResult.getFileType();

            // ✅ 6. 修复：正确设置响应头
            HttpHeaders headers = new HttpHeaders();

            // 6.1 设置内容类型
            if (fileType != null && !fileType.isEmpty()) {
                headers.setContentType(MediaType.parseMediaType(fileType));
            } else {
                // 根据文件扩展名设置类型
                String contentType = getContentTypeFromFilename(originalFilename);
                headers.setContentType(MediaType.parseMediaType(contentType));
            }

            // 6.2 设置内容长度
            headers.setContentLength(fileData.length);

            // 6.3 ✅ 修复：正确设置Content-Disposition
            String contentDisposition = createContentDisposition(originalFilename);
            headers.set(HttpHeaders.CONTENT_DISPOSITION, contentDisposition);

            // 6.4 设置缓存控制
            headers.setCacheControl("no-cache, no-store, must-revalidate");
            headers.setPragma("no-cache");
            headers.setExpires(0);

            // 6.5 设置自定义头
            headers.set("X-File-Id", fileId.toString());
            headers.set("X-Original-Filename", encodeForHeader(originalFilename));
            headers.set("X-Signature-Valid", String.valueOf(downloadResult.getSignatureValid()));
            headers.set("X-Hash-Valid", String.valueOf(downloadResult.getHashValid()));
            headers.set("X-Download-Time", downloadResult.getDownloadTime().toString());

            log.info("文件下载成功: fileId={}, filename={}, size={} bytes",
                    fileId, originalFilename, fileData.length);

            return new ResponseEntity<>(fileData, headers, 200);

        } catch (Exception e) {
            log.error("文件下载失败", e);
            return ResponseEntity.status(500)
                    .body(("文件下载失败: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * 创建正确的Content-Disposition头
     */
    private String createContentDisposition(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return "attachment";
        }

        try {
            // 清理文件名
            String cleanName = filename.trim()
                    .replaceAll(".*[/\\\\]", "")  // 移除路径
                    .replaceAll("[\\\\/:*?\"<>|]", "_");  // 替换非法字符

            if (cleanName.isEmpty()) {
                return "attachment";
            }

            // 对文件名进行URL编码
            String encodedFilename = URLEncoder.encode(cleanName, StandardCharsets.UTF_8.name())
                    .replace("+", "%20");

            // ✅ 修复：使用正确的Content-Disposition格式
            // 同时提供两种格式，浏览器会选择合适的
            return String.format(
                    "attachment; filename=\"%s\"; filename*=UTF-8''%s",
                    cleanName,  // 未编码，用于旧浏览器
                    encodedFilename  // 编码，用于新浏览器
            );

        } catch (Exception e) {
            log.error("创建Content-Disposition失败", e);
            return "attachment";
        }
    }

    /**
     * 根据文件名获取Content-Type
     */
    private String getContentTypeFromFilename(String filename) {
        if (filename == null) {
            return "application/octet-stream";
        }

        String lowerName = filename.toLowerCase();

        // 图片类型
        if (lowerName.endsWith(".jpg") || lowerName.endsWith(".jpeg")) {
            return "image/jpeg";
        } else if (lowerName.endsWith(".png")) {
            return "image/png";
        } else if (lowerName.endsWith(".gif")) {
            return "image/gif";
        } else if (lowerName.endsWith(".bmp")) {
            return "image/bmp";
        } else if (lowerName.endsWith(".webp")) {
            return "image/webp";
        }

        // 视频类型
        else if (lowerName.endsWith(".mp4")) {
            return "video/mp4";
        } else if (lowerName.endsWith(".avi")) {
            return "video/x-msvideo";
        } else if (lowerName.endsWith(".mov")) {
            return "video/quicktime";
        } else if (lowerName.endsWith(".mkv")) {
            return "video/x-matroska";
        } else if (lowerName.endsWith(".webm")) {
            return "video/webm";
        } else if (lowerName.endsWith(".flv")) {
            return "video/x-flv";
        } else if (lowerName.endsWith(".wmv")) {
            return "video/x-ms-wmv";
        }

        // 音频类型
        else if (lowerName.endsWith(".mp3")) {
            return "audio/mpeg";
        } else if (lowerName.endsWith(".wav")) {
            return "audio/wav";
        } else if (lowerName.endsWith(".ogg")) {
            return "audio/ogg";
        } else if (lowerName.endsWith(".flac")) {
            return "audio/flac";
        }

        // 文档类型
        else if (lowerName.endsWith(".pdf")) {
            return "application/pdf";
        } else if (lowerName.endsWith(".doc") || lowerName.endsWith(".docx")) {
            return "application/msword";
        } else if (lowerName.endsWith(".xls") || lowerName.endsWith(".xlsx")) {
            return "application/vnd.ms-excel";
        } else if (lowerName.endsWith(".ppt") || lowerName.endsWith(".pptx")) {
            return "application/vnd.ms-powerpoint";
        } else if (lowerName.endsWith(".txt")) {
            return "text/plain";
        } else if (lowerName.endsWith(".html") || lowerName.endsWith(".htm")) {
            return "text/html";
        } else if (lowerName.endsWith(".xml")) {
            return "text/xml";
        } else if (lowerName.endsWith(".json")) {
            return "application/json";
        }

        // 压缩文件
        else if (lowerName.endsWith(".zip")) {
            return "application/zip";
        } else if (lowerName.endsWith(".rar")) {
            return "application/x-rar-compressed";
        } else if (lowerName.endsWith(".7z")) {
            return "application/x-7z-compressed";
        } else if (lowerName.endsWith(".tar")) {
            return "application/x-tar";
        } else if (lowerName.endsWith(".gz")) {
            return "application/gzip";
        }

        // 默认
        return "application/octet-stream";
    }

    /**
     * 为HTTP头编码
     */
    private String encodeForHeader(String value) {
        if (value == null) {
            return "";
        }
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name())
                    .replace("+", "%20");
        } catch (Exception e) {
            return value;
        }
    }
}
