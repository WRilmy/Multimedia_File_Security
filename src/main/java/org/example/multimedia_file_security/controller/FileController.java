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
                        .body("用户未登录".getBytes());
            }

            // 2. 调用服务层下载文件
            Result result = fileService.downloadFile(fileId, userId);

            if (result.getCode() != 200) {
                return ResponseEntity.status(result.getCode())
                        .body(result.getMessage().getBytes());
            }

            // 3. 获取下载结果
            FileDownloadDTO downloadResult = (FileDownloadDTO)result.getData();

            // 4. 准备HTTP响应
            String filename = downloadResult.getOriginalFilename();
            String encodedFilename = URLEncoder.encode(filename, StandardCharsets.UTF_8)
                    .replaceAll("\\+", "%20");

            byte[] fileData = downloadResult.getFileData();

            // 5. 设置响应头
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentLength(fileData.length);
            headers.setContentDispositionFormData("attachment", encodedFilename);
            headers.set("X-File-Id", fileId.toString());
            headers.set("X-Original-Filename", filename);
            headers.set("X-Signature-Valid", String.valueOf(downloadResult.getSignatureValid()));
            headers.set("X-Hash-Valid", String.valueOf(downloadResult.getHashValid()));
            headers.set("X-Download-Time", downloadResult.getDownloadTime().toString());

            return new ResponseEntity<>(fileData, headers, 200);

        } catch (Exception e) {
            log.error("文件下载失败", e);
            return ResponseEntity.status(500)
                    .body(("文件下载失败: " + e.getMessage()).getBytes());
        }
    }
}
