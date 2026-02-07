package org.example.multimedia_file_security.controller;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.service.FileService;
import org.example.multimedia_file_security.threadLocal.UserThreadLocal;
import org.example.multimedia_file_security.utils.MinioUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@Slf4j
public class FileController {

    @Resource
    private MinioUtil minioUtil;

    @Autowired
    private FileService fileService;

    // 测试文件上传接口
    @PostMapping("/file/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "请选择要上传的文件";
        }
        // 调用工具类上传，自动创建桶（若不存在）
        String fileUrl = minioUtil.putObject(file);
        return fileUrl == null ? "文件上传失败" : "文件上传成功，访问路径：" + fileUrl;
    }

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
}
