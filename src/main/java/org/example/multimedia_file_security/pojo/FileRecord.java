package org.example.multimedia_file_security.pojo;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class FileRecord {

    private Long id;

    // 文件基础信息
    private String originalFilename;    // 原始文件名
    private String encryptedFilename;  // 加密后文件名
    private String filePath;          // 存储路径
    private String fileType;          // 文件类型
    private Long fileSize;            // 文件大小

    // 加密相关信息
    private String sm3Hash;           // 文件哈希值
    private String encryptedSm4Key;   // 加密的SM4密钥
    private String digitalSignature;  // 数字签名
    private String encryptionMode;    // 加密模式：FULL/SELECTIVE

    // 关联信息
    private Long userId;              // 所属用户
    private Integer downloadCount = 0;// 下载次数

    // 时间戳
    private LocalDateTime uploadTime;
    private LocalDateTime updatedTime;
}