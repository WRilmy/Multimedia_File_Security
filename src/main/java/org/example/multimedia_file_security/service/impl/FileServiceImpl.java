package org.example.multimedia_file_security.service.impl;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.dto.FileDownloadDTO;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.mapper.FileRecordMapper;
import org.example.multimedia_file_security.mapper.UserMapper;
import org.example.multimedia_file_security.pojo.FileRecord;
import org.example.multimedia_file_security.pojo.User;
import org.example.multimedia_file_security.service.FileService;
import org.example.multimedia_file_security.utils.MinioUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.example.multimedia_file_security.utils.AESUtil.decryptPrivateKey;
import static org.example.multimedia_file_security.utils.Sm2Util.*;
import static org.example.multimedia_file_security.utils.Sm3Util.calculateHash;
import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.*;
import static org.example.multimedia_file_security.utils.Sm4Util.generateSm4Key;

@Service
@Slf4j
public class FileServiceImpl implements FileService {

    @Autowired
    private FileRecordMapper fileRecordMapper;

    @Resource
    private MinioUtil minioUtil;

    @Autowired
    private UserMapper userMapper;


    @Override
    public Result uploadFile(MultipartFile file, Long userId, String encryptionMode) throws Exception {
        // 1. 文件验证
        if (file.isEmpty()) {
            throw new RuntimeException("文件不能为空");
        }

        // 2. 获取上传者SM2公钥
        User uploader = userMapper.selectById(userId);
        String uploaderPublicKey = uploader.getSm2PublicKey();

        // 3. 生成SM4密钥
        SecretKey secretKey = generateSm4Key();
        String sm4Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        // 4. 计算源文件的SM3哈希值，在解密后验证确保没有被篡改
        String fileHash = calculateHash(file.getBytes());

        // 5. 加密文件
        byte[] encryptedData = encryptFile(file, sm4Key, encryptionMode);

        // 6. 生成加密文件名
        String encryptedFilename = generateEncryptedFilename(file.getOriginalFilename());

        // 7. 使用SM2公钥加密SM4秘钥
        String encryptedSm4KeyBySM2PublicKey = encryptWithPublicKey(sm4Key, uploaderPublicKey);

        // 8. 生成数字签名
        String SM2PrivateKey = decryptPrivateKey(uploader.getEncryptedSm2PrivateKey());
        String digitalSignature = signWithSm2(encryptedSm4KeyBySM2PublicKey, SM2PrivateKey);

        // 9. 保存加密文件到MinIO
        String filePath = saveEncryptedFileToMinio(encryptedData, file.getOriginalFilename(), userId);

        // 10. 保存文件记录
        FileRecord record = new FileRecord();
        record.setOriginalFilename(file.getOriginalFilename());
        record.setEncryptedFilename(encryptedFilename);
        record.setFilePath(filePath);
        record.setFileType(file.getContentType());
        record.setFileSize((long) encryptedData.length); // 使用加密后文件大小
        record.setSm3Hash(fileHash);
        record.setEncryptedSm4Key(encryptedSm4KeyBySM2PublicKey);
        record.setDigitalSignature(digitalSignature);
        record.setEncryptionMode(encryptionMode);
        record.setUserId(userId);
        record.setUploadTime(LocalDateTime.now());
        record.setUpdatedTime(LocalDateTime.now());
        record.setDownloadCount(0);

        fileRecordMapper.insert(record);

        return Result.success("上传成功");
    }

    /**
     * 保存加密文件到MinIO
     */
    private String saveEncryptedFileToMinio(byte[] encryptedData, String originalFilename, Long userId) throws Exception {
        // 生成唯一文件名
        String encryptedFilename = generateEncryptedFilename(originalFilename);

        // 构建文件路径：user/{userId}/{encryptedFilename}
        String objectName = String.format("user/%d/%s", userId, encryptedFilename);

        // 上传加密数据到MinIO
        return minioUtil.putObject(encryptedData, objectName, "application/octet-stream");
    }

    /**
     * 生成加密文件名
     */
    private String generateEncryptedFilename(String originalFilename) {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        int dotIndex = originalFilename.lastIndexOf('.');
        String extension = "";
        if (dotIndex > 0) {
            extension = originalFilename.substring(dotIndex);
        }
        return "encrypted_" + uuid + extension;
    }

    private byte[] encryptFile(MultipartFile file, String sm4Key, String encryptionMode) throws Exception {
        if ("SELECTIVE".equals(encryptionMode)) {
            // 选择性加密
            return selectiveEncrypt(file, sm4Key);
        } else {
            // 全文件加密
            return fullEncrypt(file.getBytes(), sm4Key);
        }
    }

    @Override
    public Result downloadFile(Long fileId, Long userId) {
        try {
            log.info("用户[{}]开始下载文件[{}]", userId, fileId);

            // 1. 验证文件存在性和权限
            FileRecord fileRecord = validateFileAccess(fileId, userId);

            // 2. 获取上传者信息
            User uploader = userMapper.selectById(fileRecord.getUserId());
            if (uploader == null) {
                throw new RuntimeException("文件上传者不存在");
            }

            // 3. 获取用户私钥（需要密码）
            String userPrivateKey = decryptPrivateKey(uploader.getEncryptedSm2PrivateKey());

            // 4. 验证数字签名
            verifyDigitalSignature(fileRecord, uploader.getSm2PublicKey());

            // 5. 从MinIO获取加密文件
            byte[] encryptedData = minioUtil.getObjectByByteArray(fileRecord.getFilePath());
            if (encryptedData == null || encryptedData.length == 0) {
                throw new RuntimeException("文件数据为空或不存在");
            }

            // 6. 解密SM4密钥
            String sm4Key = decryptWithPrivateKey(fileRecord.getEncryptedSm4Key(), userPrivateKey);

            // 7. 解密文件数据
            byte[] decryptedData = decryptFile(encryptedData, sm4Key, fileRecord.getEncryptionMode(), fileRecord.getOriginalFilename());

            // 8. 验证文件哈希
            verifyFileHash(decryptedData, fileRecord.getSm3Hash());

            // 9. 返回下载结果
            FileDownloadDTO result = new FileDownloadDTO();
            result.setFileId(fileId);
            result.setOriginalFilename(fileRecord.getOriginalFilename());
            result.setFileData(decryptedData);
            result.setFileType(fileRecord.getFileType());
            result.setFileSize(decryptedData.length);
            result.setDownloadTime(LocalDateTime.now());
            result.setSignatureValid(true);
            result.setHashValid(true);

            log.info("用户[{}]成功下载文件[{}]: {}", userId, fileId, fileRecord.getOriginalFilename());
            return Result.success("文件下载成功", result);

        } catch (SecurityException e) {
            log.error("文件[{}]安全验证失败: {}", fileId, e.getMessage());
            return Result.error(403, "文件验证失败: " + e.getMessage());
        } catch (Exception e) {
            log.error("下载文件[{}]失败: {}", fileId, e.getMessage(), e);
            return Result.error(500, "文件下载失败: " + e.getMessage());
        }
    }

    /**
     * 验证文件访问权限
     */
    private FileRecord validateFileAccess(Long fileId, Long userId) {
        // 获取文件记录
        FileRecord fileRecord = fileRecordMapper.selectById(fileId);
        if (fileRecord == null) {
            throw new RuntimeException("文件不存在");
        }

        // 验证用户权限（这里假设只有上传者可以下载）
        if (!fileRecord.getUserId().equals(userId)) {
            throw new SecurityException("无权下载此文件");
        }

        return fileRecord;
    }

    /**
     * 验证数字签名
     */
    private void verifyDigitalSignature(FileRecord fileRecord, String publicKey) throws Exception {
        if (fileRecord.getDigitalSignature() == null || fileRecord.getDigitalSignature().isEmpty()) {
            throw new SecurityException("文件没有数字签名");
        }

        if (fileRecord.getEncryptedSm4Key() == null || fileRecord.getEncryptedSm4Key().isEmpty()) {
            throw new SecurityException("文件缺少加密密钥");
        }

        // 1. 验证SM4密钥的签名
        boolean isSignatureValid = verifyWithSm2(
                fileRecord.getEncryptedSm4Key(),
                fileRecord.getDigitalSignature(),
                publicKey
        );

        if (!isSignatureValid) {
            throw new SecurityException("数字签名验证失败，文件可能被篡改");
        }

        log.info("文件[{}]数字签名验证通过", fileRecord.getId());
    }

    /**
     * 验证文件哈希
     */
    private void verifyFileHash(byte[] decryptedData, String storedHash) throws Exception {
        if (storedHash == null || storedHash.isEmpty()) {
            throw new SecurityException("文件哈希记录不存在");
        }

        // 计算解密后文件的SM3哈希
        String calculatedHash = calculateHash(decryptedData);

        // 比较哈希值
        if (!storedHash.equals(calculatedHash)) {
            log.error("文件哈希验证失败!");
            log.error("存储的哈希: {}", storedHash);
            log.error("计算的哈希: {}", calculatedHash);
            throw new SecurityException("文件完整性验证失败，文件可能被篡改");
        }

        log.info("文件哈希验证通过");
    }

    /**
     * 解密文件数据
     */
    private byte[] decryptFile(byte[] encryptedData, String sm4Key, String encryptionMode, String originalFilename) throws Exception {
        if ("SELECTIVE".equals(encryptionMode)) {
            // 选择性解密
            return selectiveDecrypt(encryptedData, originalFilename, sm4Key);
        } else {
            // 全文件解密
            return fullDecrypt(encryptedData, sm4Key);
        }
    }

    @Override
    public boolean deleteFile(Long fileId, Long userId) {
        return false;
    }

    @Override
    public List<FileRecord> getUserFiles(Long userId) {
        return null;
    }
}
