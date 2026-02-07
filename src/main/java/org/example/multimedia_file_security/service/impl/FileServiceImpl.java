package org.example.multimedia_file_security.service.impl;

import jakarta.annotation.Resource;
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
import static org.example.multimedia_file_security.utils.Sm2Util.encryptWithPublicKey;
import static org.example.multimedia_file_security.utils.Sm2Util.signWithSm2;
import static org.example.multimedia_file_security.utils.Sm3Util.calculateHash;
import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.*;
import static org.example.multimedia_file_security.utils.Sm4Util.generateSm4Key;

@Service
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
        String digitalSignature = signWithSm2(sm4Key, SM2PrivateKey);

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
        return null;
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
