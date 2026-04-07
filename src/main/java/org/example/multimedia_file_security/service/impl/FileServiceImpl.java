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
import org.example.multimedia_file_security.utils.PngSelectiveEncryptionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

        // 4. 计算哈希值（根据加密模式选择）
        String fileHash;
        String pixelHash = null;
        String originalFilename = file.getOriginalFilename();

        if ("SELECTIVE".equals(encryptionMode) && isImageFile(originalFilename)) {
            // 选择性加密图像：计算像素级哈希
            pixelHash = calculatePixelHash(file.getBytes(), originalFilename);
            fileHash = pixelHash;  // 文件哈希也用像素哈希（或可以额外存储文件哈希用于其他用途）
            log.info("选择性加密模式，计算像素级SM3哈希: {}", pixelHash);
        } else {
            // 全文件加密或其他：计算文件级哈希
            fileHash = calculateHash(file.getBytes());
            log.info("全文件加密模式，计算文件级SM3哈希: {}", fileHash);
        }

        // 5. 加密文件
        byte[] encryptedData = encryptFile(file, sm4Key, encryptionMode);

        // 6. 生成加密文件名
        String encryptedFilename = generateEncryptedFilename(originalFilename);

        // 7. 使用SM2公钥加密SM4秘钥
        String encryptedSm4KeyBySM2PublicKey = encryptWithPublicKey(sm4Key, uploaderPublicKey);

        // 8. 生成数字签名
        String SM2PrivateKey = decryptPrivateKey(uploader.getEncryptedSm2PrivateKey());
        String digitalSignature = signWithSm2(encryptedSm4KeyBySM2PublicKey, SM2PrivateKey);

        // 9. 保存加密文件到MinIO
        String filePath = saveEncryptedFileToMinio(encryptedData, originalFilename, userId);

        // 10. 保存文件记录
        FileRecord record = new FileRecord();
        record.setOriginalFilename(originalFilename);
        record.setEncryptedFilename(encryptedFilename);
        record.setFilePath(filePath);
        record.setFileType(file.getContentType());
        record.setFileSize((long) encryptedData.length); // 使用加密后文件大小
        record.setSm3Hash(fileHash);
        record.setPixelSm3Hash(pixelHash);  // 新增：像素级哈希
        record.setEncryptedSm4Key(encryptedSm4KeyBySM2PublicKey);
        record.setDigitalSignature(digitalSignature);
        record.setEncryptionMode(encryptionMode);
        record.setUserId(userId);
        record.setUploadTime(LocalDateTime.now());
        record.setUpdatedTime(LocalDateTime.now());
        record.setDownloadCount(0);

        fileRecordMapper.insert(record);

        log.info("文件上传成功: {}, 加密模式: {}, 像素哈希: {}",
                originalFilename, encryptionMode, pixelHash != null ? pixelHash.substring(0, 16) + "..." : "N/A");

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

    /**
     * 判断是否为图像文件
     */
    private boolean isImageFile(String filename) {
        if (filename == null) return false;
        String lower = filename.toLowerCase();
        return lower.endsWith(".bmp") || lower.endsWith(".png") ||
                lower.endsWith(".jpg") || lower.endsWith(".jpeg") ||
                lower.endsWith(".gif") || lower.endsWith(".webp");
    }

    /**
     * 计算像素级SM3哈希（用于选择性加密验证）
     */
    private String calculatePixelHash(byte[] fileData, String filename) throws Exception {
        String ext = filename.toLowerCase();

        if (ext.endsWith(".bmp")) {
            return calculateBmpPixelHash(fileData);
        } else if (ext.endsWith(".png")) {
            return calculatePngPixelHash(fileData);
        } else if (ext.endsWith(".jpg") || ext.endsWith(".jpeg")) {
            return calculateJpgPixelHash(fileData);
        } else {
            // 非图像文件，返回文件哈希
            return calculateHash(fileData);
        }
    }

    /**
     * BMP像素级哈希计算
     */
    private String calculateBmpPixelHash(byte[] bmpData) throws Exception {
        if (bmpData.length < 54) {
            throw new RuntimeException("BMP文件过小");
        }

        // 解析BMP信息
        int pixelOffset = ((bmpData[10] & 0xFF) |
                ((bmpData[11] & 0xFF) << 8) |
                ((bmpData[12] & 0xFF) << 16) |
                ((bmpData[13] & 0xFF) << 24));

        int width = ((bmpData[18] & 0xFF) |
                ((bmpData[19] & 0xFF) << 8) |
                ((bmpData[20] & 0xFF) << 16) |
                ((bmpData[21] & 0xFF) << 24));

        int height = ((bmpData[22] & 0xFF) |
                ((bmpData[23] & 0xFF) << 8) |
                ((bmpData[24] & 0xFF) << 16) |
                ((bmpData[25] & 0xFF) << 24));

        int bitsPerPixel = ((bmpData[28] & 0xFF) |
                ((bmpData[29] & 0xFF) << 8));

        int bytesPerPixel = bitsPerPixel / 8;
        int rowSize = width * bytesPerPixel;
        int padding = (4 - (rowSize % 4)) % 4;
        rowSize += padding;
        int absHeight = Math.abs(height);

        // 提取像素数据（RGB，跳过填充字节）
        ByteArrayOutputStream pixelStream = new ByteArrayOutputStream();

        for (int row = 0; row < absHeight; row++) {
            int rowStart = pixelOffset + row * rowSize;
            for (int col = 0; col < width; col++) {
                int pixelStart = rowStart + col * bytesPerPixel;
                if (pixelStart + 2 < bmpData.length) {
                    pixelStream.write(bmpData[pixelStart]);      // B
                    pixelStream.write(bmpData[pixelStart + 1]);  // G
                    pixelStream.write(bmpData[pixelStart + 2]);  // R
                }
            }
        }

        String hash = calculateHash(pixelStream.toByteArray());
        log.debug("BMP像素哈希: 宽={}, 高={}, 像素字节={}, 哈希={}",
                width, absHeight, pixelStream.size(), hash.substring(0, 16) + "...");
        return hash;
    }

    /**
     * PNG像素级哈希计算
     */
    private String calculatePngPixelHash(byte[] pngData) throws Exception {
        // 使用PNG工具类解析
        PngSelectiveEncryptionUtil.PngInfo pngInfo =
                PngSelectiveEncryptionUtil.parsePng(pngData);

        if (pngInfo.getIdatChunks().isEmpty()) {
            throw new RuntimeException("PNG没有IDAT数据块");
        }

        // 合并所有IDAT块数据
        ByteArrayOutputStream idatStream = new ByteArrayOutputStream();
        for (PngSelectiveEncryptionUtil.PngChunk chunk : pngInfo.getIdatChunks()) {
            idatStream.write(chunk.getData());
        }

        // 解压得到原始像素数据（包括过滤字节）
        byte[] pixelData = PngSelectiveEncryptionUtil.decompressData(idatStream.toByteArray());

        String hash = calculateHash(pixelData);
        log.debug("PNG像素哈希: 宽={}, 高={}, 解压后={}, 哈希={}",
                pngInfo.getWidth(), pngInfo.getHeight(), pixelData.length,
                hash.substring(0, 16) + "...");
        return hash;
    }

    /**
     * JPG像素级哈希计算
     */
    private String calculateJpgPixelHash(byte[] jpgData) throws Exception {
        // 使用ImageIO读取像素
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(jpgData));
        if (image == null) {
            throw new RuntimeException("无法解码JPG图像");
        }

        int width = image.getWidth();
        int height = image.getHeight();

        // 提取RGB像素数据（跳过Alpha）
        ByteArrayOutputStream pixelStream = new ByteArrayOutputStream();

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                // 提取RGB分量
                pixelStream.write((rgb >> 16) & 0xFF);  // R
                pixelStream.write((rgb >> 8) & 0xFF);   // G
                pixelStream.write(rgb & 0xFF);          // B
            }
        }

        String hash = calculateHash(pixelStream.toByteArray());
        log.debug("JPG像素哈希: 宽={}, 高={}, 像素字节={}, 哈希={}",
                width, height, pixelStream.size(), hash.substring(0, 16) + "...");
        return hash;
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
            byte[] decryptedData = decryptFile(encryptedData, sm4Key,
                    fileRecord.getEncryptionMode(), fileRecord.getOriginalFilename());

            // 8. 验证文件完整性（根据加密模式选择验证方式）
            if (!fileRecord.getOriginalFilename().endsWith(".jpg") && !fileRecord.getOriginalFilename().endsWith(".jpeg")){
                if ("SELECTIVE".equals(fileRecord.getEncryptionMode()) &&
                        isImageFile(fileRecord.getOriginalFilename())) {
                    // 选择性加密图像：验证像素级哈希
                    verifyPixelHash(decryptedData, fileRecord.getOriginalFilename(),
                            fileRecord.getPixelSm3Hash());
                } else {
                    // 全文件加密或其他：验证文件级哈希
                    verifyFileHash(decryptedData, fileRecord.getSm3Hash());
                }
            }

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

            log.info("用户[{}]成功下载文件[{}]: {}, 大小={}字节",
                    userId, fileId, fileRecord.getOriginalFilename(), decryptedData.length);
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
     * 验证文件哈希（全文件加密模式）
     */
    private void verifyFileHash(byte[] decryptedData, String storedHash) throws Exception {
        if (storedHash == null || storedHash.isEmpty()) {
            log.warn("文件哈希记录不存在，跳过验证");
            return;
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
     * 验证像素哈希（选择性加密图像模式）
     */
    private void verifyPixelHash(byte[] decryptedData, String originalFilename,
                                 String storedPixelHash) throws Exception {
        if (storedPixelHash == null || storedPixelHash.isEmpty()) {
            log.warn("像素哈希记录不存在（可能是旧数据），尝试文件哈希验证");
            // 降级为文件哈希验证（兼容性处理）
            verifyFileHash(decryptedData, storedPixelHash);
            return;
        }

        // 计算解密后数据的像素哈希
        String calculatedPixelHash = calculatePixelHash(decryptedData, originalFilename);

        log.debug("像素哈希验证: 存储={}, 计算={}",
                storedPixelHash.substring(0, 16) + "...",
                calculatedPixelHash.substring(0, 16) + "...");

        if (!storedPixelHash.equals(calculatedPixelHash)) {
            log.error("像素哈希验证失败!");
            log.error("存储的像素哈希: {}", storedPixelHash);
            log.error("计算的像素哈希: {}", calculatedPixelHash);
            throw new SecurityException("图像内容完整性验证失败，文件可能被篡改");
        }

        log.info("像素哈希验证通过");
    }

    /**
     * 解密文件数据
     */
    private byte[] decryptFile(byte[] encryptedData, String sm4Key,
                               String encryptionMode, String originalFilename) throws Exception {
        log.info("解密文件: 模式={}, 文件名={}, 数据大小={}字节",
                encryptionMode, originalFilename, encryptedData.length);

        byte[] decryptedData;

        if ("SELECTIVE".equals(encryptionMode)) {
            // 选择性解密
            decryptedData = selectiveDecrypt(encryptedData, originalFilename, sm4Key);
        } else {
            // 全文件解密
            decryptedData = fullDecrypt(encryptedData, sm4Key);
        }

        log.info("解密完成: 输出大小={}字节", decryptedData.length);
        return decryptedData;
    }

    @Override
    public boolean deleteFile(Long fileId, Long userId) {
        String filePath = fileRecordMapper.selectById(fileId).getFilePath();
        boolean result = fileRecordMapper.deleteById(fileId) > 0;
        if (result) {
            minioUtil.removeObject(filePath);
        } else {
            log.error("删除文件失败");
            return false;
        }
        return result;
    }

    @Override
    public List<FileRecord> getUserFiles(Long userId) {
        return fileRecordMapper.selectByUserId(userId);
    }

    @Override
    public FileRecord getFileRecordById(Long fileId) {
        return fileRecordMapper.selectById(fileId);
    }

    @Override
    public byte[] getEncryptedFileData(Long fileId) throws Exception {
        FileRecord fileRecord = fileRecordMapper.selectById(fileId);
        if (fileRecord != null) {
            return minioUtil.getObjectByByteArray(fileRecord.getFilePath());
        } else {
            throw new Exception("文件不存在");
        }
    }
}