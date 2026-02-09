package org.example.multimedia_file_security.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

@Component
public class Sm4EncryptionUtil {

    static {
        // 注册BouncyCastle安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // SM4算法常量
    private static final String ALGORITHM = "SM4";
    private static final String TRANSFORMATION_CBC = "SM4/CBC/PKCS7Padding";
    private static final String TRANSFORMATION_ECB = "SM4/ECB/PKCS7Padding";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 16; // 128位IV

    /**
     * BMP文件信息结构
     */
    private static class BmpInfo {
        int fileSize;
        int pixelOffset;
        int infoHeaderSize;
        int width;
        int height;
        int bitsPerPixel;
        int compression;
        int imageSize;

        @Override
        public String toString() {
            return String.format(
                    "BmpInfo[width=%d, height=%d, bitsPerPixel=%d, pixelOffset=%d]",
                    width, height, bitsPerPixel, pixelOffset
            );
        }
    }

    /**
     * 解析BMP文件信息
     */
    private static BmpInfo parseBmpInfo(byte[] bmpData) {
        BmpInfo info = new BmpInfo();

        if (bmpData.length < 54) {
            throw new RuntimeException("BMP文件过小");
        }

        // 文件大小
        info.fileSize = ((bmpData[2] & 0xFF) |
                ((bmpData[3] & 0xFF) << 8) |
                ((bmpData[4] & 0xFF) << 16) |
                ((bmpData[5] & 0xFF) << 24));

        // 像素数据偏移
        info.pixelOffset = ((bmpData[10] & 0xFF) |
                ((bmpData[11] & 0xFF) << 8) |
                ((bmpData[12] & 0xFF) << 16) |
                ((bmpData[13] & 0xFF) << 24));

        // 信息头大小
        info.infoHeaderSize = ((bmpData[14] & 0xFF) |
                ((bmpData[15] & 0xFF) << 8) |
                ((bmpData[16] & 0xFF) << 16) |
                ((bmpData[17] & 0xFF) << 24));

        // 宽度和高度
        info.width = ((bmpData[18] & 0xFF) |
                ((bmpData[19] & 0xFF) << 8) |
                ((bmpData[20] & 0xFF) << 16) |
                ((bmpData[21] & 0xFF) << 24));

        info.height = ((bmpData[22] & 0xFF) |
                ((bmpData[23] & 0xFF) << 8) |
                ((bmpData[24] & 0xFF) << 16) |
                ((bmpData[25] & 0xFF) << 24));

        // 位深度
        info.bitsPerPixel = ((bmpData[28] & 0xFF) |
                ((bmpData[29] & 0xFF) << 8));

        // 压缩方式
        info.compression = ((bmpData[30] & 0xFF) |
                ((bmpData[31] & 0xFF) << 8) |
                ((bmpData[32] & 0xFF) << 16) |
                ((bmpData[33] & 0xFF) << 24));

        // 像素数据大小
        info.imageSize = ((bmpData[34] & 0xFF) |
                ((bmpData[35] & 0xFF) << 8) |
                ((bmpData[36] & 0xFF) << 16) |
                ((bmpData[37] & 0xFF) << 24));

        return info;
    }
    /**
     * 验证BMP格式
     */
    private static boolean isValidBmp(byte[] data) {
        if (data.length < 54) {
            return false;
        }

        // 检查文件签名
        if (data[0] != 'B' || data[1] != 'M') {
            return false;
        }

        return true;
    }


    /**
     * 全文件加密 - 对整个文件内容进行加密
     * @param fileData 文件数据字节数组
     * @param sm4Key SM4密钥（Base64格式）
     * @return 加密后的字节数组
     */
    public static byte[] fullEncrypt(byte[] fileData, String sm4Key) throws Exception {
        return fullEncrypt(fileData, sm4Key, "CBC");
    }

    /**
     * 全文件加密 - 支持选择加密模式
     * @param fileData 文件数据字节数组
     * @param sm4Key SM4密钥（Base64格式）
     * @param mode 加密模式：CBC或ECB
     * @return 加密后的字节数组（包含IV + 加密数据）
     */
    public static byte[] fullEncrypt(byte[] fileData, String sm4Key, String mode) throws Exception {
        if (fileData == null || fileData.length == 0) {
            throw new IllegalArgumentException("文件数据不能为空");
        }

        byte[] keyBytes = java.util.Base64.getDecoder().decode(sm4Key);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher;
        byte[] iv = new byte[IV_SIZE];

        if ("CBC".equalsIgnoreCase(mode)) {
            // CBC模式需要IV
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance(TRANSFORMATION_CBC, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else {
            // ECB模式不需要IV
            cipher = Cipher.getInstance(TRANSFORMATION_ECB, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            iv = new byte[0]; // ECB模式不使用IV
        }

        byte[] encryptedData = cipher.doFinal(fileData);

        // 返回格式：IV长度(1字节) + IV数据 + 加密数据
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv.length); // IV长度
        outputStream.write(iv);        // IV数据
        outputStream.write(encryptedData); // 加密数据

        return outputStream.toByteArray();
    }

    /**
     * 选择性加密 - 针对多媒体文件的智能加密
     * @param file 上传的文件
     * @param sm4Key SM4密钥（Base64格式）
     * @return 加密后的字节数组
     */
    public static byte[] selectiveEncrypt(MultipartFile file, String sm4Key) throws Exception {
        String filename = file.getOriginalFilename().toLowerCase();
        byte[] fileData = file.getBytes();

        // 根据文件类型选择不同的加密策略
        if (isImageFile(filename)) {
            return selectiveImageEncrypt(fileData, filename, sm4Key);
        } else if (isVideoFile(filename)) {
            return selectiveVideoEncrypt(fileData, filename, sm4Key);
        } else {
            // 默认使用全文件加密
            return fullEncrypt(fileData, sm4Key);
        }
    }


    /**
     * 选择性加密 - 扰乱特定像素
     * 保持文件可打开，显示雪花效果
     */
    public static byte[] selectiveImageEncrypt(byte[] imageData, String filename, String sm4Key) throws Exception {

        if (filename.endsWith(".bmp")) {
            return selectiveEncryptBmp(imageData, sm4Key);
        } else if (filename.endsWith(".png")) {
            return selectiveEncryptPng(imageData, sm4Key);
        } else {
            throw new RuntimeException("不支持的文件格式");
        }
    }

    /**
     * 可逆的BMP选择性加密 - XOR方案（推荐）
     */
    public static byte[] selectiveEncryptBmp(byte[] bmpData, String sm4Key) throws Exception {
        if (!isValidBmp(bmpData)) {
            throw new RuntimeException("无效的BMP文件");
        }

        BmpInfo info = parseBmpInfo(bmpData);
        System.out.println("XOR加密BMP信息: " + info);

        byte[] encryptedData = bmpData.clone();

        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        int bytesPerPixel = info.bitsPerPixel / 8;
        int rowSize = info.width * bytesPerPixel;
        int padding = (4 - (rowSize % 4)) % 4;
        rowSize += padding;

        int absHeight = Math.abs(info.height);

        for (int row = 0; row < absHeight; row++) {
            int rowStart = info.pixelOffset + row * rowSize;

            for (int col = 0; col < info.width; col++) {
                if (random.nextDouble() < 0.9) {
                    int pixelStart = rowStart + col * bytesPerPixel;

                    if (pixelStart >= 0 && pixelStart + 2 < encryptedData.length) {
                        byte maskB = (byte) random.nextInt(256);
                        byte maskG = (byte) random.nextInt(256);
                        byte maskR = (byte) random.nextInt(256);

                        encryptedData[pixelStart] ^= maskB;
                        encryptedData[pixelStart + 1] ^= maskG;
                        encryptedData[pixelStart + 2] ^= maskR;
                    }
                }
            }
        }

        return encryptedData;
    }

    /**
     * BMP选择性解密 - XOR方案
     */
    public static byte[] selectiveDecryptBmp(byte[] encryptedBmpData, String sm4Key) throws Exception {
        if (!isValidBmp(encryptedBmpData)) {
            throw new RuntimeException("无效的BMP文件");
        }

        BmpInfo info = parseBmpInfo(encryptedBmpData);
        System.out.println("XOR解密BMP信息: " + info);

        byte[] decryptedData = encryptedBmpData.clone();

        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        int bytesPerPixel = info.bitsPerPixel / 8;
        int rowSize = info.width * bytesPerPixel;
        int padding = (4 - (rowSize % 4)) % 4;
        rowSize += padding;

        int absHeight = Math.abs(info.height);

        for (int row = 0; row < absHeight; row++) {
            int rowStart = info.pixelOffset + row * rowSize;

            for (int col = 0; col < info.width; col++) {
                if (random.nextDouble() < 0.9) {
                    int pixelStart = rowStart + col * bytesPerPixel;

                    if (pixelStart >= 0 && pixelStart + 2 < decryptedData.length) {
                        byte maskB = (byte) random.nextInt(256);
                        byte maskG = (byte) random.nextInt(256);
                        byte maskR = (byte) random.nextInt(256);

                        decryptedData[pixelStart] ^= maskB;
                        decryptedData[pixelStart + 1] ^= maskG;
                        decryptedData[pixelStart + 2] ^= maskR;
                    }
                }
            }
        }

        return decryptedData;
    }

    /**
     * PNG选择性加密（简化版）
     */
    private static byte[] selectiveEncryptPng(byte[] pngData, String sm4Key) throws Exception {
        // PNG格式复杂，这里简化处理
        // TODO 实际上需要解析PNG的IDAT块

        // 1. 验证PNG签名
        byte[] pngSignature = { (byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        for (int i = 0; i < 8; i++) {
            if (pngData[i] != pngSignature[i]) {
                throw new RuntimeException("无效的PNG文件");
            }
        }

        // 2. 简单扰乱：在文件末尾添加一个无害的文本块
        // 这不会影响图片显示，但能证明文件被处理过
        String watermark = "ENCRYPTED_BY_SM4";
        byte[] watermarked = Arrays.copyOf(pngData, pngData.length + watermark.length());
        System.arraycopy(watermark.getBytes(), 0, watermarked, pngData.length, watermark.length());

        return watermarked;
    }

    /**
     * 视频文件选择性加密
     */
    private static byte[] selectiveVideoEncrypt(byte[] videoData, String filename, String sm4Key) throws Exception {
        // 视频选择性加密：加密关键帧数据
        int headerSize = getVideoHeaderSize(filename);

        if (headerSize >= videoData.length) {
            return fullEncrypt(videoData, sm4Key);
        }

        // 简单的块加密策略：每10KB数据选择加密30%
        int blockSize = 10 * 1024; // 10KB块
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // 保留文件头
        byte[] header = Arrays.copyOfRange(videoData, 0, headerSize);
        outputStream.write(header);

        // 对剩余数据分块处理
        byte[] videoContent = Arrays.copyOfRange(videoData, headerSize, videoData.length);
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < videoContent.length; i += blockSize) {
            int end = Math.min(i + blockSize, videoContent.length);
            byte[] block = Arrays.copyOfRange(videoContent, i, end);

            if (random.nextDouble() < 0.3) { // 30%的块进行加密
                byte[] encryptedBlock = fullEncrypt(block, sm4Key);
                outputStream.write(0x01); // 标记加密块
                outputStream.write(intToBytes(encryptedBlock.length)); // 加密块长度
                outputStream.write(encryptedBlock);
            } else {
                outputStream.write(0x00); // 标记未加密块
                outputStream.write(intToBytes(block.length)); // 原始块长度
                outputStream.write(block);
            }
        }

        return outputStream.toByteArray();
    }

    /**
     * 全文件解密
     */
    public static byte[] fullDecrypt(byte[] encryptedData, String sm4Key) throws Exception {
        return fullDecrypt(encryptedData, sm4Key, "CBC");
    }

    public static byte[] fullDecrypt(byte[] encryptedData, String sm4Key, String mode) throws Exception {
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("加密数据不能为空");
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encryptedData);

        // 读取IV信息
        int ivLength = inputStream.read();
        byte[] iv = new byte[ivLength];
        inputStream.read(iv);

        // 读取加密数据
        byte[] actualEncryptedData = new byte[encryptedData.length - 1 - ivLength];
        inputStream.read(actualEncryptedData);

        byte[] keyBytes = java.util.Base64.getDecoder().decode(sm4Key);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher;
        if ("CBC".equalsIgnoreCase(mode) && ivLength > 0) {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance(TRANSFORMATION_CBC, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher = Cipher.getInstance(TRANSFORMATION_ECB, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        return cipher.doFinal(actualEncryptedData);
    }

    /**
     * 选择性解密
     */
    public static byte[] selectiveDecrypt(byte[] encryptedData, String originalFilename, String sm4Key) throws Exception {
        String filename = originalFilename.toLowerCase();

        if (isImageFile(filename)) {
            return selectiveImageDecrypt(encryptedData, filename, sm4Key);
        } else if (isVideoFile(filename)) {
            return selectiveVideoDecrypt(encryptedData, filename, sm4Key);
        } else {
            return fullDecrypt(encryptedData, sm4Key);
        }
    }

    private static byte[] selectiveImageDecrypt(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        if (filename.endsWith(".bmp")) {
            return selectiveDecryptBmp(encryptedData, sm4Key);
        } else if (filename.endsWith(".png")) {
            return selectiveEncryptPng(encryptedData, sm4Key);
        } else {
            throw new RuntimeException("不支持的文件格式");
        }
    }

    private static byte[] selectiveVideoDecrypt(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        int headerSize = getVideoHeaderSize(filename);

        if (headerSize >= encryptedData.length) {
            return fullDecrypt(encryptedData, sm4Key);
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encryptedData);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // 读取文件头
        byte[] header = new byte[headerSize];
        inputStream.read(header);
        outputStream.write(header);

        // 处理数据块
        while (inputStream.available() > 0) {
            int blockType = inputStream.read(); // 块类型标记
            byte[] lengthBytes = new byte[4];
            inputStream.read(lengthBytes);
            int blockLength = bytesToInt(lengthBytes);

            byte[] blockData = new byte[blockLength];
            inputStream.read(blockData);

            if (blockType == 0x01) { // 加密块需要解密
                byte[] decryptedBlock = fullDecrypt(blockData, sm4Key);
                outputStream.write(decryptedBlock);
            } else { // 未加密块直接写入
                outputStream.write(blockData);
            }
        }

        return outputStream.toByteArray();
    }

    // 辅助方法
    private static boolean isImageFile(String filename) {
        return filename.endsWith(".bmp") || filename.endsWith(".png") ||
                filename.endsWith(".jpg") || filename.endsWith(".jpeg");
    }

    private static boolean isVideoFile(String filename) {
        return filename.endsWith(".mp4") || filename.endsWith(".avi") ||
                filename.endsWith(".mov") || filename.endsWith(".mkv");
    }

    private static int getImageHeaderSize(String filename) {
        // 根据图像格式返回头部大小
        if (filename.endsWith(".bmp")) return 54; // BMP文件头大小
        if (filename.endsWith(".png")) return 8;   // PNG文件头大小
        if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) return 2; // JPEG开始标记
        return 0; // 默认不保留头部
    }

    private static int getVideoHeaderSize(String filename) {
        // 视频文件头部大小（简化处理）
        return 1024; // 1KB头部
    }

    private static byte[] intToBytes(int value) {
        return new byte[] {
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    private static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    /**
     * 生成SM4密钥
     */
    public static String generateSm4Key() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        return java.util.Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * 生成随机IV
     */
    public static byte[] generateIv() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
