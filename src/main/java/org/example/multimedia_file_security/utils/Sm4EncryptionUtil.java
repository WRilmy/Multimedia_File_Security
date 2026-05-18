package org.example.multimedia_file_security.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
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
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int MIN_DATA_SIZE = 4096; // 4KB最小数据量

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
     * 全文件加密 - 图像文件使用双重加密（超混沌+SM4），其他文件使用纯SM4
     * @param fileData 文件数据字节数组
     * @param filename 原始文件名，用于判断文件类型
     * @param sm4Key SM4密钥（Base64格式）
     * @return 加密后的字节数组
     */
    public static byte[] newFullEncrypt(byte[] fileData, String filename, String sm4Key) throws Exception {
        if (filename != null && isImageFile(filename.toLowerCase())) {
            // 先改进版超混沌Chen XOR加密，再SM4全文件加密
            HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = deriveOptimizedChenConfigFromSm4Key(sm4Key);
            return HyperchaoticChenOptimizedUtil.hybridEncrypt(fileData, config, sm4Key);
        }
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

        // 检查最小数据量
        if (fileData.length < MIN_DATA_SIZE) {
            throw new IllegalArgumentException("数据量过小，建议至少" + MIN_DATA_SIZE + "字节以确保统计分析准确性");
        }

        byte[] keyBytes = java.util.Base64.getDecoder().decode(sm4Key);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher;
        byte[] iv = new byte[IV_SIZE];

        if ("CBC".equalsIgnoreCase(mode)) {
            // CBC模式需要IV
            SECURE_RANDOM.nextBytes(iv);
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
        } else if (isAudioFile(filename)) {
            return selectiveAudioEncrypt(fileData, filename, sm4Key);
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
            return selectiveEncryptBmpCTR(imageData, sm4Key);
        } else if (filename.endsWith(".png")) {
            return selectiveEncryptPng(imageData, sm4Key);
        } else if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) {
            return selectiveEncryptJpg(imageData, sm4Key);
        } else {
            throw new RuntimeException("不支持的文件格式");
        }
    }

    /**
     * 音频文件选择性加密
     */
    private static byte[] selectiveAudioEncrypt(byte[] audioData, String filename, String sm4Key) throws Exception {
        HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = deriveOptimizedChenConfigFromSm4Key(sm4Key);

        if (filename.endsWith(".wav")) {
            return WavSelectiveEncryptionUtil.selectiveEncryptWav(audioData, config);
        } else if (filename.endsWith(".mp3")) {
            return Mp3SelectiveEncryptionUtil.selectiveEncryptMp3(audioData, config);
        } else {
            // 其他音频格式默认使用全文件加密
            return fullEncrypt(audioData, sm4Key);
        }
    }

    /**
     * SM4-CTR选择性加密BMP - IV追加在文件末尾
     */
    public static byte[] selectiveEncryptBmpCTR(byte[] bmpData, String sm4Key) throws Exception {
        if (!isValidBmp(bmpData)) {
            throw new RuntimeException("无效的BMP文件");
        }

        // 克隆原始数据，避免修改输入
        byte[] result = bmpData.clone();

        BmpInfo info = parseBmpInfo(bmpData);

        // 解码密钥
        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "SM4");

        // 生成随机IV（16字节）- 使用静态SecureRandom实例
        byte[] iv = new byte[16];
        SECURE_RANDOM.nextBytes(iv);

        // 初始化CTR模式
        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

        int bytesPerPixel = info.bitsPerPixel / 8;
        int rowSize = info.width * bytesPerPixel;
        int padding = (4 - (rowSize % 4)) % 4;
        rowSize += padding;
        int absHeight = Math.abs(info.height);

        // 生成密钥流
        int pixelDataSize = absHeight * rowSize;
        byte[] keystream = cipher.update(new byte[pixelDataSize]);
        int keystreamPos = 0;

        // BMP 保持文件结构可解析，仅对像素区做可逆扰动。
        // 为降低明密文残留相关性，对每个像素的有效字节都进行加密。
        for (int row = 0; row < absHeight; row++) {
            int rowStart = info.pixelOffset + row * rowSize;

            for (int col = 0; col < info.width; col++) {
                int pixelStart = rowStart + col * bytesPerPixel;
                if (pixelStart >= 0 && pixelStart + bytesPerPixel - 1 < result.length) {
                    for (int channel = 0; channel < bytesPerPixel; channel++) {
                        result[pixelStart + channel] ^= keystream[keystreamPos + channel];
                    }
                }
                keystreamPos += bytesPerPixel;
            }
        }

        // 输出: 加密后的BMP + IV
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(result);  // 54字节头 + 加密像素数据
        output.write(iv);      // 16字节IV

        return output.toByteArray();
    }

    /**
     * SM4-CTR选择性解密BMP - 从文件末尾提取IV
     */
    public static byte[] selectiveDecryptBmpCTR(byte[] encryptedData, String sm4Key) throws Exception {

        // 验证数据长度
        if (encryptedData.length < 54 + 16) {
            throw new IllegalArgumentException("加密数据过短，需要至少70字节（BMP头54+IV16）");
        }

        // 提取IV（最后16字节）
        byte[] iv = Arrays.copyOfRange(encryptedData, encryptedData.length - 16, encryptedData.length);

        // 提取BMP数据（去掉最后16字节IV）
        byte[] bmpData = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - 16);

        // 验证BMP格式
        if (!isValidBmp(bmpData)) {
            throw new IllegalArgumentException("提取的BMP数据无效，可能IV位置错误或数据损坏");
        }

        BmpInfo info = parseBmpInfo(bmpData);
        byte[] result = bmpData.clone();  // 克隆，避免修改输入

        // 解码密钥
        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "SM4");

        // 初始化CTR模式（使用提取的IV）
        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

        int bytesPerPixel = info.bitsPerPixel / 8;
        int rowSize = info.width * bytesPerPixel;
        int padding = (4 - (rowSize % 4)) % 4;
        rowSize += padding;
        int absHeight = Math.abs(info.height);

        // 生成相同的密钥流
        int pixelDataSize = absHeight * rowSize;
        byte[] keystream = cipher.update(new byte[pixelDataSize]);
        int keystreamPos = 0;

        // CTR 模式下逐字节异或即可完成解密，与加密过程对称。
        for (int row = 0; row < absHeight; row++) {
            int rowStart = info.pixelOffset + row * rowSize;

            for (int col = 0; col < info.width; col++) {
                int pixelStart = rowStart + col * bytesPerPixel;
                if (pixelStart >= 0 && pixelStart + bytesPerPixel - 1 < result.length) {
                    for (int channel = 0; channel < bytesPerPixel; channel++) {
                        result[pixelStart + channel] ^= keystream[keystreamPos + channel];
                    }
                }
                keystreamPos += bytesPerPixel;
            }
        }

        // 返回纯BMP（不带IV）
        return result;
    }

    // 辅助方法：字节数组转十六进制（用于调试）
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * PNG选择性加密（简化版）
     */
    private static byte[] selectiveEncryptPng(byte[] pngData, String sm4Key) throws Exception {
        return PngSelectiveEncryptionUtil.selectiveEncryptPng(pngData, sm4Key);
    }

    /**
     * PNG选择性解密
     */
    public static byte[] selectiveDecryptPng(byte[] encryptedPngData, String sm4Key) throws Exception {
        return PngSelectiveEncryptionUtil.selectiveDecryptPng(encryptedPngData, sm4Key);
    }

    /**
     * JPG选择性加密（简化版）
     */
    private static byte[] selectiveEncryptJpg(byte[] pngData, String sm4Key) throws Exception {
        return JpegSelectiveEncryptionUtil.selectiveEncryptJpeg(pngData, sm4Key);
    }

    /**
     * JPG选择性解密
     */
    public static byte[] selectiveDecryptJpg(byte[] encryptedPngData, String sm4Key) throws Exception {
        return JpegSelectiveEncryptionUtil.selectiveDecryptJpeg(encryptedPngData, sm4Key);
    }

    /**
     * 视频文件选择性加密
     */
    private static byte[] selectiveVideoEncrypt(byte[] videoData, String filename, String sm4Key) throws Exception {
        HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = deriveOptimizedChenConfigFromSm4Key(sm4Key);

        if (filename.endsWith(".avi")) {
            return AviSelectiveEncryptionUtil.selectiveEncryptAvi(videoData, config);
        } else if (filename.endsWith(".mp4")) {
            return Mp4SelectiveEncryptionUtil.selectiveEncryptMp4(videoData, config);
        }

        int headerSize = getVideoHeaderSize(filename);

        if (headerSize >= videoData.length) {
            return fullEncrypt(videoData, sm4Key);
        }

        int blockSize = 10 * 1024;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte[] header = Arrays.copyOfRange(videoData, 0, headerSize);
        outputStream.write(header);

        byte[] videoContent = Arrays.copyOfRange(videoData, headerSize, videoData.length);

        for (int i = 0; i < videoContent.length; i += blockSize) {
            int end = Math.min(i + blockSize, videoContent.length);
            byte[] block = Arrays.copyOfRange(videoContent, i, end);

            if (SECURE_RANDOM.nextDouble() < 0.3) {
                byte[] encryptedBlock = fullEncrypt(block, sm4Key);
                outputStream.write(0x01);
                outputStream.write(intToBytes(encryptedBlock.length));
                outputStream.write(encryptedBlock);
            } else {
                outputStream.write(0x00);
                outputStream.write(intToBytes(block.length));
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

    /**
     * 全文件解密 - 图像文件使用双重解密（SM4+超混沌），其他文件使用纯SM4
     * @param encryptedData 加密数据字节数组
     * @param filename 原始文件名，用于判断文件类型
     * @param sm4Key SM4密钥（Base64格式）
     * @return 解密后的字节数组
     */
    public static byte[] newFullDecrypt(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        if (filename != null && isImageFile(filename.toLowerCase())) {
            // 图像文件：先SM4解密，再改进版超混沌Chen XOR解密
            HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = deriveOptimizedChenConfigFromSm4Key(sm4Key);
            return HyperchaoticChenOptimizedUtil.hybridDecrypt(encryptedData, config, sm4Key);
        }
        // 非图像文件：保持原有SM4全文件解密
        return fullDecrypt(encryptedData, sm4Key, "CBC");
    }

    /**
     * 按指定模式解密全文件 SM4 密文。
     * <p>
     * 加密结果的格式为 IV 长度、IV 内容、真实密文。本方法先解析该包装格式，再调用 SM4 CBC 或 ECB 解密。
     * </p>
     *
     * @param encryptedData 加密后的包装字节
     * @param sm4Key Base64 编码的 SM4 密钥
     * @param mode 解密模式，支持 CBC 或 ECB
     * @return 解密后的原始文件字节
     * @throws Exception 当密钥、填充或加密数据格式不正确时抛出
     */
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
        } else if (isAudioFile(filename)) {
            return selectiveAudioDecrypt(encryptedData, filename, sm4Key);
        } else if (isVideoFile(filename)) {
            return selectiveVideoDecrypt(encryptedData, filename, sm4Key);
        } else {
            return fullDecrypt(encryptedData, sm4Key);
        }
    }

    /**
     * 根据音频格式分派选择性解密逻辑。
     *
     * @param encryptedData 音频密文字节
     * @param filename 原始文件名
     * @param sm4Key Base64 编码的 SM4 密钥
     * @return 解密后的音频字节
     * @throws Exception 当格式解析或解密失败时抛出
     */
    private static byte[] selectiveAudioDecrypt(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = deriveOptimizedChenConfigFromSm4Key(sm4Key);

        if (filename.endsWith(".wav")) {
            return WavSelectiveEncryptionUtil.decryptWav(encryptedData, config);
        } else if (filename.endsWith(".mp3")) {
            return Mp3SelectiveEncryptionUtil.decryptMp3(encryptedData, config);
        } else {
            return fullDecrypt(encryptedData, sm4Key);
        }
    }

    /**
     * 根据图像格式分派选择性解密逻辑。
     *
     * @param encryptedData 图像密文字节
     * @param filename 原始文件名
     * @param sm4Key Base64 编码的 SM4 密钥
     * @return 解密后的图像字节
     * @throws Exception 当格式解析或解密失败时抛出
     */
    private static byte[] selectiveImageDecrypt(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        if (filename.endsWith(".bmp")) {
            return selectiveDecryptBmpCTR(encryptedData, sm4Key);
        } else if (filename.endsWith(".png")) {
            return selectiveDecryptPng(encryptedData, sm4Key);
        } else if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) {
            return selectiveDecryptJpg(encryptedData, sm4Key);
        } else {
            throw new RuntimeException("不支持的文件格式");
        }
    }

    /**
     * 根据视频格式分派选择性解密逻辑。
     *
     * @param encryptedData 视频密文字节
     * @param filename 原始文件名
     * @param sm4Key Base64 编码的 SM4 密钥
     * @return 解密后的视频字节
     * @throws Exception 当格式解析或解密失败时抛出
     */
    private static byte[] selectiveVideoDecrypt(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = deriveOptimizedChenConfigFromSm4Key(sm4Key);

        if (filename.endsWith(".avi")) {
            return AviSelectiveEncryptionUtil.decryptAvi(encryptedData, config);
        } else if (filename.endsWith(".mp4")) {
            return Mp4SelectiveEncryptionUtil.decryptMp4(encryptedData, config);
        }

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

    /**
     * 从 SM4 密钥派生改进版超混沌 Chen 系统初值。
     * <p>
     * 方法先对 SM4 原始密钥做 SHA-256 摘要，再把摘要分成四段映射到 x0、y0、z0、w0 的安全区间。
     * 这样每个文件的超混沌密钥流由该文件的 SM4 密钥唯一决定。
     * </p>
     *
     * @param sm4Key Base64 编码的 SM4 密钥
     * @return 带派生初值的改进版超混沌 Chen 配置
     * @throws Exception 当密钥为空、Base64 解码失败或摘要算法不可用时抛出
     */
    private static HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig deriveOptimizedChenConfigFromSm4Key(String sm4Key) throws Exception {
        if (sm4Key == null || sm4Key.trim().isEmpty()) {
            throw new IllegalArgumentException("SM4密钥不能为空");
        }

        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyBytes);

        return HyperchaoticChenOptimizedUtil.withInitialState(
                digestToInitialValue(digest, 0, 0.10, 0.20),
                digestToInitialValue(digest, 8, 0.20, 0.35),
                digestToInitialValue(digest, 16, 0.30, 0.45),
                digestToInitialValue(digest, 24, 0.40, 0.55)
        );
    }

    /**
     * 将 SHA-256 摘要的一段字节映射为指定范围内的超混沌初值。
     *
     * @param digest SHA-256 摘要
     * @param offset 读取起始偏移
     * @param min 初值下界
     * @param max 初值上界
     * @return 映射后的浮点初值
     */
    private static double digestToInitialValue(byte[] digest, int offset, double min, double max) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (digest[offset + i] & 0xFFL);
        }
        double unit = (value >>> 1) / (double) Long.MAX_VALUE;
        return min + (max - min) * unit;
    }

    // 辅助方法
    /**
     * 判断文件名是否属于当前支持的图像格式。
     *
     * @param filename 文件名
     * @return 是支持的图像格式则返回 true
     */
    private static boolean isImageFile(String filename) {
        return filename.endsWith(".bmp") || filename.endsWith(".png") ||
                filename.endsWith(".jpg") || filename.endsWith(".jpeg");
    }

    /**
     * 判断文件名是否属于当前支持的音频格式。
     *
     * @param filename 文件名
     * @return 是支持的音频格式则返回 true
     */
    private static boolean isAudioFile(String filename) {
        return filename.endsWith(".wav") || filename.endsWith(".mp3") ||
                filename.endsWith(".aac") || filename.endsWith(".flac");
    }

    /**
     * 判断文件名是否属于当前支持的视频格式。
     *
     * @param filename 文件名
     * @return 是支持的视频格式则返回 true
     */
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

    /**
     * 返回旧版视频块加密逻辑使用的保留头部长度。
     *
     * @param filename 文件名
     * @return 需要保留的视频头部字节数
     */
    private static int getVideoHeaderSize(String filename) {
        // 视频文件头部大小（简化处理）
        return 1024; // 1KB头部
    }

    /**
     * 将整数转换为大端序 4 字节数组。
     *
     * @param value 整数值
     * @return 大端序字节数组
     */
    private static byte[] intToBytes(int value) {
        return new byte[] {
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    /**
     * 将大端序 4 字节数组转换为整数。
     *
     * @param bytes 大端序字节数组
     * @return 整数值
     */
    private static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }
}
