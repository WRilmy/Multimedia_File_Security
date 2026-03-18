package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

/**
 * JPEG选择性加密工具类
 * 加密后图片可被正常查看，但显示为雪花效果；解密后恢复原图（视觉上一致，但JPEG有损压缩会导致微小差异）
 * 实现原理：读取像素数组，对部分像素的RGB分量进行随机异或，然后重新编码为JPEG
 */
@Component
@Slf4j
public class JpegSelectiveEncryptionUtil {

    // JPEG文件头标记
    private static final byte[] JPEG_SOI = {(byte) 0xFF, (byte) 0xD8};

    // 加密比例（控制雪花密度）
    private static final double ENCRYPT_RATIO = 0.9; // 70%的像素被扰乱

    /**
     * JPEG图像信息
     */
    @Data
    public static class JpegInfo {
        private int width;          // 图像宽度
        private int height;         // 图像高度
        private int imageType;      // BufferedImage类型
        private int[] pixels;       // 像素数组（ARGB格式）
        private byte[] originalData; // 原始JPEG数据（用于保留元数据？）

        @Override
        public String toString() {
            return String.format("JPEG[%dx%d, type=%d]", width, height, imageType);
        }
    }

    /**
     * 验证是否为有效的JPEG文件
     */
    public static boolean isValidJpeg(byte[] jpegData) {
        if (jpegData.length < 2) return false;
        return jpegData[0] == JPEG_SOI[0] && jpegData[1] == JPEG_SOI[1];
    }

    /**
     * 解析JPEG文件，提取像素信息
     */
    public static JpegInfo parseJpeg(byte[] jpegData) throws IOException {
        if (!isValidJpeg(jpegData)) {
            throw new IllegalArgumentException("无效的JPEG文件");
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(jpegData)) {
            BufferedImage image = ImageIO.read(bais);
            if (image == null) {
                throw new IOException("无法解码JPEG图像");
            }

            JpegInfo info = new JpegInfo();
            info.setWidth(image.getWidth());
            info.setHeight(image.getHeight());
            info.setImageType(image.getType());

            // 提取像素数组（ARGB格式）
            int[] pixels = new int[image.getWidth() * image.getHeight()];
            image.getRGB(0, 0, image.getWidth(), image.getHeight(), pixels, 0, image.getWidth());
            info.setPixels(pixels);
            info.setOriginalData(jpegData);

            log.info("JPEG解析完成: {}", info);
            return info;
        }
    }

    /**
     * 从像素数组重建JPEG字节数组
     */
    private static byte[] rebuildJpeg(JpegInfo info, int[] pixels) throws IOException {
        BufferedImage image = new BufferedImage(info.getWidth(), info.getHeight(), info.getImageType());
        image.setRGB(0, 0, info.getWidth(), info.getHeight(), pixels, 0, info.getWidth());

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ImageOutputStream ios = ImageIO.createImageOutputStream(baos)) {

            // 设置压缩质量（0.95 尽量保持质量）
            ImageIO.write(image, "jpg", ios); // 使用默认参数
            ios.flush();
            return baos.toByteArray();
        }
    }

    /**
     * 选择性加密JPEG
     * @param jpegData 原始JPEG数据
     * @param key      加密密钥（Base64编码的SM4密钥）
     * @return 加密后的JPEG数据
     */
    public static byte[] selectiveEncryptJpeg(byte[] jpegData, String key) throws Exception {
        log.info("开始JPEG选择性加密");

        if (!isValidJpeg(jpegData)) {
            throw new IllegalArgumentException("无效的JPEG文件");
        }

        // 解析JPEG，获取像素数组
        JpegInfo info = parseJpeg(jpegData);
        int[] pixels = info.getPixels();

        // 使用密钥初始化随机数生成器
        byte[] keyBytes = Base64.getDecoder().decode(key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        int disturbedPixels = 0;

        // 对每个像素的RGB分量进行扰乱
        for (int i = 0; i < pixels.length; i++) {
            if (random.nextDouble() < ENCRYPT_RATIO) {
                int argb = pixels[i];

                // 分离ARGB分量
                int a = (argb >> 24) & 0xFF;
                int r = (argb >> 16) & 0xFF;
                int g = (argb >> 8) & 0xFF;
                int b = argb & 0xFF;

                // 随机异或各分量
                r ^= random.nextInt(256);
                g ^= random.nextInt(256);
                b ^= random.nextInt(256);

                // 重新组合（保持Alpha不变）
                pixels[i] = (a << 24) | (r << 16) | (g << 8) | b;
                disturbedPixels++;
            }
        }

        log.info("扰乱了 {}/{} 个像素", disturbedPixels, pixels.length);

        // 重建JPEG
        return rebuildJpeg(info, pixels);
    }

    /**
     * 选择性解密JPEG
     */
    public static byte[] selectiveDecryptJpeg(byte[] encryptedJpegData, String key) throws Exception {
        log.info("开始JPEG选择性解密");

        // 解密过程与加密完全相同（异或的可逆性）
        // 注意：由于JPEG有损压缩，解密后的图像与原始图像存在微小差异
        return selectiveEncryptJpeg(encryptedJpegData, key);
    }

    /**
     * 计算CRC32校验和（用于验证）
     */
    public static long calculateCRC32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }
}