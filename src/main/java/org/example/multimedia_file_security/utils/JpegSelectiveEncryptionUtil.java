package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.zip.CRC32;

/**
 * JPEG selective encryption utility.
 * The preview remains a valid JPEG, while the exact original JPEG bytes are
 * carried in an encrypted trailer so decryption can recover the original file.
 */
@Component
@Slf4j
public class JpegSelectiveEncryptionUtil {

    private static final byte[] JPEG_SOI = {(byte) 0xFF, (byte) 0xD8};
    private static final byte[] TRAILER_MAGIC = {'J', 'S', 'E', 'G', 'R', '2'};
    private static final int TRAILER_FOOTER_SIZE = TRAILER_MAGIC.length + Integer.BYTES;
    private static final double ENCRYPT_RATIO = 1.0;

    @Data
    public static class JpegInfo {
        private int width;
        private int height;
        private int imageType;
        private int[] pixels;
        private byte[] originalData;

        @Override
        public String toString() {
            return String.format("JPEG[%dx%d, type=%d]", width, height, imageType);
        }
    }

    public static boolean isValidJpeg(byte[] jpegData) {
        return jpegData.length >= 2
                && jpegData[0] == JPEG_SOI[0]
                && jpegData[1] == JPEG_SOI[1];
    }

    public static JpegInfo parseJpeg(byte[] jpegData) throws Exception {
        if (!isValidJpeg(jpegData)) {
            throw new IllegalArgumentException("无效的JPEG文件");
        }

        BufferedImage image = ImageIO.read(new ByteArrayInputStream(jpegData));
        if (image == null) {
            throw new IllegalArgumentException("无法解码JPEG图像");
        }

        JpegInfo info = new JpegInfo();
        info.setWidth(image.getWidth());
        info.setHeight(image.getHeight());
        info.setImageType(image.getType() == BufferedImage.TYPE_CUSTOM
                ? BufferedImage.TYPE_INT_RGB
                : image.getType());

        int[] pixels = new int[image.getWidth() * image.getHeight()];
        image.getRGB(0, 0, image.getWidth(), image.getHeight(), pixels, 0, image.getWidth());
        info.setPixels(pixels);
        info.setOriginalData(jpegData);
        log.info("JPEG解析完成: {}", info);
        return info;
    }

    private static byte[] rebuildJpeg(JpegInfo info, int[] pixels) throws Exception {
        BufferedImage image = new BufferedImage(info.getWidth(), info.getHeight(), info.getImageType());
        image.setRGB(0, 0, info.getWidth(), info.getHeight(), pixels, 0, info.getWidth());

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ImageOutputStream ios = ImageIO.createImageOutputStream(baos)) {
            ImageIO.write(image, "jpg", ios);
            ios.flush();
            return baos.toByteArray();
        }
    }

    public static byte[] selectiveEncryptJpeg(byte[] jpegData, String key) throws Exception {
        log.info("开始JPEG选择性加密");

        JpegInfo info = parseJpeg(jpegData);
        int[] pixels = Arrays.copyOf(info.getPixels(), info.getPixels().length);
        byte[] keyBytes = Base64.getDecoder().decode(key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        int disturbedPixels = 0;
        for (int i = 0; i < pixels.length; i++) {
            if (random.nextDouble() < ENCRYPT_RATIO) {
                int argb = pixels[i];
                int a = (argb >> 24) & 0xFF;
                int r = (argb >> 16) & 0xFF;
                int g = (argb >> 8) & 0xFF;
                int b = argb & 0xFF;

                r ^= random.nextInt(256);
                g ^= random.nextInt(256);
                b ^= random.nextInt(256);

                pixels[i] = (a << 24) | (r << 16) | (g << 8) | b;
                disturbedPixels++;
            }
        }

        log.info("扰乱了 {}/{} 个像素", disturbedPixels, pixels.length);

        byte[] previewJpeg = rebuildJpeg(info, pixels);
        byte[] encryptedOriginal = xorWithDigestStream(jpegData, keyBytes);

        ByteArrayOutputStream output = new ByteArrayOutputStream(
                previewJpeg.length + encryptedOriginal.length + TRAILER_FOOTER_SIZE);
        output.write(previewJpeg);
        output.write(encryptedOriginal);
        output.write(TRAILER_MAGIC);
        output.write(ByteBuffer.allocate(Integer.BYTES).putInt(encryptedOriginal.length).array());
        return output.toByteArray();
    }

    public static byte[] selectiveDecryptJpeg(byte[] encryptedJpegData, String key) throws Exception {
        log.info("开始JPEG选择性解密");

        TrailerInfo trailerInfo = extractTrailer(encryptedJpegData);
        if (trailerInfo == null) {
            throw new IllegalArgumentException("JPEG加密载荷缺失或格式不正确，无法恢复原始图像");
        }

        byte[] keyBytes = Base64.getDecoder().decode(key);
        return xorWithDigestStream(trailerInfo.encryptedOriginalBytes, keyBytes);
    }

    public static long calculateCRC32(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }

    private static byte[] xorWithDigestStream(byte[] data, byte[] keyBytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] output = new byte[data.length];
        int offset = 0;
        int counter = 0;

        while (offset < data.length) {
            digest.reset();
            digest.update(keyBytes);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(counter++).array());
            byte[] block = digest.digest();

            for (int i = 0; i < block.length && offset < data.length; i++, offset++) {
                output[offset] = (byte) (data[offset] ^ block[i]);
            }
        }
        return output;
    }

    private static TrailerInfo extractTrailer(byte[] encryptedJpegData) {
        if (encryptedJpegData.length < TRAILER_FOOTER_SIZE) {
            return null;
        }

        int magicOffset = encryptedJpegData.length - TRAILER_FOOTER_SIZE;
        for (int i = 0; i < TRAILER_MAGIC.length; i++) {
            if (encryptedJpegData[magicOffset + i] != TRAILER_MAGIC[i]) {
                return null;
            }
        }

        int payloadLength = ByteBuffer.wrap(
                encryptedJpegData,
                magicOffset + TRAILER_MAGIC.length,
                Integer.BYTES
        ).getInt();

        int payloadOffset = encryptedJpegData.length - TRAILER_FOOTER_SIZE - payloadLength;
        if (payloadLength < 0 || payloadOffset < 0) {
            return null;
        }

        TrailerInfo info = new TrailerInfo();
        info.encryptedOriginalBytes = Arrays.copyOfRange(
                encryptedJpegData,
                payloadOffset,
                encryptedJpegData.length - TRAILER_FOOTER_SIZE
        );
        return info;
    }

    private static class TrailerInfo {
        private byte[] encryptedOriginalBytes;
    }
}
