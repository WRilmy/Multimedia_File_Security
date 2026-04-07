package org.example.multimedia_file_security;

import org.example.multimedia_file_security.test.EncryptionAttackTest;
import org.example.multimedia_file_security.utils.HyperchaoticChenUtil;
import org.example.multimedia_file_security.utils.Sm4EncryptionUtil;
import org.example.multimedia_file_security.utils.Sm4Util;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

public class SelectiveEncryptionComparisonTest {

    @Test
    void compareCurrentSelectiveWithHyperchaoticSelective() throws Exception {
        byte[] originalData = buildSyntheticJpeg();
        BufferedImage originalImage = ImageIO.read(new ByteArrayInputStream(originalData));

        String sm4Key = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());
        MockMultipartFile multipartFile = new MockMultipartFile("file", "synthetic.jpg", "image/jpeg", originalData);

        byte[] currentEncrypted = Sm4EncryptionUtil.selectiveEncrypt(multipartFile, sm4Key);
        BufferedImage currentEncryptedImage = ImageIO.read(new ByteArrayInputStream(currentEncrypted));

        EncryptionAttackTest attackTest = new EncryptionAttackTest();
        EncryptionAttackTest.TestReport currentReport = attackTest.runFullTestSuite(
                originalImage, currentEncryptedImage, originalData, currentEncrypted, "SELECTIVE", "synthetic.jpg");

        byte[] hyperchaoticEncrypted = hyperchaoticSelectiveEncryptJpeg(originalData);
        BufferedImage hyperchaoticEncryptedImage = ImageIO.read(new ByteArrayInputStream(hyperchaoticEncrypted));
        EncryptionAttackTest.TestReport hyperchaoticReport = attackTest.runFullTestSuite(
                originalImage, hyperchaoticEncryptedImage, originalData, hyperchaoticEncrypted, "SELECTIVE", "synthetic.jpg");

        System.out.println("===== CURRENT SELECTIVE REPORT =====");
        System.out.println(attackTest.generateTestReport(currentReport));
        System.out.println("===== HYPERCHAOTIC SELECTIVE REPORT =====");
        System.out.println(attackTest.generateTestReport(hyperchaoticReport));
    }

    private byte[] buildSyntheticJpeg() throws Exception {
        int width = 512;
        int height = 512;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setPaint(new GradientPaint(0, 0, new Color(20, 30, 180), width, height, new Color(240, 200, 60)));
        g.fillRect(0, 0, width, height);

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int r = (x * 7 + y * 3) & 0xFF;
                int gr = (x * 5 + y * 11) & 0xFF;
                int b = ((x ^ y) * 9) & 0xFF;
                int rgb = ((r << 16) | (gr << 8) | b);
                if (((x / 16) + (y / 16)) % 2 == 0) {
                    image.setRGB(x, y, image.getRGB(x, y) ^ rgb);
                }
            }
        }

        g.setColor(Color.WHITE);
        g.setStroke(new BasicStroke(6f));
        g.drawOval(70, 90, 360, 250);
        g.drawRect(140, 180, 220, 140);
        g.setFont(new Font("Serif", Font.BOLD, 48));
        g.drawString("MFS", 185, 270);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "jpg", baos);
        return baos.toByteArray();
    }

    private byte[] hyperchaoticSelectiveEncryptJpeg(byte[] jpegData) throws Exception {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(jpegData));
        int width = image.getWidth();
        int height = image.getHeight();
        int[] pixels = new int[width * height];
        image.getRGB(0, 0, width, height, pixels, 0, width);

        HyperchaoticChenUtil.ChenKeyStreamConfig config =
                HyperchaoticChenUtil.withInitialState(0.1179, 0.2318, 0.3361, 0.4517);
        byte[] keyStream = HyperchaoticChenUtil.generateKeyStream(pixels.length * 3, config);

        int ks = 0;
        for (int i = 0; i < pixels.length; i++) {
            int argb = pixels[i];
            int a = (argb >> 24) & 0xFF;
            int r = (argb >> 16) & 0xFF;
            int g = (argb >> 8) & 0xFF;
            int b = argb & 0xFF;

            r ^= keyStream[ks++] & 0xFF;
            g ^= keyStream[ks++] & 0xFF;
            b ^= keyStream[ks++] & 0xFF;
            pixels[i] = (a << 24) | (r << 16) | (g << 8) | b;
        }

        BufferedImage encryptedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        encryptedImage.setRGB(0, 0, width, height, pixels, 0, width);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(encryptedImage, "jpg", baos);
        return baos.toByteArray();
    }
}
