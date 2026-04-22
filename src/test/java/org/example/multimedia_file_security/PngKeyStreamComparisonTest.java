package org.example.multimedia_file_security;

import org.example.multimedia_file_security.test.EncryptionAttackTest;
import org.example.multimedia_file_security.utils.PngSelectiveEncryptionUtil;
import org.example.multimedia_file_security.utils.Sm4Util;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PngKeyStreamComparisonTest {

    @Test
    void compareSm4CtrKeyStreamWithHyperchaoticChenKeyStream() throws Exception {
        byte[] originalData = buildSyntheticPng();
        BufferedImage originalImage = ImageIO.read(new ByteArrayInputStream(originalData));
        String sm4Key = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());

        byte[] sm4CtrEncrypted = PngSelectiveEncryptionUtil.selectiveEncryptPngSm4Ctr(originalData, sm4Key);
        BufferedImage sm4CtrImage = ImageIO.read(new ByteArrayInputStream(sm4CtrEncrypted));
        byte[] sm4CtrDecrypted = PngSelectiveEncryptionUtil.selectiveDecryptPngSm4Ctr(sm4CtrEncrypted, sm4Key);
        BufferedImage sm4CtrDecryptedImage = ImageIO.read(new ByteArrayInputStream(sm4CtrDecrypted));

        byte[] chenEncrypted = PngSelectiveEncryptionUtil.selectiveEncryptPngHyperchaotic(originalData, sm4Key);
        BufferedImage chenImage = ImageIO.read(new ByteArrayInputStream(chenEncrypted));
        byte[] chenDecrypted = PngSelectiveEncryptionUtil.selectiveDecryptPngHyperchaotic(chenEncrypted, sm4Key);
        BufferedImage chenDecryptedImage = ImageIO.read(new ByteArrayInputStream(chenDecrypted));

        assertNotNull(sm4CtrImage, "SM4-CTR selective PNG should be decodable");
        assertNotNull(chenImage, "Hyperchaotic selective PNG should be decodable");
        assertSamePixels(originalImage, sm4CtrDecryptedImage, "SM4-CTR selective PNG should recover original pixels");
        assertSamePixels(originalImage, chenDecryptedImage, "Hyperchaotic selective PNG should recover original pixels");

        EncryptionAttackTest attackTest = new EncryptionAttackTest();
        EncryptionAttackTest.TestReport sm4CtrReport = attackTest.runFullTestSuite(
                originalImage, sm4CtrImage, originalData, sm4CtrEncrypted, "SELECTIVE", "png-sm4-ctr.png");
        EncryptionAttackTest.TestReport chenReport = attackTest.runFullTestSuite(
                originalImage, chenImage, originalData, chenEncrypted, "SELECTIVE", "png-hyperchaotic-chen.png");

        System.out.println("===== PNG SM4-CTR KEYSTREAM REPORT =====");
        System.out.println(attackTest.generateTestReport(sm4CtrReport));
        System.out.println("===== PNG HYPERCHAOTIC CHEN KEYSTREAM REPORT =====");
        System.out.println(attackTest.generateTestReport(chenReport));

        System.out.println("===== PNG KEYSTREAM COMPARISON SUMMARY =====");
        System.out.printf("SM4-CTR: passed=%d, failed=%d, passRate=%s%n",
                sm4CtrReport.getPassedTests(), sm4CtrReport.getFailedTests(),
                sm4CtrReport.getSummary().get("通过率"));
        System.out.printf("Hyperchaotic Chen: passed=%d, failed=%d, passRate=%s%n",
                chenReport.getPassedTests(), chenReport.getFailedTests(),
                chenReport.getSummary().get("通过率"));
    }

    private byte[] buildSyntheticPng() throws Exception {
        int width = 512;
        int height = 512;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setPaint(new GradientPaint(0, 0, new Color(235, 238, 230), width, height, new Color(40, 95, 160)));
        g.fillRect(0, 0, width, height);

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int r = (x * 9 + y * 5) & 0xFF;
                int gr = (x * 3 + y * 13) & 0xFF;
                int b = ((x ^ y) * 7) & 0xFF;
                if (((x / 12) + (y / 12)) % 2 == 0) {
                    image.setRGB(x, y, (r << 16) | (gr << 8) | b);
                }
            }
        }

        g.setColor(new Color(20, 20, 20));
        g.setStroke(new BasicStroke(6f));
        g.drawRoundRect(58, 74, 392, 250, 40, 40);
        g.setFont(new Font("Serif", Font.BOLD, 52));
        g.drawString("PNG TEST", 135, 230);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        return baos.toByteArray();
    }

    private void assertSamePixels(BufferedImage expected, BufferedImage actual, String message) {
        assertNotNull(actual, message + " and remain decodable");
        assertEquals(expected.getWidth(), actual.getWidth(), message + " width");
        assertEquals(expected.getHeight(), actual.getHeight(), message + " height");

        for (int y = 0; y < expected.getHeight(); y++) {
            for (int x = 0; x < expected.getWidth(); x++) {
                assertEquals(expected.getRGB(x, y), actual.getRGB(x, y), message + " at (" + x + "," + y + ")");
            }
        }
    }
}
