package org.example.multimedia_file_security;

import org.example.multimedia_file_security.test.EncryptionAttackTest;
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

import static org.junit.jupiter.api.Assertions.*;

public class JpegSelectiveEncryptionRegressionTest {

    @Test
    void jpegSelectiveEncryptionShouldRemainPreviewableAndRecoverOriginalBytes() throws Exception {
        byte[] originalData = buildJpeg();
        BufferedImage originalImage = ImageIO.read(new ByteArrayInputStream(originalData));
        String sm4Key = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());

        MockMultipartFile multipartFile = new MockMultipartFile(
                "file", "regression.jpg", "image/jpeg", originalData);

        byte[] encryptedData = Sm4EncryptionUtil.selectiveEncrypt(multipartFile, sm4Key);
        BufferedImage encryptedPreview = ImageIO.read(new ByteArrayInputStream(encryptedData));
        byte[] decryptedData = Sm4EncryptionUtil.selectiveDecrypt(encryptedData, "regression.jpg", sm4Key);

        assertNotNull(encryptedPreview, "JPEG encrypted preview should still be decodable");
        assertArrayEquals(originalData, decryptedData, "JPEG selective decrypt should recover exact original bytes");

        EncryptionAttackTest attackTest = new EncryptionAttackTest();
        EncryptionAttackTest.TestReport report = attackTest.runFullTestSuite(
                originalImage, encryptedPreview, originalData, encryptedData, "SELECTIVE", "regression.jpg");

        assertEquals(0, report.getFailedTests(), attackTest.generateTestReport(report));
    }

    private byte[] buildJpeg() throws Exception {
        int width = 512;
        int height = 512;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setPaint(new GradientPaint(0, 0, new Color(30, 80, 180), width, height, new Color(240, 210, 70)));
        g.fillRect(0, 0, width, height);
        g.setColor(new Color(20, 20, 20));
        g.setFont(new Font("Serif", Font.BOLD, 54));
        g.drawString("JPEG", 150, 260);
        g.setStroke(new BasicStroke(8f));
        g.drawOval(70, 90, 360, 220);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "jpg", baos);
        return baos.toByteArray();
    }
}
