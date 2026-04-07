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

public class LosslessSelectiveReportSmokeTest {

    @Test
    void smokeTestBmpAndPngSelectiveReports() throws Exception {
        runCase("bmp");
        runCase("png");
    }

    private void runCase(String format) throws Exception {
        byte[] originalData = buildImage(format);
        BufferedImage originalImage = ImageIO.read(new ByteArrayInputStream(originalData));
        String sm4Key = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());
        MockMultipartFile multipartFile = new MockMultipartFile("file", "synthetic." + format, "image/" + format, originalData);
        byte[] encryptedData = Sm4EncryptionUtil.selectiveEncrypt(multipartFile, sm4Key);
        BufferedImage encryptedImage = ImageIO.read(new ByteArrayInputStream(encryptedData));

        EncryptionAttackTest attackTest = new EncryptionAttackTest();
        EncryptionAttackTest.TestReport report = attackTest.runFullTestSuite(
                originalImage, encryptedImage, originalData, encryptedData, "SELECTIVE", "synthetic." + format);

        System.out.println("===== " + format.toUpperCase() + " =====");
        System.out.println(attackTest.generateTestReport(report));
    }

    private byte[] buildImage(String format) throws Exception {
        int width = 512;
        int height = 512;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(new Color(245, 245, 250));
        g.fillRect(0, 0, width, height);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int r = (x * 11 + y * 7) & 0xFF;
                int gg = (x * 3 + y * 5) & 0xFF;
                int b = (x * 13 + y * 17) & 0xFF;
                if (((x / 8) + (y / 8)) % 2 == 0) {
                    image.setRGB(x, y, (r << 16) | (gg << 8) | b);
                }
            }
        }
        g.setColor(Color.BLACK);
        g.setStroke(new BasicStroke(5f));
        g.drawRoundRect(60, 70, 380, 220, 30, 30);
        g.setFont(new Font("Serif", Font.BOLD, 56));
        g.drawString(format.toUpperCase(), 150, 230);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, format, baos);
        return baos.toByteArray();
    }
}
