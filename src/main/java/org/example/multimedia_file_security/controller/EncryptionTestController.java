package org.example.multimedia_file_security.controller;

import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.service.FileService;
import org.example.multimedia_file_security.test.EncryptionAttackTest;
import org.example.multimedia_file_security.threadLocal.UserThreadLocal;
import org.example.multimedia_file_security.utils.HyperchaoticChenUtil;
import org.example.multimedia_file_security.utils.Sm4Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/test")
public class EncryptionTestController {

    @Autowired
    private EncryptionAttackTest encryptionAttackTest;

    @Autowired
    private FileService fileService;

    /**
     * 运行完整的加密攻击测试套件
     */
    @PostMapping("/run-attack-test")
    public Result<Map<String, Object>> runAttackTest(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "encryptionMode", defaultValue = "FULL") String encryptionMode,
            @RequestParam(value = "fileType", defaultValue = "IMAGE") String fileType) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return Result.error(401, "用户未登录");
            }

            log.info("开始加密攻击测试: 文件={}, 加密模式={}", 
                    file.getOriginalFilename(), encryptionMode);

            // 1. 获取原始文件数据
            byte[] originalData = file.getBytes();
            BufferedImage originalImage = ImageIO.read(file.getInputStream());


            // 2. 生成正确的SM4密钥
            javax.crypto.SecretKey sm4Key = org.example.multimedia_file_security.utils.Sm4Util.generateSm4Key();
            String sm4KeyBase64 = java.util.Base64.getEncoder().encodeToString(sm4Key.getEncoded());

            // 3. 模拟文件上传获取加密数据
            byte[] encryptedData;
            BufferedImage encryptedImage;
            if ("SELECTIVE".equals(encryptionMode)) {
                encryptedData = org.example.multimedia_file_security.utils.Sm4EncryptionUtil.selectiveEncrypt(
                        file, sm4KeyBase64);
                encryptedImage = toBufferedImage(encryptedData);
            } else {
                encryptedData = org.example.multimedia_file_security.utils.Sm4EncryptionUtil.fullEncrypt(
                        originalData, sm4KeyBase64);
                encryptedImage = toBufferedImage(encryptedData);
            }

            // 4. 运行完整的测试套件
            EncryptionAttackTest.TestReport report = encryptionAttackTest.runFullTestSuite(originalImage, encryptedImage,
                    originalData, encryptedData, encryptionMode, file.getOriginalFilename(), fileType);

            // 5. 生成测试报告
            String reportText = encryptionAttackTest.generateTestReport(report);

            // 6. 保存测试报告
            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
            String timestamp = sdf.format(new Date());
            String cleanFilename = file.getOriginalFilename().replaceAll("[\\\\/:*?\"<>|]", "_");
            String reportPath = "test_reports/" + cleanFilename + "_" + timestamp + ".txt";
            new File("test_reports").mkdirs();
            encryptionAttackTest.saveTestReport(report, reportPath);

            // 7. 构建返回结果
            Map<String, Object> result = new HashMap<>();
            result.put("report", report);
            result.put("reportText", reportText);
            result.put("reportPath", reportPath);
            result.put("summary", report.getSummary());
            result.put("testKey", sm4KeyBase64); // 返回测试密钥用于解密测试

            log.info("加密攻击测试完成: 通过率={}", 
                    report.getSummary().get("passRate"));

            return Result.success("测试完成", result);

        } catch (Exception e) {
            log.error("加密攻击测试失败", e);
            return Result.error(500, "测试失败: " + e.getMessage());
        }
    }

    /**
     * 运行超混沌系统加密测试
     */
    @PostMapping("/run-hyperchaotic-test")
    public Result<Map<String, Object>> runHyperchaoticTest(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "encryptionType", defaultValue = "FULL") String encryptionType,
            @RequestParam(value = "configType", defaultValue = "default") String configType,
            @RequestParam(value = "fileType", defaultValue = "IMAGE") String fileType) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return Result.error(401, "用户未登录");
            }

            log.info("开始超混沌系统加密测试: 文件={}, 加密类型={}", 
                    file.getOriginalFilename(), encryptionType);

            // 1. 获取原始文件数据
            byte[] originalData = file.getBytes();
            BufferedImage originalImage = ImageIO.read(file.getInputStream());

            // 2. 使用超混沌系统进行加密
            HyperchaoticChenUtil.ChenKeyStreamConfig config;
            if ("highLyapunov".equals(configType)) {
                config = HyperchaoticChenUtil.ChenKeyStreamConfig.highLyapunovConfig();
            } else {
                config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();
            }
            byte[] encryptedData;
            String filename = file.getOriginalFilename();
            if ("FULL".equals(encryptionType)) {
                encryptedData = HyperchaoticChenUtil.xorEncrypt(originalData, config);
            } else if ("SELECTIVE".equals(encryptionType)) {
                if (filename != null && filename.toLowerCase().endsWith(".avi")) {
                    encryptedData = org.example.multimedia_file_security.utils.AviSelectiveEncryptionUtil.selectiveEncryptAvi(originalData, config);
                } else if (filename != null && filename.toLowerCase().endsWith(".mp4")) {
                    encryptedData = org.example.multimedia_file_security.utils.Mp4SelectiveEncryptionUtil.selectiveEncryptMp4(originalData, config);
                } else if (filename != null && filename.toLowerCase().endsWith(".wav")) {
                    encryptedData = org.example.multimedia_file_security.utils.WavSelectiveEncryptionUtil.selectiveEncryptWav(originalData, config);
                } else if (filename != null && filename.toLowerCase().endsWith(".mp3")) {
                    encryptedData = org.example.multimedia_file_security.utils.Mp3SelectiveEncryptionUtil.selectiveEncryptMp3(originalData, config);
                } else {
                    throw new IllegalArgumentException("选择性加密仅支持 AVI、MP4、WAV 和 MP3 格式");
                }
            } else {
                throw new IllegalArgumentException("不支持的加密类型: " + encryptionType);
            }
            
            // 尝试将加密数据转换为图像，如果失败则使用null
            BufferedImage encryptedImage = null;
            try {
                encryptedImage = toBufferedImage(encryptedData);
            } catch (Exception e) {
                log.warn("加密后数据不是有效图像格式，跳过图像处理测试", e);
            }

            // 3. 运行完整的测试套件
            EncryptionAttackTest.TestReport report = encryptionAttackTest.runFullTestSuite(originalImage, encryptedImage,
                    originalData, encryptedData, "HYPERCHAOTIC", file.getOriginalFilename(), fileType);

            // 4. 生成测试报告
            String reportText = encryptionAttackTest.generateTestReport(report);

            // 5. 保存测试报告
            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
            String timestamp = sdf.format(new Date());
            String cleanFilename = file.getOriginalFilename().replaceAll("[\\\\/:*?\"<>|]", "_");
            String reportPath = "test_reports/" + cleanFilename + "_" + timestamp + ".txt";
            new File("test_reports").mkdirs();
            encryptionAttackTest.saveTestReport(report, reportPath);

            // 6. 构建返回结果
            Map<String, Object> result = new HashMap<>();
            result.put("report", report);
            result.put("reportText", reportText);
            result.put("reportPath", reportPath);
            result.put("summary", report.getSummary());
            result.put("encryptionType", encryptionType);

            log.info("超混沌系统加密测试完成: 通过率={}", 
                    report.getSummary().get("passRate"));

            return Result.success("测试完成", result);

        } catch (Exception e) {
            log.error("超混沌系统加密测试失败", e);
            return Result.error(500, "测试失败: " + e.getMessage());
        }
    }

    /**
     * 运行混合加密测试（超混沌 + SM4）
     */
    @PostMapping("/run-hybrid-test")
    public Result<Map<String, Object>> runHybridTest(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "encryptionType", defaultValue = "FULL") String encryptionType,
            @RequestParam(value = "fileType", defaultValue = "IMAGE") String fileType) {
        try {
            Long userId = UserThreadLocal.getCurrentId();
            if (userId == null) {
                return Result.error(401, "用户未登录");
            }

            log.info("开始混合加密测试: 文件={}, 加密类型={}", 
                    file.getOriginalFilename(), encryptionType);

            byte[] originalData = file.getBytes();
            BufferedImage originalImage = ImageIO.read(file.getInputStream());

            HyperchaoticChenUtil.ChenKeyStreamConfig chenConfig = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();
            javax.crypto.SecretKey sm4Key = Sm4Util.generateSm4Key();
            String sm4KeyBase64 = java.util.Base64.getEncoder().encodeToString(sm4Key.getEncoded());

            byte[] encryptedData;
            if ("FULL".equals(encryptionType)) {
                encryptedData = HyperchaoticChenUtil.hybridEncrypt(originalData, chenConfig, sm4KeyBase64);
            } else if ("SELECTIVE".equals(encryptionType)) {
                encryptedData = HyperchaoticChenUtil.hybridEncryptPayload(originalData, file.getOriginalFilename(), chenConfig, sm4KeyBase64);
            } else {
                throw new IllegalArgumentException("不支持的加密类型: " + encryptionType);
            }
            
            BufferedImage encryptedImage = null;
            try {
                encryptedImage = toBufferedImage(encryptedData);
            } catch (Exception e) {
                log.warn("加密后数据不是有效图像格式，跳过图像处理测试", e);
            }

            EncryptionAttackTest.TestReport report = encryptionAttackTest.runFullTestSuite(originalImage, encryptedImage,
                    originalData, encryptedData, "HYBRID", file.getOriginalFilename(), fileType);

            String reportText = encryptionAttackTest.generateTestReport(report);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
            String timestamp = sdf.format(new Date());
            String cleanFilename = file.getOriginalFilename().replaceAll("[\\\\/:*?\"<>|]", "_");
            String reportPath = "test_reports/" + cleanFilename + "_" + timestamp + ".txt";
            new File("test_reports").mkdirs();
            encryptionAttackTest.saveTestReport(report, reportPath);

            Map<String, Object> result = new HashMap<>();
            result.put("report", report);
            result.put("reportText", reportText);
            result.put("reportPath", reportPath);
            result.put("summary", report.getSummary());
            result.put("encryptionType", encryptionType);
            result.put("sm4Key", sm4KeyBase64);
            result.put("chenConfig", chenConfig);

            log.info("混合加密测试完成: 通过率={}", 
                    report.getSummary().get("passRate"));

            return Result.success("测试完成", result);

        } catch (Exception e) {
            log.error("混合加密测试失败", e);
            return Result.error(500, "测试失败: " + e.getMessage());
        }
    }

    private BufferedImage deepCopy(BufferedImage bi) {
        BufferedImage copy = new BufferedImage(
                bi.getWidth(),
                bi.getHeight(),
                bi.getType()
        );
        copy.setData(bi.getData());
        return copy;
    }

    private byte[] imageToBytes(BufferedImage image) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        return baos.toByteArray();
    }
    private BufferedImage toBufferedImage(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data)) {
            return ImageIO.read(bis);
        } catch (Exception e) {
            log.warn("无法将数据解析为图像: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 获取测试报告列表
     */
    @GetMapping("/test-reports")
    public Result<Map<String, Object>> getTestReports() {
        try {
            File reportsDir = new File("test_reports");
            if (!reportsDir.exists()) {
                return Result.success("无测试报告", Map.of("reports", new String[0]));
            }

            File[] reportFiles = reportsDir.listFiles((dir, name) -> name.endsWith(".txt"));
            String[] reportNames = new String[reportFiles.length];

            for (int i = 0; i < reportFiles.length; i++) {
                reportNames[i] = reportFiles[i].getName();
            }

            Map<String, Object> result = new HashMap<>();
            result.put("reports", reportNames);
            result.put("count", reportNames.length);

            return Result.success("获取测试报告列表成功", result);

        } catch (Exception e) {
            log.error("获取测试报告列表失败", e);
            return Result.error(500, "获取失败: " + e.getMessage());
        }
    }

    /**
     * 下载测试报告
     */
    @GetMapping("/test-reports/{reportName}")
    public Result<String> downloadTestReport(@PathVariable String reportName) {
        try {
            File reportFile = new File("test_reports/" + reportName);
            if (!reportFile.exists()) {
                return Result.error(404, "报告文件不存在");
            }

            String reportContent = new String(Files.readAllBytes(reportFile.toPath()));
            return Result.success("获取报告成功", reportContent);

        } catch (Exception e) {
            log.error("下载测试报告失败", e);
            return Result.error(500, "下载失败: " + e.getMessage());
        }
    }
}