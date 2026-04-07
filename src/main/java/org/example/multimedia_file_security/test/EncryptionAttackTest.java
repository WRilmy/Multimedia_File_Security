package org.example.multimedia_file_security.test;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.example.multimedia_file_security.utils.Sm4EncryptionUtil;
import org.example.multimedia_file_security.utils.Sm4Util;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.bytesToHex;

@Component
@Slf4j
public class EncryptionAttackTest {

    private static final int SAMPLE_PAIRS = 3000;
    private static final double ALPHA = 0.01;

    @Data
    public static class TestResult {
        private String testName;
        private boolean passed;
        private String description;
        private Map<String, Object> metrics;
        private long executionTime;
        private String details;

        public TestResult(String testName, boolean passed, String description) {
            this.testName = testName;
            this.passed = passed;
            this.description = description;
            this.metrics = new LinkedHashMap<>();
            this.executionTime = 0;
            this.details = "";
        }

        public void addMetric(String key, Object value) {
            metrics.put(key, value);
        }
    }

    @Data
    public static class TestReport {
        private String testDate;
        private String testFile;
        private String encryptionMode;
        private int totalTests;
        private int passedTests;
        private int failedTests;
        private List<TestResult> results;
        private Map<String, Object> summary;

        public TestReport() {
            this.results = new ArrayList<>();
            this.summary = new LinkedHashMap<>();
        }

        public void addResult(TestResult result) {
            results.add(result);
            totalTests++;
            if (result.isPassed()) {
                passedTests++;
            } else {
                failedTests++;
            }
        }

        public void calculateSummary() {
            double passRate = totalTests > 0 ? (double) passedTests / totalTests * 100 : 0;
            summary.put("通过率", String.format("%.2f%%", passRate));
            summary.put("测试总数", totalTests);
            summary.put("通过数量", passedTests);
            summary.put("失败数量", failedTests);
        }
    }

    public TestReport runFullTestSuite(BufferedImage originalImage, BufferedImage encryptedImage, byte[] originalData,
                                       byte[] encryptedData, String encryptionMode, String filename) throws Exception {
        log.info("开始执行加密攻击测试套件");

        TestReport report = new TestReport();
        report.setTestDate(new Date().toString());
        report.setTestFile(filename);
        report.setEncryptionMode(encryptionMode);

        if ("FULL".equals(encryptionMode)) {
            runBasicSecurityTests(encryptedImage, encryptedData, report, encryptionMode);
            runCryptographicAttacks(originalData, encryptedData, report, encryptionMode, filename);
            runStatisticalAttacks(originalData, encryptedData, report, encryptedImage, encryptionMode);
            runFormatAnalysisAttacks(encryptedData, filename, report);
            exportByteHistogram(originalData, encryptedData, filename);
        } else {
            runSelectiveImageDomainTests(originalImage, encryptedImage, originalData, encryptedData, report, filename);
        }

        runPerformanceTests(originalData, report, encryptionMode, filename);

        if ("SELECTIVE".equals(encryptionMode)) {
            runSelectiveEncryptionTests(originalData, encryptedData, report);
        }

        report.calculateSummary();
        return report;
    }

    private void runSelectiveImageDomainTests(BufferedImage originalImage, BufferedImage encryptedImage,
                                              byte[] originalData, byte[] encryptedData,
                                              TestReport report, String filename) throws Exception {
        report.addResult(testDataEntropy(encryptedImage, encryptedData, "SELECTIVE"));
        report.addResult(testHistogramUniformity(originalImage, encryptedImage));
        report.addResult(testImagePlainCipherCorrelation(originalImage, encryptedImage, filename));
        report.addResult(testCorrelationAnalysis(encryptedData, encryptedImage, "SELECTIVE"));
        report.addResult(testSelectiveDifferentialAnalysis(originalData, filename));
        report.addResult(testAvalanche(originalData, "SELECTIVE", encryptedData));
        exportHistogramData(originalImage, encryptedImage, filename.replace(".", "_"));
    }

    public void runBasicSecurityTests(BufferedImage encryptedImage, byte[] encryptedData,
                                      TestReport report, String encryptionMode) {
        report.addResult(testDataEntropy(encryptedImage, encryptedData, encryptionMode));
        report.addResult(testDataDistribution(encryptedData));
        report.addResult(testPatternDetection(encryptedData));
    }

    public void runCryptographicAttacks(byte[] originalData, byte[] encryptedData,
                                        TestReport report, String encryptionMode,
                                        String filename) throws Exception {
        report.addResult(testMonobit(encryptedData));
        report.addResult(testNistBlockFrequency(encryptedData));
        report.addResult(testRuns(encryptedData));
        report.addResult(testNistApproximateEntropy(encryptedData));
        report.addResult(testNistCumulativeSums(encryptedData));
        report.addResult(testKnownPlaintextAttack(originalData, encryptedData));
        report.addResult(testDifferentialAttack(originalData, encryptionMode, filename));
    }

    public void runStatisticalAttacks(byte[] originalData, byte[] encryptedData, TestReport report,
                                      BufferedImage encryptedImage, String encryptionMode) {
        report.addResult(testFrequencyAnalysis(encryptedData));
        report.addResult(testCorrelationAnalysis(encryptedData, encryptedImage, encryptionMode));
        report.addResult(testAvalanche(originalData, encryptionMode, encryptedData));
    }

    private void runFormatAnalysisAttacks(byte[] encryptedData, String filename,
                                          TestReport report) {
        report.addResult(testFileHeaderAnalysis(encryptedData, filename));
        report.addResult(testFileStructureAnalysis(encryptedData, filename));
        report.addResult(testVisualInformationLeakage(encryptedData, filename));
    }

    public void runPerformanceTests(byte[] originalData, TestReport report,
                                    String encryptionMode, String filename) {
        report.addResult(testEncryptionDecryptionPerformance(originalData, encryptionMode, filename));
        report.addResult(testMemoryUsage(originalData, encryptionMode, filename));
    }

    public void runSelectiveEncryptionTests(byte[] originalData, byte[] encryptedData,
                                            TestReport report) {
        report.addResult(testEncryptionRatio(originalData, encryptedData));
        report.addResult(testVisualQuality(originalData, encryptedData));
    }

    private TestResult testDataEntropy(BufferedImage image, byte[] data, String encryptionMode) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("信息熵分析", true, "评估密文的统计随机性");

        double entropy = ("SELECTIVE".equals(encryptionMode) && image != null)
                ? calculateRGBEntropy(image)
                : calculateEntropy(data);

        result.addMetric("信息熵", String.format("%.4f", entropy));
        result.addMetric("理论最大值", "8.0000");
        result.addMetric("熵占比", String.format("%.2f%%", entropy / 8.0 * 100));

        if (entropy < 7.5) {
            result.setPassed(false);
            result.setDetails("信息熵偏低，说明密文仍可能保留可识别统计结构");
        } else {
            result.setDetails("信息熵较高，密文统计分布较均匀");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) {
            return 0;
        }

        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }

        double entropy = 0;
        for (int freq : frequency) {
            if (freq == 0) {
                continue;
            }
            double probability = (double) freq / data.length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    private double calculateRGBEntropy(BufferedImage image) {
        int[] r = new int[256];
        int[] g = new int[256];
        int[] b = new int[256];

        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int rgb = image.getRGB(x, y);
                r[(rgb >> 16) & 0xFF]++;
                g[(rgb >> 8) & 0xFF]++;
                b[rgb & 0xFF]++;
            }
        }

        return (histEntropy(r) + histEntropy(g) + histEntropy(b)) / 3.0;
    }

    private double histEntropy(int[] hist) {
        int total = Arrays.stream(hist).sum();
        if (total == 0) {
            return 0;
        }

        double entropy = 0;
        for (int h : hist) {
            if (h == 0) {
                continue;
            }
            double p = (double) h / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private TestResult testHistogramUniformity(BufferedImage originalImage, BufferedImage encryptedImage) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("直方图均匀性分析", true, "比较加密前后图像灰度直方图的离散程度");

        if (originalImage == null || encryptedImage == null) {
            result.setPassed(false);
            result.setDetails("图像不可解码，无法进行直方图均匀性分析");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        double originalCv = histogramCv(originalImage);
        double encryptedCv = histogramCv(encryptedImage);
        double flattenRatio = originalCv == 0 ? 0 : encryptedCv / originalCv;

        result.addMetric("原图直方图变异系数", String.format("%.6f", originalCv));
        result.addMetric("密文直方图变异系数", String.format("%.6f", encryptedCv));
        result.addMetric("均匀化比例", String.format("%.6f", flattenRatio));

        if (encryptedCv < originalCv) {
            result.setDetails("密文直方图比原图更均匀，说明统计特征被一定程度打散");
        } else {
            result.setPassed(false);
            result.setDetails("密文直方图没有明显均匀化，统计隐藏效果一般");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testImagePlainCipherCorrelation(BufferedImage originalImage, BufferedImage encryptedImage,
                                                       String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("明密文图像相关性分析", true, "评估原图与密文图在像素域上的线性相关程度");

        if (originalImage == null || encryptedImage == null) {
            result.setPassed(false);
            result.setDetails("图像不可解码，无法进行图像域相关性分析");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        int width = Math.min(originalImage.getWidth(), encryptedImage.getWidth());
        int height = Math.min(originalImage.getHeight(), encryptedImage.getHeight());
        List<Double> xs = new ArrayList<>(width * height);
        List<Double> ys = new ArrayList<>(width * height);

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                xs.add((double) gray(originalImage.getRGB(x, y)));
                ys.add((double) gray(encryptedImage.getRGB(x, y)));
            }
        }

        double corr = pearson(xs, ys);
        result.addMetric("图像域皮尔逊相关系数", String.format("%.8f", corr));

        double threshold = isLossyImageFormat(filename) ? 0.10 : 0.05;
        result.addMetric("判定阈值", String.format("%.2f", threshold));

        if (Math.abs(corr) > threshold) {
            result.setPassed(false);
            result.setDetails("原图与密文图像相关性偏高，图像域统计隐藏效果不足");
        } else {
            result.setDetails("原图与密文图像相关性接近于零，图像域统计隐藏效果较好");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private double histogramCv(BufferedImage image) {
        int[] histogram = new int[256];
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                histogram[gray(image.getRGB(x, y))]++;
            }
        }

        double mean = Arrays.stream(histogram).average().orElse(0);
        if (mean == 0) {
            return 0;
        }

        double variance = 0;
        for (int count : histogram) {
            double diff = count - mean;
            variance += diff * diff;
        }
        variance /= histogram.length;
        return Math.sqrt(variance) / mean;
    }

    private TestResult testDataDistribution(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("卡方分布检验", true, "检验密文字节分布是否接近均匀");

        int[] frequency = buildFrequency(data);
        double expected = (double) data.length / 256;
        if (expected < 5) {
            result.setPassed(false);
            result.setDetails("样本过小，卡方检验不具备统计意义");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        double chiSquare = 0;
        for (int f : frequency) {
            double diff = f - expected;
            chiSquare += diff * diff / expected;
        }

        ChiSquaredDistribution distribution = new ChiSquaredDistribution(255);
        double pValue = 1.0 - distribution.cumulativeProbability(chiSquare);

        result.addMetric("卡方统计量", String.format("%.4f", chiSquare));
        result.addMetric("p值", formatScientific(pValue));
        result.addMetric("期望频数", String.format("%.4f", expected));

        if (pValue < ALPHA) {
            result.setPassed(false);
            result.setDetails("拒绝均匀分布假设，说明密文分布仍存在显著偏差");
        } else {
            result.setDetails("无法拒绝均匀分布假设，说明密文字节分布较均匀");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testPatternDetection(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("重复模式检测", true, "检测滑动窗口下的重复模式强度");

        final int window = 8;
        if (data.length < window) {
            result.setPassed(false);
            result.setDetails("数据过短，无法进行重复模式检测");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        Map<Long, Integer> freq = new HashMap<>();
        long hash = 0;
        long mask = -1L;

        for (int i = 0; i < window; i++) {
            hash = (hash << 8) | (data[i] & 0xFFL);
        }
        freq.put(hash, 1);

        for (int i = window; i < data.length; i++) {
            hash = ((hash << 8) | (data[i] & 0xFFL)) & mask;
            freq.put(hash, freq.getOrDefault(hash, 0) + 1);
        }

        int totalPatterns = data.length - window + 1;
        int maxFrequency = freq.values().stream().max(Integer::compareTo).orElse(0);
        double repetitionRatio = (double) maxFrequency / totalPatterns;

        result.addMetric("窗口大小", window);
        result.addMetric("模式总数", totalPatterns);
        result.addMetric("唯一模式数", freq.size());
        result.addMetric("最大重复次数", maxFrequency);
        result.addMetric("最大重复占比", String.format("%.8f", repetitionRatio));

        if (repetitionRatio > 0.001) {
            result.setPassed(false);
            result.setDetails("检测到较强重复模式，说明密文中可能残留结构特征");
        } else {
            result.setDetails("未检测到显著重复模式");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testKnownPlaintextAttack(byte[] originalData, byte[] encryptedData) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("明密文相关性分析", true, "评估明文与密文之间的线性相关程度");

        double corr = calculateCorrelation(originalData, encryptedData);
        result.addMetric("皮尔逊相关系数", String.format("%.8f", corr));

        if (Math.abs(corr) > 0.05) {
            result.setPassed(false);
            result.setDetails("明文与密文相关性偏高，不利于说明统计隐藏效果");
        } else {
            result.setDetails("明文与密文相关性接近于零，统计隐藏效果较好");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private double calculateCorrelation(byte[] x, byte[] y) {
        int n = Math.min(x.length, y.length);
        if (n == 0) {
            return 0;
        }

        double meanX = 0;
        double meanY = 0;
        for (int i = 0; i < n; i++) {
            meanX += x[i] & 0xFF;
            meanY += y[i] & 0xFF;
        }
        meanX /= n;
        meanY /= n;

        double numerator = 0;
        double denomX = 0;
        double denomY = 0;
        for (int i = 0; i < n; i++) {
            double dx = (x[i] & 0xFF) - meanX;
            double dy = (y[i] & 0xFF) - meanY;
            numerator += dx * dy;
            denomX += dx * dx;
            denomY += dy * dy;
        }

        if (denomX == 0 || denomY == 0) {
            return 0;
        }
        return numerator / Math.sqrt(denomX * denomY);
    }

    private TestResult testMonobit(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("单比特频数检验", true, "参考 NIST SP 800-22 的单比特频数检验");

        int ones = 0;
        int totalBits = data.length * 8;
        for (byte b : data) {
            ones += Integer.bitCount(b & 0xFF);
        }

        int zeros = totalBits - ones;
        double sObs = Math.abs(ones - zeros) / Math.sqrt(totalBits);
        double pValue = erfc(sObs / Math.sqrt(2.0));

        result.addMetric("1的数量", ones);
        result.addMetric("0的数量", zeros);
        result.addMetric("p值", formatScientific(pValue));

        if (pValue < ALPHA) {
            result.setPassed(false);
            result.setDetails("未通过单比特频数检验，说明比特分布不够均衡");
        } else {
            result.setDetails("通过单比特频数检验");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testRuns(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("游程检验", true, "参考 NIST SP 800-22 的游程检验");

        int[] bits = toBitArray(data);
        int n = bits.length;

        double pi = 0;
        for (int bit : bits) {
            pi += bit;
        }
        pi /= n;

        double tau = 2.0 / Math.sqrt(n);
        if (Math.abs(pi - 0.5) >= tau) {
            result.setPassed(false);
            result.addMetric("比特中1的比例", String.format("%.8f", pi));
            result.addMetric("前提阈值", String.format("%.8f", tau));
            result.setDetails("不满足游程检验前提条件，说明比特比例已明显偏离均衡");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        int runs = 1;
        for (int i = 1; i < n; i++) {
            if (bits[i] != bits[i - 1]) {
                runs++;
            }
        }

        double numerator = Math.abs(runs - 2.0 * n * pi * (1 - pi));
        double denominator = 2.0 * Math.sqrt(2.0 * n) * pi * (1 - pi);
        double pValue = erfc(numerator / denominator);

        result.addMetric("比特中1的比例", String.format("%.8f", pi));
        result.addMetric("游程数", runs);
        result.addMetric("p值", formatScientific(pValue));

        if (pValue < ALPHA) {
            result.setPassed(false);
            result.setDetails("未通过游程检验，说明密文中可能存在模式性切换结构");
        } else {
            result.setDetails("通过游程检验");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testNistBlockFrequency(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("NIST分组频数检验", true,
                "参考 NIST SP 800-22 的分组比特频数检验");

        int[] bits = toBitArray(data);
        int n = bits.length;
        int blockSize = chooseBlockSize(n);
        int blockCount = n / blockSize;

        if (blockCount < 8) {
            result.setPassed(false);
            result.addMetric("比特数量", n);
            result.addMetric("分组长度", blockSize);
            result.setDetails("样本形成的完整分组数不足 8 组，分组频数检验结果不稳定");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        double chiSquare = 0;
        for (int i = 0; i < blockCount; i++) {
            int ones = 0;
            int offset = i * blockSize;
            for (int j = 0; j < blockSize; j++) {
                ones += bits[offset + j];
            }
            double pi = (double) ones / blockSize;
            chiSquare += 4.0 * blockSize * Math.pow(pi - 0.5, 2);
        }

        ChiSquaredDistribution distribution = new ChiSquaredDistribution(blockCount);
        double pValue = 1.0 - distribution.cumulativeProbability(chiSquare);

        result.addMetric("比特数量", n);
        result.addMetric("分组长度", blockSize);
        result.addMetric("分组数量", blockCount);
        result.addMetric("卡方统计量", String.format("%.6f", chiSquare));
        result.addMetric("p值", formatScientific(pValue));

        if (pValue < ALPHA) {
            result.setPassed(false);
            result.setDetails("未通过分组频数检验，说明局部比特频数分布可能偏离均匀");
        } else {
            result.setDetails("通过分组频数检验");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testNistApproximateEntropy(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("NIST近似熵检验", true,
                "参考 NIST SP 800-22 的近似熵检验，评估比特模式重复情况");

        int[] bits = toBitArray(data);
        int n = bits.length;
        int m = 2;

        if (n < 1024) {
            result.setPassed(false);
            result.addMetric("比特数量", n);
            result.setDetails("近似熵检验需要足够长的比特序列，当前样本过小");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        double phiM = approximateEntropyPhi(bits, m);
        double phiMPlus1 = approximateEntropyPhi(bits, m + 1);
        double apEn = phiM - phiMPlus1;
        double chiSquare = 2.0 * n * (Math.log(2) - apEn);

        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1 << (m - 1));
        double pValue = 1.0 - distribution.cumulativeProbability(chiSquare);

        result.addMetric("模式长度m", m);
        result.addMetric("近似熵", String.format("%.6f", apEn));
        result.addMetric("卡方统计量", String.format("%.6f", chiSquare));
        result.addMetric("p值", formatScientific(pValue));

        if (pValue < ALPHA) {
            result.setPassed(false);
            result.setDetails("未通过近似熵检验，说明比特模式重复的随机性不足");
        } else {
            result.setDetails("通过近似熵检验");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testNistCumulativeSums(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("NIST累加和检验", true,
                "参考 NIST SP 800-22 的累加和检验，评估随机漂移程度");

        int[] bits = toBitArray(data);
        int n = bits.length;
        if (n == 0) {
            result.setPassed(false);
            result.setDetails("比特序列为空，无法进行累加和检验");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        int sum = 0;
        int maxAbs = 0;
        for (int bit : bits) {
            sum += bit == 1 ? 1 : -1;
            maxAbs = Math.max(maxAbs, Math.abs(sum));
        }

        double pValue = cumulativeSumsPValue(bits);
        result.addMetric("比特数量", n);
        result.addMetric("最大绝对偏移", maxAbs);
        result.addMetric("p值", formatScientific(pValue));

        if (pValue < ALPHA) {
            result.setPassed(false);
            result.setDetails("未通过累加和检验，说明可能存在统计漂移");
        } else {
            result.setDetails("通过累加和检验");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testDifferentialAttack(byte[] originalData, String encryptionMode, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("差分攻击分析", true, "计算 NPCR/UACI 评估明文敏感性");

        if ("SELECTIVE".equals(encryptionMode) && isLossyImageFormat(filename)) {
            result.addMetric("适用性说明", "JPEG等有损格式的选择性加密不以 NPCR/UACI 作为硬性否决指标");
            result.setDetails("当前文件属于有损压缩格式，NPCR/UACI 在此场景下仅作参考，不纳入否决");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        try {
            BufferedImage original = ImageIO.read(new ByteArrayInputStream(originalData));
            if (original == null) {
                result.setPassed(false);
                result.setDetails("仅图像数据支持 NPCR/UACI 测试");
                result.setExecutionTime(System.currentTimeMillis() - startTime);
                return result;
            }

            BufferedImage modified = deepCopy(original);
            modified.setRGB(0, 0, modified.getRGB(0, 0) ^ 0x00010101);

            String keyBase64 = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());
            byte[] image1 = imageToBytes(original, filename);
            byte[] image2 = imageToBytes(modified, filename);

            byte[] cipher1 = encryptForTest(image1, filename, encryptionMode, keyBase64);
            byte[] cipher2 = encryptForTest(image2, filename, encryptionMode, keyBase64);

            BufferedImage encImage1 = ImageIO.read(new ByteArrayInputStream(cipher1));
            BufferedImage encImage2 = ImageIO.read(new ByteArrayInputStream(cipher2));

            if (encImage1 != null && encImage2 != null) {
                double npcr = calculateNPCR(encImage1, encImage2);
                double uaci = calculateUACI(encImage1, encImage2);

                result.addMetric("NPCR", String.format("%.4f%%", npcr));
                result.addMetric("UACI", String.format("%.4f%%", uaci));

                if (npcr < 99.0 || uaci < 30.0) {
                    result.setPassed(false);
                    result.setDetails("差分扩散能力偏弱，明文微小变化未能充分传递到密文图像");
                } else {
                    result.setDetails("NPCR/UACI 结果较好，说明算法对明文变化较敏感");
                }
            } else {
                double byteNpcr = calculateByteNPCR(cipher1, cipher2);
                double byteUaci = calculateByteUACI(cipher1, cipher2);
                result.addMetric("字节级NPCR", String.format("%.4f%%", byteNpcr));
                result.addMetric("字节级UACI", String.format("%.4f%%", byteUaci));
                result.setDetails("密文不可直接解码为图像，已退化为字节级差分分析");
            }
        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("差分测试失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testSelectiveDifferentialAnalysis(byte[] originalData, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("差分敏感性分析", true, "评估格式保持选择性加密对明文微小变化的响应方式");

        if (isLossyImageFormat(filename)) {
            result.addMetric("适用性说明", "JPEG等有损格式的选择性加密不以 NPCR/UACI 作为硬性否决指标");
            result.addMetric("评价口径", "有损重编码会弱化单像素扰动传播，JPEG更关注视觉失真和统计特征削弱");
            result.setDetails("当前 JPEG 方案以可解码预览与精确恢复原图为目标，NPCR/UACI 仅保留在全文件或强扩散方案中使用");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        if (filename != null && filename.toLowerCase().endsWith(".bmp")) {
            result.addMetric("适用性说明", "BMP 选择性加密包含随机 IV，同一明文重复加密会引入随机扰动");
            result.addMetric("评价口径", "BMP 不使用两次独立加密结果的 NPCR/UACI 作为否决指标");
            result.setDetails("当前 BMP 方案强调内容区随机扰乱与可逆解密，重复加密随机性会放大差分统计，因此改为说明性指标");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        try {
            BufferedImage original = ImageIO.read(new ByteArrayInputStream(originalData));
            if (original == null) {
                result.setPassed(false);
                result.setDetails("图像不可解码，无法进行选择性差分敏感性分析");
                result.setExecutionTime(System.currentTimeMillis() - startTime);
                return result;
            }

            BufferedImage modified = deepCopy(original);
            modified.setRGB(0, 0, modified.getRGB(0, 0) ^ 0x00010101);

            String keyBase64 = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());
            byte[] image1 = imageToBytes(original, filename);
            byte[] image2 = imageToBytes(modified, filename);

            byte[] cipher1 = encryptForTest(image1, filename, "SELECTIVE", keyBase64);
            byte[] cipher2 = encryptForTest(image2, filename, "SELECTIVE", keyBase64);

            BufferedImage encImage1 = ImageIO.read(new ByteArrayInputStream(cipher1));
            BufferedImage encImage2 = ImageIO.read(new ByteArrayInputStream(cipher2));

            if (encImage1 != null && encImage2 != null) {
                double npcr = calculateNPCR(encImage1, encImage2);
                double uaci = calculateUACI(encImage1, encImage2);
                result.addMetric("参考NPCR", String.format("%.4f%%", npcr));
                result.addMetric("参考UACI", String.format("%.4f%%", uaci));
                result.addMetric("评价口径", "PNG 等无损格式的选择性加密更强调局部敏感性而非全局扩散");

                if (npcr > 0) {
                    result.setDetails("明文微小变化能够传递到对应密文区域；该指标在当前设计下作为参考项，不作为全局扩散否决标准");
                } else {
                    result.setPassed(false);
                    result.setDetails("明文微小变化未能反映到密文图像，局部敏感性不足");
                }
            } else {
                double byteNpcr = calculateByteNPCR(cipher1, cipher2);
                double byteUaci = calculateByteUACI(cipher1, cipher2);
                result.addMetric("参考字节级NPCR", String.format("%.4f%%", byteNpcr));
                result.addMetric("参考字节级UACI", String.format("%.4f%%", byteUaci));
                result.addMetric("评价口径", "密文图像不可解码时退化为字节级比较，仅作参考");
                result.setDetails("该结果仅作参考，不作为格式保持选择性加密的主要否决指标");
            }
        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("选择性差分敏感性分析失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private double calculateNPCR(BufferedImage img1, BufferedImage img2) {
        int width = Math.min(img1.getWidth(), img2.getWidth());
        int height = Math.min(img1.getHeight(), img2.getHeight());
        long diff = 0;
        long total = (long) width * height;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (img1.getRGB(x, y) != img2.getRGB(x, y)) {
                    diff++;
                }
            }
        }
        return total == 0 ? 0 : (double) diff / total * 100;
    }

    private double calculateUACI(BufferedImage img1, BufferedImage img2) {
        int width = Math.min(img1.getWidth(), img2.getWidth());
        int height = Math.min(img1.getHeight(), img2.getHeight());
        double sum = 0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb1 = img1.getRGB(x, y);
                int rgb2 = img2.getRGB(x, y);
                sum += channelDiff((rgb1 >> 16) & 0xFF, (rgb2 >> 16) & 0xFF);
                sum += channelDiff((rgb1 >> 8) & 0xFF, (rgb2 >> 8) & 0xFF);
                sum += channelDiff(rgb1 & 0xFF, rgb2 & 0xFF);
            }
        }

        return width == 0 || height == 0 ? 0 : sum / (width * height * 3 * 255.0) * 100;
    }

    private double channelDiff(int a, int b) {
        return Math.abs(a - b);
    }

    private double calculateByteNPCR(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        int diff = 0;
        for (int i = 0; i < n; i++) {
            if (a[i] != b[i]) {
                diff++;
            }
        }
        return n == 0 ? 0 : (double) diff / n * 100;
    }

    private double calculateByteUACI(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        double sum = 0;
        for (int i = 0; i < n; i++) {
            sum += Math.abs((a[i] & 0xFF) - (b[i] & 0xFF));
        }
        return n == 0 ? 0 : sum / (n * 255.0) * 100;
    }

    private BufferedImage deepCopy(BufferedImage bi) {
        BufferedImage copy = new BufferedImage(bi.getWidth(), bi.getHeight(), bi.getType());
        copy.setData(bi.getData());
        return copy;
    }

    private byte[] imageToBytes(BufferedImage image, String filename) throws IOException {
        String format = getImageFormat(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, format, baos);
        return baos.toByteArray();
    }

    private String getImageFormat(String filename) {
        if (filename == null) {
            return "png";
        }
        String lower = filename.toLowerCase();
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "jpg";
        }
        if (lower.endsWith(".bmp")) {
            return "bmp";
        }
        if (lower.endsWith(".gif")) {
            return "gif";
        }
        return "png";
    }

    private boolean isLossyImageFormat(String filename) {
        if (filename == null) {
            return false;
        }
        String lower = filename.toLowerCase();
        return lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".webp");
    }

    private byte[] encryptForTest(byte[] data, String filename, String encryptionMode, String keyBase64)
            throws Exception {
        if ("SELECTIVE".equals(encryptionMode)) {
            return Sm4EncryptionUtil.selectiveEncrypt(new InMemoryMultipartFile(filename, data), keyBase64);
        }
        return Sm4EncryptionUtil.fullEncrypt(data, keyBase64);
    }

    private byte[] decryptForTest(byte[] encrypted, String filename, String encryptionMode, String keyBase64)
            throws Exception {
        if ("SELECTIVE".equals(encryptionMode)) {
            return Sm4EncryptionUtil.selectiveDecrypt(encrypted, filename, keyBase64);
        }
        return Sm4EncryptionUtil.fullDecrypt(encrypted, keyBase64);
    }

    private TestResult testFrequencyAnalysis(byte[] data) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("频率分布分析", true, "分析密文字节频率偏差程度");

        int[] frequency = buildFrequency(data);
        double expected = (double) data.length / 256;
        double variance = 0;
        for (int f : frequency) {
            variance += Math.pow(f - expected, 2);
        }
        variance /= 256;
        double stdDev = Math.sqrt(variance);
        double cv = expected == 0 ? 0 : stdDev / expected;

        result.addMetric("均值", String.format("%.4f", expected));
        result.addMetric("标准差", String.format("%.4f", stdDev));
        result.addMetric("变异系数", String.format("%.6f", cv));

        if (cv > 0.15) {
            result.setPassed(false);
            result.setDetails("频率波动较大，说明密文字节分布不够稳定");
        } else {
            result.setDetails("频率分布波动较小");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testCorrelationAnalysis(byte[] data, BufferedImage encryptedImage, String encryptionMode) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("相关性分析", true, "评估密文相邻样本之间的相关程度");

        if ("SELECTIVE".equals(encryptionMode) && encryptedImage != null) {
            double horizontal = calculateAdjacentPixelCorrelation(encryptedImage, 1, 0);
            double vertical = calculateAdjacentPixelCorrelation(encryptedImage, 0, 1);
            double diagonal = calculateAdjacentPixelCorrelation(encryptedImage, 1, 1);
            double maxAbs = Math.max(Math.abs(horizontal), Math.max(Math.abs(vertical), Math.abs(diagonal)));

            result.addMetric("水平相关系数", String.format("%.8f", horizontal));
            result.addMetric("垂直相关系数", String.format("%.8f", vertical));
            result.addMetric("对角相关系数", String.format("%.8f", diagonal));

            if (maxAbs > 0.1) {
                result.setPassed(false);
                result.setDetails("密文图像相邻像素相关性仍较明显");
            } else {
                result.setDetails("密文图像相邻像素相关性较低");
            }
        } else {
            double maxCorr = calculateByteAutocorrelation(data, Math.min(100, Math.max(1, data.length / 20)));
            result.addMetric("最大字节自相关", String.format("%.8f", maxCorr));
            if (maxCorr > 0.05) {
                result.setPassed(false);
                result.setDetails("密文字节序列存在较明显自相关");
            } else {
                result.setDetails("密文字节序列自相关较低");
            }
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private double calculateAdjacentPixelCorrelation(BufferedImage image, int dx, int dy) {
        List<Double> xs = new ArrayList<>();
        List<Double> ys = new ArrayList<>();

        for (int y = 0; y < image.getHeight() - dy && xs.size() < SAMPLE_PAIRS; y++) {
            for (int x = 0; x < image.getWidth() - dx && xs.size() < SAMPLE_PAIRS; x++) {
                xs.add((double) gray(image.getRGB(x, y)));
                ys.add((double) gray(image.getRGB(x + dx, y + dy)));
            }
        }
        return pearson(xs, ys);
    }

    private int gray(int rgb) {
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return (r + g + b) / 3;
    }

    private double pearson(List<Double> xs, List<Double> ys) {
        int n = Math.min(xs.size(), ys.size());
        if (n == 0) {
            return 0;
        }

        double meanX = xs.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double meanY = ys.stream().mapToDouble(Double::doubleValue).average().orElse(0);

        double numerator = 0;
        double denomX = 0;
        double denomY = 0;
        for (int i = 0; i < n; i++) {
            double dx = xs.get(i) - meanX;
            double dy = ys.get(i) - meanY;
            numerator += dx * dy;
            denomX += dx * dx;
            denomY += dy * dy;
        }

        if (denomX == 0 || denomY == 0) {
            return 0;
        }
        return numerator / Math.sqrt(denomX * denomY);
    }

    private double calculateByteAutocorrelation(byte[] data, int maxLag) {
        int n = data.length;
        if (n < 2) {
            return 0;
        }

        double mean = 0;
        for (byte b : data) {
            mean += b & 0xFF;
        }
        mean /= n;

        double variance = 0;
        for (byte b : data) {
            double diff = (b & 0xFF) - mean;
            variance += diff * diff;
        }
        if (variance == 0) {
            return 0;
        }

        double maxCorr = 0;
        for (int lag = 1; lag <= maxLag; lag++) {
            double numerator = 0;
            for (int i = 0; i < n - lag; i++) {
                double x = (data[i] & 0xFF) - mean;
                double y = (data[i + lag] & 0xFF) - mean;
                numerator += x * y;
            }
            maxCorr = Math.max(maxCorr, Math.abs(numerator / variance));
        }
        return maxCorr;
    }

    private TestResult testFileHeaderAnalysis(byte[] data, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("文件头分析", true, "分析密文文件头是否泄露原始格式标识");

        String originalHeader = getFileHeader(filename);
        String encryptedHeader = getHexHeader(data);
        boolean headerChanged = !originalHeader.equals("UNKNOWN")
                && encryptedHeader.length() >= originalHeader.length()
                && !originalHeader.equals(encryptedHeader.substring(0, originalHeader.length()));

        result.addMetric("原始文件头", originalHeader);
        result.addMetric("密文文件头", encryptedHeader);
        result.addMetric("文件头是否变化", headerChanged ? "是" : "否");

        if (!headerChanged) {
            result.setPassed(false);
            result.setDetails("密文头部仍保留原始格式特征");
        } else {
            result.setDetails("密文头部已打乱，格式泄露风险较低");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private String getFileHeader(String filename) {
        if (filename == null) {
            return "UNKNOWN";
        }
        String lower = filename.toLowerCase();
        if (lower.endsWith(".bmp")) return "424D";
        if (lower.endsWith(".png")) return "89504E470D0A1A0A";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "FFD8FF";
        if (lower.endsWith(".gif")) return "47494638";
        if (lower.endsWith(".mp4")) return "000000";
        return "UNKNOWN";
    }

    private String getHexHeader(byte[] data) {
        int length = Math.min(16, data.length);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < length; i++) {
            hex.append(String.format("%02X", data[i] & 0xFF));
        }
        return hex.toString();
    }

    private TestResult testFileStructureAnalysis(byte[] data, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("文件结构分析", true, "分析密文是否仍保留明显格式结构");

        boolean hasStructure = false;
        String lower = filename.toLowerCase();
        if (lower.endsWith(".png")) {
            hasStructure = data.length >= 8 && data[0] == (byte) 0x89 && data[1] == 0x50;
        } else if (lower.endsWith(".bmp")) {
            hasStructure = data.length >= 2 && data[0] == 0x42 && data[1] == 0x4D;
        } else if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            hasStructure = data.length >= 2 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xD8;
        }

        result.addMetric("是否保留格式结构", hasStructure ? "是" : "否");

        if (hasStructure) {
            result.setPassed(false);
            result.setDetails("密文仍可识别出明显文件结构");
        } else {
            result.setDetails("密文结构已被充分打散");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testVisualInformationLeakage(byte[] data, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("可视化信息泄露分析", true, "评估全加密密文是否仍可被图像解码器识别");

        String lower = filename.toLowerCase();
        if (!lower.endsWith(".bmp") && !lower.endsWith(".png") && !lower.endsWith(".jpg") && !lower.endsWith(".jpeg")) {
            result.setDetails("非图像文件，跳过可视化泄露测试");
            result.setExecutionTime(System.currentTimeMillis() - startTime);
            return result;
        }

        try {
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(data));
            boolean decodable = image != null;

            result.addMetric("是否可解码", decodable ? "是" : "否");
            if (decodable) {
                result.setPassed(false);
                result.setDetails("全加密后仍可被图像解码器读取，存在格式或视觉泄露风险");
            } else {
                result.setDetails("全加密密文不可被图像解码器直接识别");
            }
        } catch (Exception e) {
            result.addMetric("是否可解码", "否");
            result.setDetails("全加密密文不可被图像解码器直接识别");
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testEncryptionDecryptionPerformance(byte[] originalData, String encryptionMode, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("加解密性能测试", true, "统计测试样本的加解密耗时与吞吐率");

        try {
            String keyBase64 = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());

            long encryptStart = System.currentTimeMillis();
            byte[] encrypted = encryptForTest(originalData, filename, encryptionMode, keyBase64);
            long encryptTime = System.currentTimeMillis() - encryptStart;

            long decryptStart = System.currentTimeMillis();
            byte[] decrypted = decryptForTest(encrypted, filename, encryptionMode, keyBase64);
            long decryptTime = System.currentTimeMillis() - decryptStart;


            double encThroughput = originalData.length / Math.max(1.0, encryptTime) / 1024.0;
            double decThroughput = decrypted.length / Math.max(1.0, decryptTime) / 1024.0;

            result.addMetric("数据大小", originalData.length + " 字节");
            result.addMetric("加密耗时", encryptTime + " ms");
            result.addMetric("解密耗时", decryptTime + " ms");
            result.addMetric("加密吞吐率", String.format("%.2f KB/s", encThroughput * 1000));
            result.addMetric("解密吞吐率", String.format("%.2f KB/s", decThroughput * 1000));
            result.setDetails("性能测试完毕");

        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("性能测试失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testMemoryUsage(byte[] originalData, String encryptionMode, String filename) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("内存开销测试", true, "估计单次加解密过程中的额外内存使用");

        Runtime runtime = Runtime.getRuntime();
        long memoryBefore = runtime.totalMemory() - runtime.freeMemory();

        try {
            String keyBase64 = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());
            byte[] encrypted = encryptForTest(originalData, filename, encryptionMode, keyBase64);
            byte[] decrypted = decryptForTest(encrypted, filename, encryptionMode, keyBase64);

            long memoryAfter = runtime.totalMemory() - runtime.freeMemory();
            long memoryUsed = Math.max(0, memoryAfter - memoryBefore);
            double memoryPerMB = originalData.length == 0 ? 0
                    : memoryUsed / (originalData.length / 1024.0 / 1024.0);

            result.addMetric("估计额外内存", memoryUsed + " 字节");
            result.addMetric("每MB数据内存开销", String.format("%.2f 字节/MB", memoryPerMB));
            result.addMetric("结果校验", Arrays.equals(originalData, decrypted) ? "正确" : "错误");
            result.setDetails("该指标受 JVM 垃圾回收影响较大，仅用于工程比较");
        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("内存开销测试失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testEncryptionRatio(byte[] originalData, byte[] encryptedData) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("像素变化率分析", true, "统计选择性加密后发生变化的像素比例");

        try {
            BufferedImage originalImage = ImageIO.read(new ByteArrayInputStream(originalData));
            BufferedImage encryptedImage = ImageIO.read(new ByteArrayInputStream(encryptedData));
            if (originalImage == null || encryptedImage == null) {
                result.setPassed(false);
                result.setDetails("密文图像不可解码，无法计算像素变化率");
                result.setExecutionTime(System.currentTimeMillis() - startTime);
                return result;
            }

            int width = Math.min(originalImage.getWidth(), encryptedImage.getWidth());
            int height = Math.min(originalImage.getHeight(), encryptedImage.getHeight());
            int changedPixels = 0;

            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    if (originalImage.getRGB(x, y) != encryptedImage.getRGB(x, y)) {
                        changedPixels++;
                    }
                }
            }

            int totalPixels = width * height;
            double ratio = totalPixels == 0 ? 0 : (double) changedPixels / totalPixels * 100;

            result.addMetric("总像素数", totalPixels);
            result.addMetric("变化像素数", changedPixels);
            result.addMetric("像素变化率", String.format("%.4f%%", ratio));

            if (ratio < 50) {
                result.setPassed(false);
                result.setDetails("像素变化比例偏低，选择性扰动强度不足");
            } else {
                result.setDetails("像素变化比例较高");
            }
        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("像素变化率测试失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testVisualQuality(byte[] originalData, byte[] encryptedData) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("视觉失真分析", true, "计算 MSE 与 PSNR 评估密文图像可辨识程度");

        try {
            BufferedImage original = ImageIO.read(new ByteArrayInputStream(originalData));
            BufferedImage encrypted = ImageIO.read(new ByteArrayInputStream(encryptedData));

            if (original == null || encrypted == null) {
                result.setPassed(false);
                result.setDetails("密文图像不可解码，无法直接计算 MSE/PSNR");
                result.setExecutionTime(System.currentTimeMillis() - startTime);
                return result;
            }

            int width = Math.min(original.getWidth(), encrypted.getWidth());
            int height = Math.min(original.getHeight(), encrypted.getHeight());
            double mse = 0;

            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    int gray1 = gray(original.getRGB(x, y));
                    int gray2 = gray(encrypted.getRGB(x, y));
                    double diff = gray1 - gray2;
                    mse += diff * diff;
                }
            }
            mse /= Math.max(1, width * height);

            double psnr = mse == 0 ? 100 : 10 * Math.log10(255 * 255 / mse);

            result.addMetric("均方误差MSE", String.format("%.4f", mse));
            result.addMetric("峰值信噪比PSNR", String.format("%.4f dB", psnr));

            if (psnr > 20) {
                result.setPassed(false);
                result.setDetails("PSNR 偏高，说明密文图像仍可能保留较强可辨识信息");
            } else {
                result.setDetails("PSNR 较低，说明图像视觉失真明显");
            }
        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("视觉失真测试失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private TestResult testAvalanche(byte[] originalData, String encryptionMode, byte[] ignoredEncryptedData) {
        long startTime = System.currentTimeMillis();
        TestResult result = new TestResult("雪崩效应分析", true, "比较单比特明文扰动前后两次密文差异");

        try {
            String keyBase64 = Base64.getEncoder().encodeToString(Sm4Util.generateSm4Key().getEncoded());
            byte[] modified = Arrays.copyOf(originalData, originalData.length);
            if (modified.length > 0) {
                modified[0] ^= 0x01;
            }

            String filename = detectFileType(originalData);
            if ("UNKNOWN".equals(filename)) {
                filename = "sample.bin";
            } else {
                filename = "sample." + filename;
            }

            byte[] cipher1 = encryptForTest(originalData, filename, encryptionMode, keyBase64);
            byte[] cipher2 = encryptForTest(modified, filename, encryptionMode, keyBase64);

            int n = Math.min(cipher1.length, cipher2.length);
            int diffBits = 0;
            for (int i = 0; i < n; i++) {
                diffBits += Integer.bitCount((cipher1[i] ^ cipher2[i]) & 0xFF);
            }
            double avalancheRatio = n == 0 ? 0 : (double) diffBits / (n * 8);

            result.addMetric("雪崩比", String.format("%.6f", avalancheRatio));
            result.addMetric("比较比特数", n * 8);

            if (avalancheRatio < 0.45 || avalancheRatio > 0.55) {
                result.setPassed(false);
                result.setDetails("雪崩比偏离理想区间 [0.45, 0.55]");
            } else {
                result.setDetails("雪崩比接近理想值 0.5");
            }
        } catch (Exception e) {
            result.setPassed(false);
            result.setDetails("雪崩效应测试失败: " + e.getMessage());
        }

        result.setExecutionTime(System.currentTimeMillis() - startTime);
        return result;
    }

    private int[] buildFrequency(byte[] data) {
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        return frequency;
    }

    private int[] toBitArray(byte[] data) {
        int[] bits = new int[data.length * 8];
        int index = 0;
        for (byte b : data) {
            for (int i = 7; i >= 0; i--) {
                bits[index++] = (b >> i) & 1;
            }
        }
        return bits;
    }

    private int chooseBlockSize(int bitLength) {
        if (bitLength >= 1_000_000) {
            return 1024;
        }
        if (bitLength >= 100_000) {
            return 256;
        }
        if (bitLength >= 10_000) {
            return 128;
        }
        return 32;
    }

    private double approximateEntropyPhi(int[] bits, int m) {
        int n = bits.length;
        int patterns = 1 << m;
        int[] counts = new int[patterns];

        for (int i = 0; i < n; i++) {
            int pattern = 0;
            for (int j = 0; j < m; j++) {
                pattern = (pattern << 1) | bits[(i + j) % n];
            }
            counts[pattern]++;
        }

        double phi = 0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double p = (double) count / n;
            phi += p * Math.log(p);
        }
        return phi;
    }

    private double cumulativeSumsPValue(int[] bits) {
        int n = bits.length;
        int sum = 0;
        int z = 0;
        for (int bit : bits) {
            sum += bit == 1 ? 1 : -1;
            z = Math.max(z, Math.abs(sum));
        }

        if (z == 0) {
            return 1.0;
        }

        double sqrtN = Math.sqrt(n);
        double first = 0;
        int start1 = (int) Math.floor((-n / (double) z + 1.0) / 4.0);
        int end1 = (int) Math.floor((n / (double) z - 1.0) / 4.0);
        for (int k = start1; k <= end1; k++) {
            first += normalCdf((4 * k + 1) * z / sqrtN)
                    - normalCdf((4 * k - 1) * z / sqrtN);
        }

        double second = 0;
        int start2 = (int) Math.floor((-n / (double) z - 3.0) / 4.0);
        int end2 = (int) Math.floor((n / (double) z - 1.0) / 4.0);
        for (int k = start2; k <= end2; k++) {
            second += normalCdf((4 * k + 3) * z / sqrtN)
                    - normalCdf((4 * k + 1) * z / sqrtN);
        }

        double pValue = 1.0 - first + second;
        if (Double.isNaN(pValue)) {
            return 0;
        }
        return Math.max(0.0, Math.min(1.0, pValue));
    }

    private double normalCdf(double x) {
        return 0.5 * (1.0 + erf(x / Math.sqrt(2.0)));
    }

    private double erfc(double x) {
        return 1 - erf(x);
    }

    private double erf(double x) {
        double t = 1.0 / (1.0 + 0.5 * Math.abs(x));
        double tau = t * Math.exp(-x * x - 1.26551223
                + t * (1.00002368
                + t * (0.37409196
                + t * (0.09678418
                + t * (-0.18628806
                + t * (0.27886807
                + t * (-1.13520398
                + t * (1.48851587
                + t * (-0.82215223
                + t * 0.17087277)))))))));
        return x >= 0 ? 1 - tau : tau - 1;
    }

    private String detectFileType(byte[] data) {
        String header = bytesToHex(data);
        if (header.startsWith("FFD8FF")) return "jpg";
        if (header.startsWith("89504E470D0A1A0A")) return "png";
        if (header.startsWith("47494638")) return "gif";
        if (header.startsWith("424D")) return "bmp";
        if (header.startsWith("25504446")) return "pdf";
        if (header.startsWith("504B0304")) return "zip";
        return "UNKNOWN";
    }

    private String formatScientific(double value) {
        return String.format("%.6e", value);
    }

    public String generateTestReport(TestReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append("加密安全性测试报告\n");
        sb.append("================================================================================\n\n");

        sb.append("测试日期: ").append(report.getTestDate()).append("\n");
        sb.append("测试文件: ").append(report.getTestFile()).append("\n");
        sb.append("加密模式: ").append(report.getEncryptionMode()).append("\n\n");

        sb.append("----------------------------------------\n");
        sb.append("测试摘要\n");
        sb.append("----------------------------------------\n");
        report.getSummary().forEach((key, value) -> sb.append(key).append(": ").append(value).append("\n"));

        sb.append("\n----------------------------------------\n");
        sb.append("详细测试结果\n");
        sb.append("----------------------------------------\n\n");

        for (TestResult testResult : report.getResults()) {
            sb.append("测试项: ").append(testResult.getTestName()).append("\n");
            sb.append("状态: ").append(testResult.isPassed() ? "通过" : "失败").append("\n");
            sb.append("说明: ").append(testResult.getDescription()).append("\n");
            sb.append("耗时: ").append(testResult.getExecutionTime()).append(" ms\n");

            if (!testResult.getMetrics().isEmpty()) {
                sb.append("指标:\n");
                testResult.getMetrics().forEach((key, value) ->
                        sb.append("  ").append(key).append(": ").append(value).append("\n"));
            }

            if (testResult.getDetails() != null && !testResult.getDetails().isEmpty()) {
                sb.append("结论: ").append(testResult.getDetails()).append("\n");
            }
            sb.append("\n");
        }

        sb.append("================================================================================\n");
        return sb.toString();
    }

    public void exportHistogramData(BufferedImage original, BufferedImage encrypted, String filePrefix) throws IOException {
        int[] origHist = new int[256];
        int[] encHist = new int[256];

        for (int y = 0; y < original.getHeight(); y++) {
            for (int x = 0; x < original.getWidth(); x++) {
                origHist[gray(original.getRGB(x, y))]++;
            }
        }
        for (int y = 0; y < encrypted.getHeight(); y++) {
            for (int x = 0; x < encrypted.getWidth(); x++) {
                encHist[gray(encrypted.getRGB(x, y))]++;
            }
        }

        try (FileWriter writer = new FileWriter(filePrefix + "_histogram.csv")) {
            writer.write("GrayLevel,OriginalCount,EncryptedCount\n");
            for (int i = 0; i < 256; i++) {
                writer.write(i + "," + origHist[i] + "," + encHist[i] + "\n");
            }
        }
        log.info("直方图数据已导出至 {}", filePrefix + "_histogram.csv");
    }

    public void exportByteHistogram(byte[] plainData, byte[] cipherData, String filePrefix) throws IOException {
        int[] plainFreq = new int[256];
        int[] cipherFreq = new int[256];
        for (byte b : plainData) plainFreq[b & 0xFF]++;
        for (byte b : cipherData) cipherFreq[b & 0xFF]++;

        try (FileWriter writer = new FileWriter(filePrefix + "_byte_hist.csv")) {
            writer.write("ByteValue,PlainCount,CipherCount\n");
            for (int i = 0; i < 256; i++) {
                writer.write(i + "," + plainFreq[i] + "," + cipherFreq[i] + "\n");
            }
        }
    }

    public void saveTestReport(TestReport report, String filePath) throws IOException {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(generateTestReport(report));
        }
        log.info("测试报告已保存到: {}", filePath);
    }

    private static final class InMemoryMultipartFile implements MultipartFile {
        private final String originalFilename;
        private final byte[] content;

        private InMemoryMultipartFile(String originalFilename, byte[] content) {
            this.originalFilename = originalFilename;
            this.content = content;
        }

        @Override
        public String getName() {
            return "file";
        }

        @Override
        public String getOriginalFilename() {
            return originalFilename;
        }

        @Override
        public String getContentType() {
            return null;
        }

        @Override
        public boolean isEmpty() {
            return content.length == 0;
        }

        @Override
        public long getSize() {
            return content.length;
        }

        @Override
        public byte[] getBytes() {
            return content;
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(content);
        }

        @Override
        public void transferTo(java.io.File dest) {
            throw new UnsupportedOperationException("Not required for in-memory multipart file");
        }
    }
}
