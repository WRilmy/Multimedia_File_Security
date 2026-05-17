package org.example.multimedia_file_security.utils;

import org.apache.commons.math3.complex.Complex;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.special.Gamma;
import org.apache.commons.math3.transform.DftNormalization;
import org.apache.commons.math3.transform.FastFourierTransformer;
import org.apache.commons.math3.transform.TransformType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 为生成的密钥流提供兼容 NIST SP 800-22 的随机性测试。
 */
public final class NistRandomnessTestUtil {

    /**
     * 判断测试项是否通过时使用的显著性水平。
     */
    public static final double ALPHA = 0.01;

    /**
     * 工具类不允许实例化。
     */
    private NistRandomnessTestUtil() {
    }

    /**
     * 对密钥流运行当前配置的 NIST 兼容测试集。
     *
     * @param data 待测试的密钥流字节
     * @return 用于前端展示的总体摘要和各测试项结果
     * @throws IllegalArgumentException 当 {@code data} 为空时抛出
     */
    public static Map<String, Object> runKeyStreamTests(byte[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("key stream must not be empty");
        }

        List<Map<String, Object>> tests = new ArrayList<>();
        tests.add(testMonobit(data));
        tests.add(testRuns(data));
        tests.add(testBlockFrequency(data));
        tests.add(testLongestRunOfOnes(data));
        tests.add(testBinaryMatrixRank(data));
        tests.add(testDiscreteFourierTransform(data));
        tests.add(testSerial(data));
        tests.add(testApproximateEntropy(data));
        tests.add(testCumulativeSums(data));

        int passed = 0;
        for (Map<String, Object> test : tests) {
            if (Boolean.TRUE.equals(test.get("passed"))) {
                passed++;
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalTests", tests.size());
        summary.put("passedTests", passed);
        summary.put("failedTests", tests.size() - passed);
        summary.put("passRate", tests.isEmpty() ? 0 : passed * 100.0 / tests.size());
        summary.put("alpha", ALPHA);
        summary.put("byteLength", data.length);
        summary.put("bitLength", data.length * 8L);
        summary.put("testSuite", "NIST SP 800-22");
        summary.put("implementation", "Java NIST-compatible implementation with Apache Commons Math");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("summary", summary);
        result.put("tests", tests);
        return result;
    }

    /**
     * 测试 0 比特和 1 比特的数量是否接近平衡。
     *
     * @param data 密钥流字节
     * @return 单比特频数测试结果
     */
    private static Map<String, Object> testMonobit(byte[] data) {
        long startTime = System.currentTimeMillis();
        int ones = 0;
        int totalBits = data.length * 8;
        for (byte b : data) {
            ones += Integer.bitCount(b & 0xFF);
        }

        int zeros = totalBits - ones;
        double sObs = Math.abs(ones - zeros) / Math.sqrt(totalBits);
        double pValue = erfc(sObs / Math.sqrt(2.0));

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("ones", ones);
        metrics.put("zeros", zeros);
        metrics.put("sObs", sObs);

        return buildTest("monobit", "NIST monobit frequency test", pValue, metrics, startTime);
    }

    /**
     * 测试 0 和 1 之间的切换次数是否符合随机序列的自然频率。
     *
     * @param data 密钥流字节
     * @return 游程测试结果
     */
    private static Map<String, Object> testRuns(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int n = bits.length;

        double pi = 0;
        for (int bit : bits) {
            pi += bit;
        }
        pi /= n;

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("oneRatio", pi);
        metrics.put("threshold", 2.0 / Math.sqrt(n));

        double tau = 2.0 / Math.sqrt(n);
        if (Math.abs(pi - 0.5) >= tau) {
            return buildTest("runs", "NIST runs test", 0.0, metrics, startTime,
                    "The sequence does not satisfy the runs-test precondition.");
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
        metrics.put("runs", runs);

        return buildTest("runs", "NIST runs test", pValue, metrics, startTime);
    }

    /**
     * 测试每个固定大小分组中的 1 比特比例是否接近 0.5。
     *
     * @param data 密钥流字节
     * @return 分组频数测试结果
     */
    private static Map<String, Object> testBlockFrequency(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int n = bits.length;
        int blockSize = chooseBlockSize(n);
        int blockCount = n / blockSize;

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", n);
        metrics.put("blockSize", blockSize);
        metrics.put("blockCount", blockCount);

        if (blockCount < 8) {
            return buildTest("blockFrequency", "NIST block frequency test", 0.0, metrics, startTime,
                    "Too few complete blocks for a stable block-frequency result.");
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
        metrics.put("chiSquare", chiSquare);

        return buildTest("blockFrequency", "NIST block frequency test", pValue, metrics, startTime);
    }

    /**
     * 测试每个分组中最长连续 1 游程是否符合随机序列的期望分布。
     *
     * @param data 密钥流字节
     * @return 最长连续 1 游程测试结果
     */
    private static Map<String, Object> testLongestRunOfOnes(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int n = bits.length;

        LongestRunConfig config = chooseLongestRunConfig(n);
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", n);
        metrics.put("blockSize", config.blockSize);
        metrics.put("blockCount", config.blockCount);

        if (config.blockCount == 0) {
            return buildTest("longestRunOfOnes", "NIST longest run of ones test", 0.0, metrics, startTime,
                    "The sequence is too short for longest-run testing.");
        }

        int[] observed = new int[config.probabilities.length];
        for (int i = 0; i < config.blockCount; i++) {
            int longest = 0;
            int current = 0;
            int offset = i * config.blockSize;
            for (int j = 0; j < config.blockSize; j++) {
                if (bits[offset + j] == 1) {
                    current++;
                    longest = Math.max(longest, current);
                } else {
                    current = 0;
                }
            }
            observed[longestRunBucket(longest, config.thresholds)]++;
        }

        double chiSquare = 0.0;
        for (int i = 0; i < observed.length; i++) {
            double expected = config.blockCount * config.probabilities[i];
            chiSquare += Math.pow(observed[i] - expected, 2) / expected;
        }

        ChiSquaredDistribution distribution = new ChiSquaredDistribution(observed.length - 1);
        double pValue = 1.0 - distribution.cumulativeProbability(chiSquare);
        metrics.put("chiSquare", chiSquare);
        metrics.put("observedBuckets", observed);

        return buildTest("longestRunOfOnes", "NIST longest run of ones test", pValue, metrics, startTime);
    }

    /**
     * 通过 32x32 二进制矩阵的秩分布测试序列是否存在线性相关。
     *
     * @param data 密钥流字节
     * @return 二进制矩阵秩测试结果
     */
    private static Map<String, Object> testBinaryMatrixRank(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int rows = 32;
        int cols = 32;
        int matrixBits = rows * cols;
        int matrixCount = bits.length / matrixBits;

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", bits.length);
        metrics.put("matrixRows", rows);
        metrics.put("matrixColumns", cols);
        metrics.put("matrixCount", matrixCount);

        if (matrixCount < 8) {
            return buildTest("binaryMatrixRank", "NIST binary matrix rank test", 0.0, metrics, startTime,
                    "Too few 32x32 matrices for a stable rank result.");
        }

        int fullRank = 0;
        int rank31 = 0;
        for (int i = 0; i < matrixCount; i++) {
            int[] matrixRows = new int[rows];
            int bitOffset = i * matrixBits;
            for (int r = 0; r < rows; r++) {
                int value = 0;
                for (int c = 0; c < cols; c++) {
                    value = (value << 1) | bits[bitOffset + r * cols + c];
                }
                matrixRows[r] = value;
            }

            int rank = binaryRank(matrixRows, cols);
            if (rank == 32) {
                fullRank++;
            } else if (rank == 31) {
                rank31++;
            }
        }

        int lowerRank = matrixCount - fullRank - rank31;
        int[] observed = {fullRank, rank31, lowerRank};
        double[] probabilities = {0.2887880950866024, 0.5775761901732048, 0.1336357147401928};

        double chiSquare = 0.0;
        for (int i = 0; i < observed.length; i++) {
            double expected = matrixCount * probabilities[i];
            chiSquare += Math.pow(observed[i] - expected, 2) / expected;
        }

        ChiSquaredDistribution distribution = new ChiSquaredDistribution(2);
        double pValue = 1.0 - distribution.cumulativeProbability(chiSquare);
        metrics.put("fullRankCount", fullRank);
        metrics.put("rank31Count", rank31);
        metrics.put("lowerRankCount", lowerRank);
        metrics.put("chiSquare", chiSquare);

        return buildTest("binaryMatrixRank", "NIST binary matrix rank test", pValue, metrics, startTime);
    }

    /**
     * 测试序列在频域中是否存在明显的周期性模式。
     *
     * @param data 密钥流字节
     * @return 离散傅里叶变换频谱测试结果
     */
    private static Map<String, Object> testDiscreteFourierTransform(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int n = highestPowerOfTwoAtMost(bits.length);

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", bits.length);
        metrics.put("effectiveBitLength", n);

        if (n < 1024) {
            return buildTest("discreteFourierTransform", "NIST discrete Fourier transform test", 0.0, metrics, startTime,
                    "The sequence is too short for spectral testing.");
        }

        double[] sequence = new double[n];
        for (int i = 0; i < n; i++) {
            sequence[i] = bits[i] == 1 ? 1.0 : -1.0;
        }

        FastFourierTransformer transformer = new FastFourierTransformer(DftNormalization.STANDARD);
        Complex[] spectrum = transformer.transform(sequence, TransformType.FORWARD);
        double threshold = Math.sqrt(Math.log(1.0 / 0.05) * n);
        int countBelowThreshold = 0;
        for (int i = 0; i < n / 2; i++) {
            if (spectrum[i].abs() < threshold) {
                countBelowThreshold++;
            }
        }

        double expected = 0.95 * n / 2.0;
        double normalizedDifference = (countBelowThreshold - expected) / Math.sqrt(n * 0.95 * 0.05 / 4.0);
        double pValue = erfc(Math.abs(normalizedDifference) / Math.sqrt(2.0));

        metrics.put("threshold", threshold);
        metrics.put("countBelowThreshold", countBelowThreshold);
        metrics.put("expectedCount", expected);
        metrics.put("normalizedDifference", normalizedDifference);

        return buildTest("discreteFourierTransform", "NIST discrete Fourier transform test", pValue, metrics, startTime);
    }

    /**
     * 测试固定长度的重叠比特模式是否均匀出现。
     *
     * @param data 密钥流字节
     * @return 序列模式测试结果
     */
    private static Map<String, Object> testSerial(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int n = bits.length;
        int patternLength = 3;

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", n);
        metrics.put("patternLength", patternLength);

        if (n < 1024) {
            return buildTest("serial", "NIST serial test", 0.0, metrics, startTime,
                    "The sequence is too short for serial testing.");
        }

        double psiM = serialPsi(bits, patternLength);
        double psiMMinus1 = serialPsi(bits, patternLength - 1);
        double psiMMinus2 = serialPsi(bits, patternLength - 2);
        double delta1 = psiM - psiMMinus1;
        double delta2 = psiM - 2.0 * psiMMinus1 + psiMMinus2;
        double pValue1 = Gamma.regularizedGammaQ(Math.pow(2, patternLength - 1) / 2.0, delta1 / 2.0);
        double pValue2 = Gamma.regularizedGammaQ(Math.pow(2, patternLength - 2) / 2.0, delta2 / 2.0);
        double pValue = Math.min(pValue1, pValue2);

        metrics.put("psiM", psiM);
        metrics.put("psiMMinus1", psiMMinus1);
        metrics.put("psiMMinus2", psiMMinus2);
        metrics.put("delta1", delta1);
        metrics.put("delta2", delta2);
        metrics.put("pValue1", pValue1);
        metrics.put("pValue2", pValue2);

        return buildTest("serial", "NIST serial test", pValue, metrics, startTime);
    }

    /**
     * 测试相邻模式长度的熵是否接近随机序列。
     *
     * @param data 密钥流字节
     * @return 近似熵测试结果
     */
    private static Map<String, Object> testApproximateEntropy(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int n = bits.length;
        int m = 2;

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", n);
        metrics.put("patternLength", m);

        if (n < 1024) {
            return buildTest("approximateEntropy", "NIST approximate entropy test", 0.0, metrics, startTime,
                    "The sequence is too short for approximate-entropy testing.");
        }

        double phiM = approximateEntropyPhi(bits, m);
        double phiMPlus1 = approximateEntropyPhi(bits, m + 1);
        double apEn = phiM - phiMPlus1;
        double chiSquare = 2.0 * n * (Math.log(2) - apEn);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1 << (m - 1));
        double pValue = 1.0 - distribution.cumulativeProbability(chiSquare);

        metrics.put("approximateEntropy", apEn);
        metrics.put("chiSquare", chiSquare);

        return buildTest("approximateEntropy", "NIST approximate entropy test", pValue, metrics, startTime);
    }

    /**
     * 测试比特累计游走是否保持在随机序列的期望偏移范围内。
     *
     * @param data 密钥流字节
     * @return 累加和测试结果
     */
    private static Map<String, Object> testCumulativeSums(byte[] data) {
        long startTime = System.currentTimeMillis();
        int[] bits = toBitArray(data);
        int sum = 0;
        int maxAbs = 0;
        for (int bit : bits) {
            sum += bit == 1 ? 1 : -1;
            maxAbs = Math.max(maxAbs, Math.abs(sum));
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bitLength", bits.length);
        metrics.put("maxAbsoluteExcursion", maxAbs);

        double pValue = cumulativeSumsPValue(bits);
        return buildTest("cumulativeSums", "NIST cumulative sums test", pValue, metrics, startTime);
    }

    /**
     * 构造不带自定义说明的前端标准测试结果对象。
     *
     * @param id 稳定的测试项标识
     * @param name 可读的测试项名称
     * @param pValue 原始 p 值
     * @param metrics 测试项专属指标
     * @param startTime 测试开始时间，单位毫秒
     * @return 标准化后的测试结果
     */
    private static Map<String, Object> buildTest(String id, String name, double pValue,
                                                 Map<String, Object> metrics, long startTime) {
        return buildTest(id, name, pValue, metrics, startTime, null);
    }

    /**
     * 构造前端标准测试结果对象，并对异常 p 值做边界处理。
     *
     * @param id 稳定的测试项标识
     * @param name 可读的测试项名称
     * @param pValue 原始 p 值
     * @param metrics 测试项专属指标
     * @param startTime 测试开始时间，单位毫秒
     * @param detailOverride 可选的自定义说明
     * @return 标准化后的测试结果
     */
    private static Map<String, Object> buildTest(String id, String name, double pValue,
                                                 Map<String, Object> metrics, long startTime,
                                                 String detailOverride) {
        Map<String, Object> result = new LinkedHashMap<>();
        double boundedPValue = Double.isNaN(pValue) ? 0.0 : Math.max(0.0, Math.min(1.0, pValue));
        boolean passed = boundedPValue >= ALPHA;
        result.put("id", id);
        result.put("name", name);
        result.put("passed", passed);
        result.put("pValue", boundedPValue);
        result.put("alpha", ALPHA);
        result.put("metrics", metrics);
        result.put("executionTimeMs", System.currentTimeMillis() - startTime);
        result.put("details", detailOverride != null
                ? detailOverride
                : (passed ? "Passed at alpha = 0.01." : "Failed at alpha = 0.01."));
        return result;
    }

    /**
     * 将字节数组转换为大端顺序的比特数组。
     *
     * @param data 待转换的字节数组
     * @return 只包含 0 和 1 的比特数组
     */
    private static int[] toBitArray(byte[] data) {
        int[] bits = new int[data.length * 8];
        int index = 0;
        for (byte b : data) {
            for (int i = 7; i >= 0; i--) {
                bits[index++] = (b >> i) & 1;
            }
        }
        return bits;
    }

    /**
     * 根据序列长度选择分组频数测试使用的分组大小。
     *
     * @param bitLength 序列比特长度
     * @return 分组大小，单位比特
     */
    private static int chooseBlockSize(int bitLength) {
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

    /**
     * 根据当前序列长度选择 NIST 最长游程测试参数。
     *
     * @param bitLength 序列比特长度
     * @return 最长游程测试配置
     */
    private static LongestRunConfig chooseLongestRunConfig(int bitLength) {
        if (bitLength < 128) {
            return new LongestRunConfig(8, 0, new int[]{1, 2, 3},
                    new double[]{0.2148, 0.3672, 0.2305, 0.1875});
        }
        if (bitLength < 6272) {
            return new LongestRunConfig(8, bitLength / 8, new int[]{1, 2, 3},
                    new double[]{0.2148, 0.3672, 0.2305, 0.1875});
        }
        if (bitLength < 750000) {
            return new LongestRunConfig(128, bitLength / 128, new int[]{4, 5, 6, 7, 8},
                    new double[]{0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124});
        }
        return new LongestRunConfig(10000, bitLength / 10000, new int[]{10, 11, 12, 13, 14, 15},
                new double[]{0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727});
    }

    /**
     * 将观测到的最长游程值映射到配置好的概率分桶中。
     *
     * @param longestRun 观测到的最长连续 1 长度
     * @param thresholds 除最后溢出分桶外各分桶的上界
     * @return 分桶索引
     */
    private static int longestRunBucket(int longestRun, int[] thresholds) {
        for (int i = 0; i < thresholds.length; i++) {
            if (longestRun <= thresholds[i]) {
                return i;
            }
        }
        return thresholds.length;
    }

    /**
     * 计算由整数比特行表示的二进制矩阵秩。
     *
     * @param rows 按比特编码的矩阵行
     * @param columns 矩阵列数
     * @return GF(2) 域上的矩阵秩
     */
    private static int binaryRank(int[] rows, int columns) {
        int rank = 0;
        for (int column = columns - 1; column >= 0 && rank < rows.length; column--) {
            int pivot = -1;
            int mask = 1 << column;
            for (int r = rank; r < rows.length; r++) {
                if ((rows[r] & mask) != 0) {
                    pivot = r;
                    break;
                }
            }
            if (pivot < 0) {
                continue;
            }

            int temp = rows[rank];
            rows[rank] = rows[pivot];
            rows[pivot] = temp;

            for (int r = 0; r < rows.length; r++) {
                if (r != rank && (rows[r] & mask) != 0) {
                    rows[r] ^= rows[rank];
                }
            }
            rank++;
        }
        return rank;
    }

    /**
     * 查找不大于给定值的最大 2 的幂。
     *
     * @param value 正整数上界
     * @return 小于等于 {@code value} 的最大 2 的幂
     */
    private static int highestPowerOfTwoAtMost(int value) {
        int power = 1;
        while (power <= value / 2) {
            power <<= 1;
        }
        return power;
    }

    /**
     * 计算 NIST 序列模式测试使用的 psi 统计量。
     *
     * @param bits 只包含 0 和 1 的比特数组
     * @param patternLength 重叠模式长度
     * @return psi 统计量
     */
    private static double serialPsi(int[] bits, int patternLength) {
        if (patternLength <= 0) {
            return 0.0;
        }
        int n = bits.length;
        int patterns = 1 << patternLength;
        int[] counts = new int[patterns];
        for (int i = 0; i < n; i++) {
            int pattern = 0;
            for (int j = 0; j < patternLength; j++) {
                pattern = (pattern << 1) | bits[(i + j) % n];
            }
            counts[pattern]++;
        }

        double sum = 0.0;
        for (int count : counts) {
            sum += count * count;
        }
        return (sum * patterns / n) - n;
    }

    /**
     * NIST 最长连续 1 游程测试的不可变参数集。
     */
    private static final class LongestRunConfig {
        private final int blockSize;
        private final int blockCount;
        private final int[] thresholds;
        private final double[] probabilities;

        /**
         * 创建最长游程测试配置。
         *
         * @param blockSize 每个测试分组的比特数
         * @param blockCount 当前序列中的完整分组数
         * @param thresholds 分桶上界
         * @param probabilities 每个分桶的期望概率
         */
        private LongestRunConfig(int blockSize, int blockCount, int[] thresholds, double[] probabilities) {
            this.blockSize = blockSize;
            this.blockCount = blockCount;
            this.thresholds = thresholds;
            this.probabilities = probabilities;
        }
    }

    /**
     * 计算近似熵测试使用的 phi 值。
     *
     * @param bits 只包含 0 和 1 的比特数组
     * @param m 模式长度
     * @return 近似熵 phi 值
     */
    private static double approximateEntropyPhi(int[] bits, int m) {
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

    /**
     * 计算正向累加和测试的 p 值。
     *
     * @param bits 只包含 0 和 1 的比特数组
     * @return 累加和测试 p 值
     */
    private static double cumulativeSumsPValue(int[] bits) {
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

    /**
     * 近似计算标准正态分布的累积分布函数。
     *
     * @param x 输入值
     * @return 累积概率
     */
    private static double normalCdf(double x) {
        return 0.5 * (1.0 + erf(x / Math.sqrt(2.0)));
    }

    /**
     * 近似计算互补误差函数。
     *
     * @param x 输入值
     * @return 互补误差函数值
     */
    private static double erfc(double x) {
        return 1 - erf(x);
    }

    /**
     * 近似计算误差函数。
     *
     * @param x 输入值
     * @return 误差函数值
     */
    private static double erf(double x) {
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
}
