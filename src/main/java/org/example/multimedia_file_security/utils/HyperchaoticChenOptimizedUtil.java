package org.example.multimedia_file_security.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.fullEncrypt;
import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.fullDecrypt;

/**
 * 改进版四维超混沌 Chen 系统：在第三个方程添加 ew 项
 * 微分方程组：
 * dx/dt = a(y - x) + w
 * dy/dt = d*x - x*z + c*y
 * dz/dt = x*y - b*z + e*w  ← 添加了 ew 项
 * dw/dt = x*z + r*w
 */
public final class HyperchaoticChenOptimizedUtil {

    private static final int DIGEST_BLOCK_SIZE = 32;

    private HyperchaoticChenOptimizedUtil() {
    }

    /**
     * 改进版四维超混沌 Chen 参数。
     * 新增参数 e，控制 z 和 w 之间的耦合强度。
     */
    public static final class ChenKeyStreamConfig {
        private final double a;
        private final double b;
        private final double c;
        private final double d;
        private final double e;  // 新增参数
        private final double r;
        private final double x0;
        private final double y0;
        private final double z0;
        private final double w0;
        private final double stepSize;
        private final int warmupIterations;
        private final int samplingStride;

        public ChenKeyStreamConfig(double a, double b, double c, double d, double e, double r,
                                   double x0, double y0, double z0, double w0,
                                   double stepSize, int warmupIterations, int samplingStride) {
            if (stepSize <= 0) {
                throw new IllegalArgumentException("stepSize must be > 0");
            }
            if (warmupIterations < 0) {
                throw new IllegalArgumentException("warmupIterations must be >= 0");
            }
            if (samplingStride <= 0) {
                throw new IllegalArgumentException("samplingStride must be > 0");
            }

            this.a = a;
            this.b = b;
            this.c = c;
            this.d = d;
            this.e = e;  // 新增参数
            this.r = r;
            this.x0 = x0;
            this.y0 = y0;
            this.z0 = z0;
            this.w0 = w0;
            this.stepSize = stepSize;
            this.warmupIterations = warmupIterations;
            this.samplingStride = samplingStride;
        }

        public static ChenKeyStreamConfig defaultConfig() {
            return new ChenKeyStreamConfig(
                    35.0, 3.0, 25.0, 10.0, 3.0, 0.5,
                    0.1179, 0.2318, 0.3361, 0.4517,
                    0.001,
                    4000,
                    3
            );
        }

        public static ChenKeyStreamConfig highCouplingConfig() {
            return new ChenKeyStreamConfig(
                    35.0, 3.0, 25.0, 15.0, 3.0, 0.8,
                    0.1179, 0.2318, 0.3361, 0.4517,
                    0.0008,
                    5000,
                    2
            );
        }

        public static ChenKeyStreamConfig negativeFeedbackConfig() {
            return new ChenKeyStreamConfig(
                    35.0, 3.0, 25.0, 10.0, -0.5, 0.5,
                    0.1179, 0.2318, 0.3361, 0.4517,
                    0.001,
                    4000,
                    3
            );
        }

        public double getA() { return a; }
        public double getB() { return b; }
        public double getC() { return c; }
        public double getD() { return d; }
        public double getE() { return e; }  // 新增 getter
        public double getR() { return r; }
        public double getX0() { return x0; }
        public double getY0() { return y0; }
        public double getZ0() { return z0; }
        public double getW0() { return w0; }
        public double getStepSize() { return stepSize; }
        public int getWarmupIterations() { return warmupIterations; }
        public int getSamplingStride() { return samplingStride; }
    }

    private static final class State {
        private final double x;
        private final double y;
        private final double z;
        private final double w;

        private State(double x, double y, double z, double w) {
            this.x = x;
            this.y = y;
            this.z = z;
            this.w = w;
        }
    }

    public static final class KeyStreamGenerator {
        private final ChenKeyStreamConfig config;
        private final MessageDigest digest;
        private State state;
        private long blockCounter;
        private byte[] currentBlock;
        private int blockOffset;

        public KeyStreamGenerator(ChenKeyStreamConfig config) {
            if (config == null) {
                throw new IllegalArgumentException("config must not be null");
            }
            try {
                this.config = config;
                this.digest = MessageDigest.getInstance("SHA-256");
                this.state = new State(config.getX0(), config.getY0(), config.getZ0(), config.getW0());
                this.blockCounter = 0L;
                this.currentBlock = new byte[0];
                this.blockOffset = 0;

                for (int i = 0; i < config.getWarmupIterations(); i++) {
                    this.state = rk4Next(this.state, config);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize optimized Chen key stream generator", e);
            }
        }

        public byte[] nextBytes(int length) {
            if (length < 0) {
                throw new IllegalArgumentException("length must be >= 0");
            }
            byte[] output = new byte[length];
            fill(output, 0, length);
            return output;
        }

        public void xorInPlace(byte[] data, int offset, int length) {
            if (data == null) {
                throw new IllegalArgumentException("data must not be null");
            }
            if (offset < 0 || length < 0 || offset + length > data.length) {
                throw new IllegalArgumentException("offset/length is out of range");
            }
            for (int i = 0; i < length; i++) {
                data[offset + i] ^= nextByte();
            }
        }

        private void fill(byte[] target, int offset, int length) {
            if (offset < 0 || length < 0 || offset + length > target.length) {
                throw new IllegalArgumentException("offset/length is out of range");
            }
            for (int i = 0; i < length; i++) {
                target[offset + i] = nextByte();
            }
        }

        private byte nextByte() {
            if (blockOffset >= currentBlock.length) {
                for (int i = 0; i < config.getSamplingStride(); i++) {
                    state = rk4Next(state, config);
                }
                currentBlock = whitenState(state, blockCounter, digest);
                blockCounter++;
                blockOffset = 0;
            }
            return currentBlock[blockOffset++];
        }
    }

    /**
     * 生成指定长度的密钥流
     */
    public static byte[] generateKeyStream(int length, ChenKeyStreamConfig config) {
        if (length < 0) {
            throw new IllegalArgumentException("length must be >= 0");
        }
        if (length == 0) {
            return new byte[0];
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyStream = new byte[length];
            State state = new State(config.getX0(), config.getY0(), config.getZ0(), config.getW0());

            for (int i = 0; i < config.getWarmupIterations(); i++) {
                state = rk4Next(state, config);
            }

            int offset = 0;
            long blockCounter = 0L;
            while (offset < length) {
                for (int i = 0; i < config.getSamplingStride(); i++) {
                    state = rk4Next(state, config);
                }

                byte[] block = whitenState(state, blockCounter, digest);
                int copyLength = Math.min(block.length, length - offset);
                System.arraycopy(block, 0, keyStream, offset, copyLength);
                offset += copyLength;
                blockCounter++;
            }

            return keyStream;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate hyperchaotic Chen key stream", e);
        }
    }

    /**
     * 对整个字节数组做 XOR 加密
     */
    public static byte[] xorEncrypt(byte[] plainData, ChenKeyStreamConfig config) {
        return xorWithKeyStream(plainData, config);
    }

    /**
     * XOR 模式下解密与加密相同
     */
    public static byte[] xorDecrypt(byte[] encryptedData, ChenKeyStreamConfig config) {
        return xorWithKeyStream(encryptedData, config);
    }

    /**
     * 混合加密：先改进版超混沌Chen加密，再SM4加密
     * 加密流程：原始数据 -> 超混沌XOR加密 -> SM4加密 -> 密文
     */
    public static byte[] hybridEncrypt(byte[] plainData, ChenKeyStreamConfig chenConfig, String sm4KeyBase64) {
        if (plainData == null) {
            throw new IllegalArgumentException("plainData must not be null");
        }
        try {
            byte[] chaosEncrypted = xorWithKeyStream(plainData, chenConfig);
            return fullEncrypt(chaosEncrypted, sm4KeyBase64);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hybrid encrypt with optimized Chen", e);
        }
    }

    /**
     * 混合解密：先SM4解密，再改进版超混沌Chen解密
     * 解密流程：密文 -> SM4解密 -> 超混沌XOR解密 -> 原始数据
     */
    public static byte[] hybridDecrypt(byte[] encryptedData, ChenKeyStreamConfig chenConfig, String sm4KeyBase64) {
        if (encryptedData == null) {
            throw new IllegalArgumentException("encryptedData must not be null");
        }
        try {
            byte[] chaosDecrypted = fullDecrypt(encryptedData, sm4KeyBase64);
            return xorWithKeyStream(chaosDecrypted, chenConfig);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hybrid decrypt with optimized Chen", e);
        }
    }

    public static byte[] xorWithKeyStream(byte[] input, ChenKeyStreamConfig config) {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }

        byte[] keyStream = generateKeyStream(input.length, config);
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] ^ keyStream[i]);
        }
        return output;
    }

    private static byte[] whitenState(State state, long blockCounter, MessageDigest digest) {
        ByteBuffer buffer = ByteBuffer.allocate(8 * 5).order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(Double.doubleToLongBits(state.x));
        buffer.putLong(Double.doubleToLongBits(state.y));
        buffer.putLong(Double.doubleToLongBits(state.z));
        buffer.putLong(Double.doubleToLongBits(state.w));
        buffer.putLong(blockCounter);
        return digest.digest(buffer.array());
    }

    /**
     * 四阶龙格-库塔法求解微分方程
     */
    private static State rk4Next(State current, ChenKeyStreamConfig config) {
        double h = config.getStepSize();

        double[] k1 = derivative(current, config);
        double[] k2 = derivative(add(current, k1, h / 2.0), config);
        double[] k3 = derivative(add(current, k2, h / 2.0), config);
        double[] k4 = derivative(add(current, k3, h), config);

        double x = current.x + h * (k1[0] + 2 * k2[0] + 2 * k3[0] + k4[0]) / 6.0;
        double y = current.y + h * (k1[1] + 2 * k2[1] + 2 * k3[1] + k4[1]) / 6.0;
        double z = current.z + h * (k1[2] + 2 * k2[2] + 2 * k3[2] + k4[2]) / 6.0;
        double w = current.w + h * (k1[3] + 2 * k2[3] + 2 * k3[3] + k4[3]) / 6.0;

        return new State(x, y, z, w);
    }

    /**
     * 改进版四维超混沌 Chen 系统微分方程：
     * dx/dt = a(y - x) + w
     * dy/dt = d*x - x*z + c*y
     * dz/dt = x*y - b*z + e*w  ← 新增 e*w 项
     * dw/dt = x*z + r*w
     */
    private static double[] derivative(State state, ChenKeyStreamConfig config) {
        double dx = config.getA() * (state.y - state.x) + state.w;
        double dy = config.getD() * state.x - state.x * state.z + config.getC() * state.y;
        double dz = state.x * state.y - config.getB() * state.z + config.getE() * state.w;  // 添加 e*w
        double dw = state.x * state.z + config.getR() * state.w;
        return new double[]{dx, dy, dz, dw};
    }

    private static State add(State state, double[] delta, double factor) {
        return new State(
                state.x + delta[0] * factor,
                state.y + delta[1] * factor,
                state.z + delta[2] * factor,
                state.w + delta[3] * factor
        );
    }

    /**
     * 计算雅可比矩阵
     */
    private static double[][] jacobian(State state, ChenKeyStreamConfig config) {
        double a = config.getA();
        double b = config.getB();
        double c = config.getC();
        double d = config.getD();
        double e = config.getE();  // 新增参数
        double r = config.getR();

        return new double[][]{
                {-a, a, 0, 1},                     // dx/dx, dx/dy, dx/dz, dx/dw
                {d - state.z, c, -state.x, 0},    // dy/dx, dy/dy, dy/dz, dy/dw
                {state.y, state.x, -b, e},        // dz/dx, dz/dy, dz/dz, dz/dw ← 第三行第四列变为 e
                {state.z, 0, state.x, r}          // dw/dx, dw/dy, dw/dz, dw/dw
        };
    }

    /**
     * 计算李雅普诺夫指数
     */
    public static double[] calculateLyapunovExponents(ChenKeyStreamConfig config,
                                                      int warmupSteps,
                                                      int integrationSteps,
                                                      int orthogonalizationInterval) {
        if (warmupSteps < 0) {
            throw new IllegalArgumentException("warmupSteps must be >= 0");
        }
        if (integrationSteps <= 0) {
            throw new IllegalArgumentException("integrationSteps must be > 0");
        }
        if (orthogonalizationInterval <= 0) {
            throw new IllegalArgumentException("orthogonalizationInterval must be > 0");
        }

        double h = config.getStepSize();
        State state = new State(config.getX0(), config.getY0(), config.getZ0(), config.getW0());

        for (int i = 0; i < warmupSteps; i++) {
            state = rk4Next(state, config);
        }

        double[][] perturbations = new double[4][4];
        for (int i = 0; i < 4; i++) {
            perturbations[i][i] = 1.0;
        }

        double[] lyapunovExponents = new double[4];
        int stepsSinceOrthogonalization = 0;

        for (int i = 0; i < integrationSteps; i++) {
            double[][] J = jacobian(state, config);

            for (int j = 0; j < 4; j++) {
                double[] newPerturbation = new double[4];
                for (int k = 0; k < 4; k++) {
                    for (int l = 0; l < 4; l++) {
                        newPerturbation[k] += J[k][l] * perturbations[j][l];
                    }
                }
                for (int k = 0; k < 4; k++) {
                    perturbations[j][k] += h * newPerturbation[k];
                }
            }

            state = rk4Next(state, config);

            stepsSinceOrthogonalization++;

            if (stepsSinceOrthogonalization >= orthogonalizationInterval) {
                double[] norms = gramSchmidtWithNorms(perturbations);
                for (int j = 0; j < 4; j++) {
                    if (norms[j] > 1e-10) {
                        lyapunovExponents[j] += Math.log(norms[j]);
                    }
                }
                stepsSinceOrthogonalization = 0;
            }
        }

        double totalTime = integrationSteps * h;
        for (int i = 0; i < 4; i++) {
            lyapunovExponents[i] /= totalTime;
        }

        Arrays.sort(lyapunovExponents);
        reverseArray(lyapunovExponents);

        return lyapunovExponents;
    }

    private static double[] gramSchmidtWithNorms(double[][] vectors) {
        double[] norms = new double[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < i; j++) {
                double dot = 0;
                for (int k = 0; k < 4; k++) {
                    dot += vectors[i][k] * vectors[j][k];
                }
                for (int k = 0; k < 4; k++) {
                    vectors[i][k] -= dot * vectors[j][k];
                }
            }
            norms[i] = 0;
            for (int k = 0; k < 4; k++) {
                norms[i] += vectors[i][k] * vectors[i][k];
            }
            norms[i] = Math.sqrt(norms[i]);
            if (norms[i] > 1e-10) {
                for (int k = 0; k < 4; k++) {
                    vectors[i][k] /= norms[i];
                }
            }
        }
        return norms;
    }

    private static void reverseArray(double[] array) {
        int left = 0;
        int right = array.length - 1;
        while (left < right) {
            double temp = array[left];
            array[left] = array[right];
            array[right] = temp;
            left++;
            right--;
        }
    }

    public static double[] calculateLyapunovExponents() {
        return calculateLyapunovExponents(
                ChenKeyStreamConfig.defaultConfig(),
                10000,
                50000,
                100
        );
    }

    /**
     * 便于调试和重复实验：对默认参数只替换初值
     */
    public static ChenKeyStreamConfig withInitialState(double x0, double y0, double z0, double w0) {
        ChenKeyStreamConfig base = ChenKeyStreamConfig.defaultConfig();
        return new ChenKeyStreamConfig(
                base.getA(), base.getB(), base.getC(), base.getD(), base.getE(), base.getR(),
                x0, y0, z0, w0,
                base.getStepSize(),
                base.getWarmupIterations(),
                base.getSamplingStride()
        );
    }

    /**
     * 测试函数
     */
    public static void main(String[] args) {
        System.out.println("=== 改进版四维超混沌Chen系统测试 ===");

        // 测试默认配置
        ChenKeyStreamConfig defaultConfig = ChenKeyStreamConfig.defaultConfig();
        System.out.println("\n1. 默认配置 (e=" + defaultConfig.getE() + "):");

        // 生成密钥流测试
        byte[] keyStream = generateKeyStream(32, defaultConfig);
        System.out.println("生成的32字节密钥流: " + bytesToHex(keyStream));

        // 计算李雅普诺夫指数
        double[] lyapunov = calculateLyapunovExponents(defaultConfig, 10000, 50000, 100);
        System.out.println("李雅普诺夫指数: " + Arrays.toString(lyapunov));

        // 测试高耦合配置
        ChenKeyStreamConfig highCouplingConfig = ChenKeyStreamConfig.highCouplingConfig();
        System.out.println("\n2. 高耦合配置 (e=" + highCouplingConfig.getE() + "):");

        double[] lyapunovHigh = calculateLyapunovExponents(highCouplingConfig, 10000, 50000, 100);
        System.out.println("李雅普诺夫指数: " + Arrays.toString(lyapunovHigh));

        // 测试负反馈配置
        ChenKeyStreamConfig negativeConfig = ChenKeyStreamConfig.negativeFeedbackConfig();
        System.out.println("\n3. 负反馈配置 (e=" + negativeConfig.getE() + "):");

        double[] lyapunovNeg = calculateLyapunovExponents(negativeConfig, 10000, 50000, 100);
        System.out.println("李雅普诺夫指数: " + Arrays.toString(lyapunovNeg));

        // 测试加密解密
        System.out.println("\n4. 加密解密测试:");
        String testData = "Hello, Hyperchaotic Chen System!";
        byte[] plainBytes = testData.getBytes();

        byte[] encrypted = xorEncrypt(plainBytes, defaultConfig);
        byte[] decrypted = xorDecrypt(encrypted, defaultConfig);
        String decryptedText = new String(decrypted);

        System.out.println("原始数据: " + testData);
        System.out.println("加密后hex: " + bytesToHex(encrypted));
        System.out.println("解密后: " + decryptedText);
        System.out.println("加解密结果一致: " + testData.equals(decryptedText));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
