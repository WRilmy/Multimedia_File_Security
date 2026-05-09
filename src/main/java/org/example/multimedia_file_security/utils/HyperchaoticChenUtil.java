package org.example.multimedia_file_security.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.fullEncrypt;
import static org.example.multimedia_file_security.utils.Sm4EncryptionUtil.fullDecrypt;

/**
 * 基于四维超混沌 Chen 系统的密钥流工具。
 * 该工具不接入现有上传下载链路，只提供独立的密钥流生成和 XOR 加解密能力，便于单独测试效果。
 */
public final class HyperchaoticChenUtil {

    private static final int DIGEST_BLOCK_SIZE = 32;

    private HyperchaoticChenUtil() {
    }

    /**
     * 四维超混沌 Chen 参数。
     * 使用者可以只改初值，也可以整体调整参数。
     */
    public static final class ChenKeyStreamConfig {
        private final double a;
        private final double b;
        private final double c;
        private final double d;
        private final double r;
        private final double x0;
        private final double y0;
        private final double z0;
        private final double w0;
        private final double stepSize;
        private final int warmupIterations;
        private final int samplingStride;

        public ChenKeyStreamConfig(double a, double b, double c, double d, double r,
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
                    35.0, 3.0, 12.0, 7.0, 0.5,
                    0.1179, 0.2318, 0.3361, 0.4517,
                    0.001,
                    4000,
                    3
            );
        }

        /**
         * 高李雅普诺夫指数配置
         * 优化参数以获得更高的混沌特性和李雅普诺夫指数
         */
        public static ChenKeyStreamConfig highLyapunovConfig() {
            return new ChenKeyStreamConfig(
                    38.0, 2.8, 14.0, 8.0, 0.6,  // 调整主要参数以增强混沌
                    0.1234, 0.5678, 0.9012, 0.3456,  // 更精细的初始值
                    0.0008,  // 更小的步长提高精度
                    5000,    // 增加预热迭代次数
                    2        // 减小采样步长以获取更多状态点
            );
        }

        public double getA() {
            return a;
        }

        public double getB() {
            return b;
        }

        public double getC() {
            return c;
        }

        public double getD() {
            return d;
        }

        public double getR() {
            return r;
        }

        public double getX0() {
            return x0;
        }

        public double getY0() {
            return y0;
        }

        public double getZ0() {
            return z0;
        }

        public double getW0() {
            return w0;
        }

        public double getStepSize() {
            return stepSize;
        }

        public int getWarmupIterations() {
            return warmupIterations;
        }

        public int getSamplingStride() {
            return samplingStride;
        }
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

    /**
     * 生成指定长度的密钥流。
     * 先用超混沌 Chen 系统演化状态，再把状态采样结果做 SHA-256 白化，降低直接量化带来的模式残留。
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
     * 对整个字节数组做 XOR 加密。
     */
    public static byte[] xorEncrypt(byte[] plainData, ChenKeyStreamConfig config) {
        return xorWithKeyStream(plainData, config);
    }

    /**
     * XOR 模式下解密与加密相同。
     */
    public static byte[] xorDecrypt(byte[] encryptedData, ChenKeyStreamConfig config) {
        return xorWithKeyStream(encryptedData, config);
    }

    /**
     * 保留图片头部，仅对内容区做 XOR。
     * 适合你测试“保留部分格式特征，但提升内容区扰动强度”的效果。
     */
    public static byte[] xorEncryptImagePayload(byte[] imageData, String filename, ChenKeyStreamConfig config) {
        return xorImagePayload(imageData, filename, config);
    }

    /**
     * XOR 模式下解密与加密相同。
     */
    public static byte[] xorDecryptImagePayload(byte[] encryptedImageData, String filename,
                                                ChenKeyStreamConfig config) {
        return xorImagePayload(encryptedImageData, filename, config);
    }

    /**
     * 混合加密：先混沌加密，再SM4加密
     * 加密流程：原始数据 -> 超混沌XOR加密 -> SM4-XOR加密 -> 密文
     */
    public static byte[] hybridEncrypt(byte[] plainData, ChenKeyStreamConfig chenConfig, String sm4KeyBase64) {
        if (plainData == null) {
            throw new IllegalArgumentException("plainData must not be null");
        }
        try {
            byte[] chaosEncrypted = xorWithKeyStream(plainData, chenConfig);
            return fullEncrypt(chaosEncrypted, sm4KeyBase64);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hybrid encrypt", e);
        }
    }

    /**
     * 混合解密：先SM4解密，再混沌解密
     * 解密流程：密文 -> SM4-XOR解密 -> 超混沌XOR解密 -> 原始数据
     */
    public static byte[] hybridDecrypt(byte[] encryptedData, ChenKeyStreamConfig chenConfig, String sm4KeyBase64) {
        if (encryptedData == null) {
            throw new IllegalArgumentException("encryptedData must not be null");
        }
        try {
            byte[] chaosDecrypted = fullDecrypt(encryptedData, sm4KeyBase64);
            return xorWithKeyStream(chaosDecrypted, chenConfig);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hybrid decrypt", e);
        }
    }

    /**
     * 混合加密（仅内容区）：先混沌加密内容区，再SM4加密
     * 保留文件头，仅对内容区进行混合加密
     */
    public static byte[] hybridEncryptPayload(byte[] imageData, String filename, 
                                              ChenKeyStreamConfig chenConfig, String sm4KeyBase64) {
        if (imageData == null) {
            throw new IllegalArgumentException("imageData must not be null");
        }
        try {
            int headerSize = detectHeaderSize(filename, imageData);
            byte[] payload = Arrays.copyOfRange(imageData, headerSize, imageData.length);
            byte[] chaosEncrypted = xorWithKeyStream(payload, chenConfig);
            byte[] hybridEncrypted = fullEncrypt(chaosEncrypted, sm4KeyBase64);
            
            // 创建足够大的新数组来容纳文件头和加密后的内容
            byte[] result = new byte[headerSize + hybridEncrypted.length];
            // 复制文件头
            System.arraycopy(imageData, 0, result, 0, headerSize);
            // 复制加密后的内容
            System.arraycopy(hybridEncrypted, 0, result, headerSize, hybridEncrypted.length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Failed to hybrid encrypt payload", e);
        }
    }

    /**
     * 混合解密（仅内容区）：先SM4解密内容区，再混沌解密
     */
    public static byte[] hybridDecryptPayload(byte[] encryptedImageData, String filename,
                                              ChenKeyStreamConfig chenConfig, String sm4KeyBase64) {
        if (encryptedImageData == null) {
            throw new IllegalArgumentException("encryptedImageData must not be null");
        }
        try {
            int headerSize = detectHeaderSize(filename, encryptedImageData);
            byte[] encryptedPayload = Arrays.copyOfRange(encryptedImageData, headerSize, encryptedImageData.length);
            byte[] chaosDecrypted = fullDecrypt(encryptedPayload, sm4KeyBase64);
            byte[] hybridDecrypted = xorWithKeyStream(chaosDecrypted, chenConfig);
            
            // 创建足够大的新数组来容纳文件头和解密后的内容
            byte[] result = new byte[headerSize + hybridDecrypted.length];
            // 复制文件头
            System.arraycopy(encryptedImageData, 0, result, 0, headerSize);
            // 复制解密后的内容
            System.arraycopy(hybridDecrypted, 0, result, headerSize, hybridDecrypted.length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Failed to hybrid decrypt payload", e);
        }
    }

    /**
     * 允许外部直接指定保留头长度。
     */
    public static byte[] xorWithReservedHeader(byte[] data, int headerSize, ChenKeyStreamConfig config) {
        if (data == null) {
            throw new IllegalArgumentException("data must not be null");
        }
        if (headerSize < 0 || headerSize > data.length) {
            throw new IllegalArgumentException("headerSize is out of range");
        }

        byte[] result = Arrays.copyOf(data, data.length);
        byte[] payload = Arrays.copyOfRange(data, headerSize, data.length);
        byte[] encryptedPayload = xorWithKeyStream(payload, config);
        System.arraycopy(encryptedPayload, 0, result, headerSize, encryptedPayload.length);
        return result;
    }

    private static byte[] xorImagePayload(byte[] imageData, String filename, ChenKeyStreamConfig config) {
        if (imageData == null) {
            throw new IllegalArgumentException("imageData must not be null");
        }
        int headerSize = detectHeaderSize(filename, imageData);
        return xorWithReservedHeader(imageData, headerSize, config);
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
     * 四维超混沌 Chen 系统：
     * dx/dt = a(y - x) + w
     * dy/dt = d*x - x*z + c*y
     * dz/dt = x*y - b*z
     * dw/dt = x*z + r*w
     */
    private static double[] derivative(State state, ChenKeyStreamConfig config) {
        double dx = config.getA() * (state.y - state.x) + state.w;
        double dy = config.getD() * state.x - state.x * state.z + config.getC() * state.y;
        double dz = state.x * state.y - config.getB() * state.z;
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
     * 计算超混沌 Chen 系统的雅可比矩阵。
     * 雅可比矩阵用于线性化扰动方程，是计算李雅普诺夫指数的基础。
     */
    private static double[][] jacobian(State state, ChenKeyStreamConfig config) {
        double a = config.getA();
        double b = config.getB();
        double c = config.getC();
        double d = config.getD();
        double r = config.getR();
        
        return new double[][]{  
            {-a, a, 0, 1},            // dx/dx, dx/dy, dx/dz, dx/dw
            {d - state.z, c, -state.x, 0},  // dy/dx, dy/dy, dy/dz, dy/dw
            {state.y, state.x, -b, 0},      // dz/dx, dz/dy, dz/dz, dz/dw
            {state.z, 0, state.x, r}        // dw/dx, dw/dy, dw/dz, dw/dw
        };
    }

    /**
     * 使用四阶龙格-库塔方法积分扰动向量的线性化方程。
     * 线性化方程：d(δv)/dt = J(t) · δv，其中 J(t) 是雅可比矩阵。
     */
    private static double[] integratePerturbation(double[] perturbation, State state, 
                                                ChenKeyStreamConfig config, double h) {
        double[][] J = jacobian(state, config);
        
        // k1 = f(y)
        double[] k1 = multiplyJacobian(J, perturbation);
        
        // k2 = f(y + h/2 * k1)
        double[] y2 = addVectors(perturbation, scaleVector(k1, h / 2.0));
        double[] k2 = multiplyJacobian(J, y2);
        
        // k3 = f(y + h/2 * k2)
        double[] y3 = addVectors(perturbation, scaleVector(k2, h / 2.0));
        double[] k3 = multiplyJacobian(J, y3);
        
        // k4 = f(y + h * k3)
        double[] y4 = addVectors(perturbation, scaleVector(k3, h));
        double[] k4 = multiplyJacobian(J, y4);
        
        // 组合结果：y = y + h/6 * (k1 + 2*k2 + 2*k3 + k4)
        double[] result = new double[4];
        for (int i = 0; i < 4; i++) {
            result[i] = perturbation[i] + h / 6.0 * (k1[i] + 2 * k2[i] + 2 * k3[i] + k4[i]);
        }
        return result;
    }

    /**
     * 雅可比矩阵与向量的乘法。
     */
    private static double[] multiplyJacobian(double[][] J, double[] v) {
        double[] result = new double[4];
        for (int i = 0; i < 4; i++) {
            result[i] = J[i][0] * v[0] + J[i][1] * v[1] + J[i][2] * v[2] + J[i][3] * v[3];
        }
        return result;
    }

    /**
     * 向量加法。
     */
    private static double[] addVectors(double[] a, double[] b) {
        double[] result = new double[4];
        for (int i = 0; i < 4; i++) {
            result[i] = a[i] + b[i];
        }
        return result;
    }

    /**
     * 向量缩放。
     */
    private static double[] scaleVector(double[] v, double factor) {
        double[] result = new double[4];
        for (int i = 0; i < 4; i++) {
            result[i] = v[i] * factor;
        }
        return result;
    }

    /**
     * Gram-Schmidt 正交化。
     * 对扰动向量组进行正交化，避免数值误差累积。
     */
    private static double[] gramSchmidtWithNorms(double[][] vectors) {
        double[] norms = new double[4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < i; j++) {
                double dot = dotProduct(vectors[i], vectors[j]);
                for (int k = 0; k < 4; k++) {
                    vectors[i][k] -= dot * vectors[j][k];
                }
            }
            norms[i] = vectorNorm(vectors[i]);
            if (norms[i] > 1e-10) {
                for (int k = 0; k < 4; k++) {
                    vectors[i][k] /= norms[i];
                }
            }
        }
        return norms;
    }

    /**
     * 计算向量点积。
     */
    private static double dotProduct(double[] a, double[] b) {
        double result = 0;
        for (int i = 0; i < 4; i++) {
            result += a[i] * b[i];
        }
        return result;
    }

    /**
     * 计算向量范数。
     */
    private static double vectorNorm(double[] v) {
        double sum = 0;
        for (double x : v) {
            sum += x * x;
        }
        return Math.sqrt(sum);
    }

    private static int detectHeaderSize(String filename, byte[] data) {
        if (filename == null) {
            return detectHeaderSizeBySignature(data);
        }

        String lower = filename.toLowerCase();
        if (lower.endsWith(".bmp")) {
            return 54;
        }
        if (lower.endsWith(".png")) {
            return 8;
        }
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return 2;
        }
        if (lower.endsWith(".gif")) {
            return 6;
        }
        if (lower.endsWith(".webp")) {
            return 12;
        }
        return detectHeaderSizeBySignature(data);
    }

    private static int detectHeaderSizeBySignature(byte[] data) {
        if (data == null || data.length < 4) {
            return 0;
        }

        if (data.length >= 8 &&
                (data[0] & 0xFF) == 0x89 &&
                data[1] == 0x50 &&
                data[2] == 0x4E &&
                data[3] == 0x47) {
            return 8;
        }

        if (data[0] == 0x42 && data[1] == 0x4D) {
            return 54;
        }

        if ((data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xD8) {
            return 2;
        }

        if (data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46) {
            return 6;
        }

        if (data.length >= 12 &&
                data[0] == 0x52 &&
                data[1] == 0x49 &&
                data[2] == 0x46 &&
                data[8] == 0x57 &&
                data[9] == 0x45 &&
                data[10] == 0x42 &&
                data[11] == 0x50) {
            return 12;
        }

        return 0;
    }

    /**
     * 便于调试和重复实验：对默认参数只替换初值。
     */
    public static ChenKeyStreamConfig withInitialState(double x0, double y0, double z0, double w0) {
        ChenKeyStreamConfig base = ChenKeyStreamConfig.defaultConfig();
        return new ChenKeyStreamConfig(
                base.getA(), base.getB(), base.getC(), base.getD(), base.getR(),
                x0, y0, z0, w0,
                base.getStepSize(),
                base.getWarmupIterations(),
                base.getSamplingStride()
        );
    }

    public static int getDigestBlockSize() {
        return DIGEST_BLOCK_SIZE;
    }

    /**
     * 计算超混沌 Chen 系统的李雅普诺夫指数。
     * 使用雅可比矩阵法，通过跟踪扰动向量的指数级分离速率来计算。
     * 
     * @param config 系统配置
     * @param warmupSteps 预热步数（让系统进入吸引子）
     * @param integrationSteps 积分步数（用于计算指数）
     * @param orthogonalizationInterval 正交化间隔（避免数值误差累积）
     * @return 李雅普诺夫指数数组（按从大到小排序）
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
        
        // 1. 预热：让系统进入吸引子
        for (int i = 0; i < warmupSteps; i++) {
            state = rk4Next(state, config);
        }

        // 2. 初始化扰动向量（标准基向量）
        double[][] perturbations = new double[4][4];
        for (int i = 0; i < 4; i++) {
            perturbations[i][i] = 1.0;
        }

        // 3. 初始化李雅普诺夫指数累积器
        double[] lyapunovExponents = new double[4];
        int stepsSinceOrthogonalization = 0;

        // 4. 积分并累积指数
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

        // 5. 时间平均
        double totalTime = integrationSteps * h;
        for (int i = 0; i < 4; i++) {
            lyapunovExponents[i] /= totalTime;
        }

        // 6. 按从大到小排序
        Arrays.sort(lyapunovExponents);
        reverseArray(lyapunovExponents);

        return lyapunovExponents;
    }

    /**
     * 反转数组。
     */
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

    /**
     * 计算默认配置下的李雅普诺夫指数。
     * 提供合理的默认参数，方便快速评估系统混沌特性。
     * 
     * @return 李雅普诺夫指数数组（按从大到小排序）
     */
    public static double[] calculateLyapunovExponents() {
        return calculateLyapunovExponents(
                ChenKeyStreamConfig.defaultConfig(),
                10000,  // 预热步数
                50000,  // 积分步数
                100     // 正交化间隔
        );
    }
}
