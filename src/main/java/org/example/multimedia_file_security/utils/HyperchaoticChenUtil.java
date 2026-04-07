package org.example.multimedia_file_security.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

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

    private static byte[] xorWithKeyStream(byte[] input, ChenKeyStreamConfig config) {
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
}
