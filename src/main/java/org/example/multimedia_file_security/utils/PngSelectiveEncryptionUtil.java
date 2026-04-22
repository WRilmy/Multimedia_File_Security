package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

@Component
@Slf4j
public class PngSelectiveEncryptionUtil {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final byte[] PNG_SIGNATURE = {
            (byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    private static final String CHUNK_IHDR = "IHDR";
    private static final String CHUNK_PLTE = "PLTE";
    private static final String CHUNK_IDAT = "IDAT";
    private static final String CHUNK_IEND = "IEND";

    // 新 IDAT 块的最大大小（可调整）
    private static final int IDAT_CHUNK_SIZE = 8192;

    @Data
    public static class PngChunk {
        private int length;
        private String type;
        private byte[] data;
        private long crc;
        private int startPos;

        public PngChunk(int length, String type, byte[] data, long crc, int startPos) {
            this.length = length;
            this.type = type;
            this.data = data;
            this.crc = crc;
            this.startPos = startPos;
        }
    }

    @Data
    public static class PngInfo {
        private int width;
        private int height;
        private int bitDepth;
        private int colorType;
        private int compression;
        private int filter;
        private int interlace;
        private List<PngChunk> idatChunks = new ArrayList<>();

        @Override
        public String toString() {
            return String.format("PNG[%dx%d, bitDepth=%d, colorType=%d, IDAT块数=%d]",
                    width, height, bitDepth, colorType, idatChunks.size());
        }
    }

    public static boolean isValidPng(byte[] pngData) {
        if (pngData.length < 8) return false;
        for (int i = 0; i < 8; i++) {
            if (pngData[i] != PNG_SIGNATURE[i]) return false;
        }
        return true;
    }

    public static PngInfo parsePng(byte[] pngData) throws IOException {
        if (!isValidPng(pngData)) {
            throw new IllegalArgumentException("无效的PNG文件");
        }
        PngInfo pngInfo = new PngInfo();
        ByteArrayInputStream bis = new ByteArrayInputStream(pngData);
        DataInputStream dis = new DataInputStream(bis);
        dis.skipBytes(8);
        int position = 8;

        try {
            while (dis.available() > 0) {
                int chunkStart = position;
                int length = dis.readInt();
                position += 4;

                byte[] typeBytes = new byte[4];
                dis.readFully(typeBytes);
                String type = new String(typeBytes, StandardCharsets.US_ASCII);
                position += 4;

                byte[] data = new byte[length];
                dis.readFully(data);
                position += length;

                long crc = Integer.toUnsignedLong(dis.readInt());
                position += 4;

                PngChunk chunk = new PngChunk(length, type, data, crc, chunkStart);

                switch (type) {
                    case CHUNK_IHDR:
                        parseIhdrChunk(data, pngInfo);
                        break;
                    case CHUNK_IDAT:
                        pngInfo.getIdatChunks().add(chunk);
                        break;
                    case CHUNK_IEND:
                        return pngInfo;
                }
            }
        } finally {
            dis.close();
        }
        return pngInfo;
    }

    private static void parseIhdrChunk(byte[] data, PngInfo pngInfo) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        pngInfo.setWidth(dis.readInt());
        pngInfo.setHeight(dis.readInt());
        pngInfo.setBitDepth(dis.readUnsignedByte());
        pngInfo.setColorType(dis.readUnsignedByte());
        pngInfo.setCompression(dis.readUnsignedByte());
        pngInfo.setFilter(dis.readUnsignedByte());
        pngInfo.setInterlace(dis.readUnsignedByte());
    }

    public static byte[] selectiveDecryptPng(byte[] encryptedPngData, String sm4Key) throws Exception {
        return selectiveEncryptPng(encryptedPngData, sm4Key);
    }

    public static byte[] selectiveEncryptPng(byte[] pngData, String sm4Key) throws Exception {
        log.info("开始高级PNG加密");

        if (!isValidPng(pngData)) {
            throw new IllegalArgumentException("无效的PNG文件");
        }

        PngInfo pngInfo = parsePng(pngData);

        if (pngInfo.getIdatChunks().isEmpty()) {
            return Sm4EncryptionUtil.fullEncrypt(pngData, sm4Key);
        }

        // 合并所有IDAT块数据
        ByteArrayOutputStream idatDataStream = new ByteArrayOutputStream();
        for (PngChunk chunk : pngInfo.getIdatChunks()) {
            idatDataStream.write(chunk.getData());
        }
        byte[] compressedData = idatDataStream.toByteArray();

        // 解压IDAT数据
        byte[] pixelData = decompressData(compressedData);
        log.info("解压后像素数据大小: {} bytes", pixelData.length);

        int bytesPerPixel = getBytesPerPixel(pngInfo);
        int rowSize = pngInfo.getWidth() * bytesPerPixel;

        // 使用密钥初始化随机数生成器（保证加解密一致）
        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        int disturbedPixels = 0;
        // 扫描每一行（每行开头有一个过滤字节）
        for (int row = 0; row < pngInfo.getHeight(); row++) {
            int rowStart = row * (rowSize + 1); // +1 为过滤字节
            if (rowStart + 1 >= pixelData.length) break;

            int pixelStart = rowStart + 1; // 跳过过滤字节
            for (int col = 0; col < pngInfo.getWidth(); col++) {
                // 99% 的像素被扰乱（可调整比例）
                if (random.nextDouble() < 0.99) {
                    int pixelPos = pixelStart + col * bytesPerPixel;
                    if (pixelPos + bytesPerPixel <= pixelData.length) {
                        for (int b = 0; b < bytesPerPixel; b++) {
                            pixelData[pixelPos + b] ^= (byte) random.nextInt(256);
                        }
                        disturbedPixels++;
                    }
                }
            }
        }

        log.info("扰乱了 {}/{} 个像素",
                disturbedPixels, pngInfo.getWidth() * pngInfo.getHeight());

        // 重新压缩数据
        byte[] recompressedData = compressData(pixelData);

        // 重建PNG文件
        return rebuildPng(pngData, pngInfo, recompressedData);
    }

    public static byte[] selectiveEncryptPngSm4Ctr(byte[] pngData, String sm4Key) throws Exception {
        return selectiveEncryptPngWithKeyStream(pngData, sm4Key, KeyStreamMode.SM4_CTR);
    }

    public static byte[] selectiveDecryptPngSm4Ctr(byte[] encryptedPngData, String sm4Key) throws Exception {
        return selectiveEncryptPngSm4Ctr(encryptedPngData, sm4Key);
    }

    public static byte[] selectiveEncryptPngHyperchaotic(byte[] pngData, String sm4Key) throws Exception {
        return selectiveEncryptPngWithKeyStream(pngData, sm4Key, KeyStreamMode.HYPERCHAOTIC_CHEN);
    }

    public static byte[] selectiveDecryptPngHyperchaotic(byte[] encryptedPngData, String sm4Key) throws Exception {
        return selectiveEncryptPngHyperchaotic(encryptedPngData, sm4Key);
    }

    private static byte[] selectiveEncryptPngWithKeyStream(byte[] pngData, String sm4Key,
                                                           KeyStreamMode mode) throws Exception {
        if (!isValidPng(pngData)) {
            throw new IllegalArgumentException("无效的PNG文件");
        }

        PngInfo pngInfo = parsePng(pngData);
        if (pngInfo.getIdatChunks().isEmpty()) {
            return Sm4EncryptionUtil.fullEncrypt(pngData, sm4Key);
        }

        ByteArrayOutputStream idatDataStream = new ByteArrayOutputStream();
        for (PngChunk chunk : pngInfo.getIdatChunks()) {
            idatDataStream.write(chunk.getData());
        }

        byte[] pixelData = decompressData(idatDataStream.toByteArray());
        int bytesPerPixel = getBytesPerPixel(pngInfo);
        int rowSize = pngInfo.getWidth() * bytesPerPixel;
        int payloadLength = pngInfo.getWidth() * pngInfo.getHeight() * bytesPerPixel;
        byte[] keyStream = generateExperimentKeyStream(payloadLength, sm4Key, mode);

        int streamIndex = 0;
        int disturbedPixels = 0;
        for (int row = 0; row < pngInfo.getHeight(); row++) {
            int rowStart = row * (rowSize + 1);
            if (rowStart + 1 >= pixelData.length) {
                break;
            }

            int pixelStart = rowStart + 1;
            for (int col = 0; col < pngInfo.getWidth(); col++) {
                int pixelPos = pixelStart + col * bytesPerPixel;
                if (pixelPos + bytesPerPixel <= pixelData.length && streamIndex + bytesPerPixel <= keyStream.length) {
                    for (int b = 0; b < bytesPerPixel; b++) {
                        pixelData[pixelPos + b] ^= keyStream[streamIndex++];
                    }
                    disturbedPixels++;
                }
            }
        }

        log.info("PNG {} 密钥流扰动了 {}/{} 个像素",
                mode.getDisplayName(), disturbedPixels, pngInfo.getWidth() * pngInfo.getHeight());

        byte[] recompressedData = compressData(pixelData);
        return rebuildPng(pngData, pngInfo, recompressedData);
    }

    private static byte[] generateExperimentKeyStream(int length, String sm4Key, KeyStreamMode mode) throws Exception {
        if (mode == KeyStreamMode.SM4_CTR) {
            return generateSm4CtrKeyStream(length, sm4Key);
        }

        HyperchaoticChenUtil.ChenKeyStreamConfig config = deriveChenConfigFromKey(sm4Key);
        return HyperchaoticChenUtil.generateKeyStream(length, config);
    }

    private static byte[] generateSm4CtrKeyStream(int length, String sm4Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        byte[] iv = Arrays.copyOf(sha256(keyBytes, "PNG-SM4-CTR".getBytes(StandardCharsets.UTF_8)), 16);

        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "SM4"), new IvParameterSpec(iv));
        return cipher.update(new byte[length]);
    }

    private static HyperchaoticChenUtil.ChenKeyStreamConfig deriveChenConfigFromKey(String sm4Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(sm4Key);
        byte[] digest = sha256(keyBytes, "PNG-HYPERCHAOTIC-CHEN".getBytes(StandardCharsets.UTF_8));

        double x0 = 0.10 + unsignedFraction(digest, 0) * 0.80;
        double y0 = 0.10 + unsignedFraction(digest, 8) * 0.80;
        double z0 = 0.10 + unsignedFraction(digest, 16) * 0.80;
        double w0 = 0.10 + unsignedFraction(digest, 24) * 0.80;
        return HyperchaoticChenUtil.withInitialState(x0, y0, z0, w0);
    }

    private static byte[] sha256(byte[] first, byte[] second) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(first);
        digest.update(second);
        return digest.digest();
    }

    private static double unsignedFraction(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFFL);
        }
        return (value >>> 1) / (double) Long.MAX_VALUE;
    }

    private enum KeyStreamMode {
        SM4_CTR("SM4-CTR"),
        HYPERCHAOTIC_CHEN("超混沌Chen");

        private final String displayName;

        KeyStreamMode(String displayName) {
            this.displayName = displayName;
        }

        private String getDisplayName() {
            return displayName;
        }
    }

    private static int getBytesPerPixel(PngInfo pngInfo) {
        int colorType = pngInfo.getColorType();
        int bitDepth = pngInfo.getBitDepth();
        int bytesPerChannel = (bitDepth + 7) / 8; // 每个通道占用的字节数（向上取整）

        switch (colorType) {
            case 0:  return bytesPerChannel;                      // 灰度
            case 2:  return 3 * bytesPerChannel;                  // RGB
            case 3:  return 1;                                     // 索引色（每像素1字节索引）
            case 4:  return 2 * bytesPerChannel;                  // 灰度+Alpha
            case 6:  return 4 * bytesPerChannel;                  // RGBA
            default: return 3;                                      // 默认按RGB处理
        }
    }

    public static byte[] decompressData(byte[] compressedData) throws DataFormatException {
        Inflater inflater = new Inflater();
        inflater.setInput(compressedData);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                baos.write(buffer, 0, count);
            }
        } finally {
            inflater.end();
        }
        return baos.toByteArray();
    }

    private static byte[] compressData(byte[] data) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            baos.write(buffer, 0, count);
        }
        deflater.end();
        return baos.toByteArray();
    }

    /**
     * 改进后的 PNG 重建方法
     * @param originalPng 原始 PNG 数据
     * @param pngInfo 解析出的 PNG 信息（包含 IDAT 块列表）
     * @param newIdatData 新的压缩后的 IDAT 数据（完整的压缩流）
     * @return 重建后的 PNG 字节数组
     */
    private static byte[] rebuildPng(byte[] originalPng, PngInfo pngInfo, byte[] newIdatData)
            throws IOException {

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(originalPng));

        // 1. 写入 PNG 签名
        output.write(PNG_SIGNATURE);
        dis.skipBytes(8);

        // 2. 读取所有块，并分类
        List<PngChunk> preIdatChunks = new ArrayList<>();   // 第一个 IDAT 之前的块
        List<PngChunk> postIdatChunks = new ArrayList<>();  // 最后一个 IDAT 之后的块
        List<PngChunk> idatChunks = new ArrayList<>();      // 原始 IDAT 块（仅用于定位）

        boolean idatStarted = false;
        boolean idatEnded = false;

        try {
            while (dis.available() > 0) {
                int length = dis.readInt();
                byte[] typeBytes = new byte[4];
                dis.readFully(typeBytes);
                String type = new String(typeBytes, StandardCharsets.US_ASCII);
                byte[] data = new byte[length];
                dis.readFully(data);
                long crc = Integer.toUnsignedLong(dis.readInt());

                PngChunk chunk = new PngChunk(length, type, data, crc, -1);

                if (CHUNK_IDAT.equals(type)) {
                    if (!idatStarted) {
                        idatStarted = true; // 遇到第一个 IDAT
                    }
                    idatChunks.add(chunk);
                } else {
                    if (!idatStarted) {
                        // 尚未开始 IDAT，属于前置块
                        preIdatChunks.add(chunk);
                    } else {
                        // 已经经过 IDAT 区域，现在遇到非 IDAT，说明 IDAT 结束
                        idatEnded = true;
                        postIdatChunks.add(chunk);
                    }
                }
            }
        } finally {
            dis.close();
        }

        // 3. 写入前置非 IDAT 块
        DataOutputStream dos = new DataOutputStream(output);
        for (PngChunk chunk : preIdatChunks) {
            dos.writeInt(chunk.getLength());
            dos.write(chunk.getType().getBytes(StandardCharsets.US_ASCII));
            dos.write(chunk.getData());
            dos.writeInt((int) chunk.getCrc());
        }

        // 4. 写入新的 IDAT 块序列（将 newIdatData 分块）
        int offset = 0;
        while (offset < newIdatData.length) {
            int chunkSize = Math.min(IDAT_CHUNK_SIZE, newIdatData.length - offset);
            byte[] chunkData = new byte[chunkSize];
            System.arraycopy(newIdatData, offset, chunkData, 0, chunkSize);

            dos.writeInt(chunkSize);                                    // 长度
            dos.write(CHUNK_IDAT.getBytes(StandardCharsets.US_ASCII)); // 类型
            dos.write(chunkData);                                       // 数据
            long crc = calculateCrc(CHUNK_IDAT.getBytes(StandardCharsets.US_ASCII), chunkData);
            dos.writeInt((int) crc);                                    // CRC

            offset += chunkSize;
        }

        // 5. 写入后置非 IDAT 块（包括 IEND）
        for (PngChunk chunk : postIdatChunks) {
            dos.writeInt(chunk.getLength());
            dos.write(chunk.getType().getBytes(StandardCharsets.US_ASCII));
            dos.write(chunk.getData());
            dos.writeInt((int) chunk.getCrc());
        }

        dos.flush();
        return output.toByteArray();
    }

    private static long calculateCrc(byte[] type, byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(type);
        crc.update(data);
        return crc.getValue();
    }
}
