package org.example.multimedia_file_security;

import org.example.multimedia_file_security.utils.AviSelectiveEncryptionUtil;
import org.example.multimedia_file_security.utils.HyperchaoticChenUtil;
import org.example.multimedia_file_security.utils.Sm4EncryptionUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AviSelectiveEncryptionTest {

    private static final String SM4_KEY = Base64.getEncoder().encodeToString("test123456789012".getBytes());
    private static final String TEST_AVI_FILE = "test.avi";
    private static byte[] syntheticAvi;

    @BeforeAll
    public static void setUp() throws Exception {
        File testFile = new File(TEST_AVI_FILE);
        if (testFile.exists()) {
            try (FileInputStream fis = new FileInputStream(testFile)) {
                syntheticAvi = new byte[(int) testFile.length()];
                fis.read(syntheticAvi);
            }
        } else {
            syntheticAvi = createMinimalAvi();
        }
    }

    @Test
    public void testAviValidation() throws Exception {
        assertTrue(AviSelectiveEncryptionUtil.isValidAvi(syntheticAvi));
    }

    @Test
    public void testAviParsing() throws Exception {
        AviSelectiveEncryptionUtil.AviInfo info = AviSelectiveEncryptionUtil.parseAvi(syntheticAvi);
        assertTrue(info.getVideoFrameCount() > 0, "AVI should contain video frames");
        System.out.println("AVI解析结果: " + info);
    }

    @Test
    public void testAviSelectiveEncryptionRoundTrip() throws Exception {
        HyperchaoticChenUtil.ChenKeyStreamConfig config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();

        byte[] encryptedData = AviSelectiveEncryptionUtil.selectiveEncryptAvi(syntheticAvi, config);

        assertTrue(AviSelectiveEncryptionUtil.isValidAvi(encryptedData),
                "加密后的AVI应仍为有效格式");

        AviSelectiveEncryptionUtil.AviInfo encryptedInfo = AviSelectiveEncryptionUtil.parseAvi(encryptedData);
        AviSelectiveEncryptionUtil.AviInfo originalInfo = AviSelectiveEncryptionUtil.parseAvi(syntheticAvi);
        assertEquals(originalInfo.getVideoFrameCount(), encryptedInfo.getVideoFrameCount(),
                "加密后视频帧数应不变");

        byte[] decryptedData = AviSelectiveEncryptionUtil.selectiveDecryptAvi(encryptedData, config);

        assertArrayEquals(syntheticAvi, decryptedData,
                "解密后应完全还原原始AVI数据");

        System.out.println("AVI选择性加密闭环测试通过");
    }

    @Test
    public void testAviFullEncryptionRoundTrip() throws Exception {
        HyperchaoticChenUtil.ChenKeyStreamConfig config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();

        byte[] encryptedData = AviSelectiveEncryptionUtil.fullEncryptAvi(syntheticAvi, config);
        byte[] decryptedData = HyperchaoticChenUtil.xorWithKeyStream(encryptedData, config);

        assertArrayEquals(syntheticAvi, decryptedData, "全文件加密解密后应还原原始数据");
        System.out.println("AVI全文件加密闭环测试通过");
    }

    @Test
    public void testAviSelectiveEncryptsVideoFrames() throws Exception {
        HyperchaoticChenUtil.ChenKeyStreamConfig config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();

        byte[] encryptedData = AviSelectiveEncryptionUtil.selectiveEncryptAvi(syntheticAvi, config);

        AviSelectiveEncryptionUtil.AviInfo originalInfo = AviSelectiveEncryptionUtil.parseAvi(syntheticAvi);
        AviSelectiveEncryptionUtil.AviInfo encryptedInfo = AviSelectiveEncryptionUtil.parseAvi(encryptedData);

        boolean videoDataChanged = false;
        for (int i = 0; i < originalInfo.getVideoChunks().size(); i++) {
            byte[] origChunk = originalInfo.getVideoChunks().get(i).getData();
            byte[] encChunk = encryptedInfo.getVideoChunks().get(i).getData();
            if (!java.util.Arrays.equals(origChunk, encChunk)) {
                videoDataChanged = true;
                break;
            }
        }
        assertTrue(videoDataChanged, "加密后至少应有部分视频帧数据被修改");

        boolean audioDataPreserved = true;
        for (int i = 0; i < originalInfo.getAudioChunks().size() && i < encryptedInfo.getAudioChunks().size(); i++) {
            byte[] origChunk = originalInfo.getAudioChunks().get(i).getData();
            byte[] encChunk = encryptedInfo.getAudioChunks().get(i).getData();
            if (!java.util.Arrays.equals(origChunk, encChunk)) {
                audioDataPreserved = false;
                break;
            }
        }
        assertTrue(audioDataPreserved, "加密后音频数据应保持不变");

        System.out.println("AVI选择性加密: 视频帧已加密, 音频帧已保留");
    }

    @Test
    public void testAviDecryptViaSm4EncryptionUtil() throws Exception {
        HyperchaoticChenUtil.ChenKeyStreamConfig config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();

        byte[] encryptedData = AviSelectiveEncryptionUtil.selectiveEncryptAvi(syntheticAvi, config);

        byte[] decryptedData = AviSelectiveEncryptionUtil.decryptAvi(encryptedData, config);

        assertArrayEquals(syntheticAvi, decryptedData, "通过decryptAvi解密后应还原原始数据");
        System.out.println("AVI decryptAvi方法测试通过");
    }

    private static byte[] createMinimalAvi() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        int width = 64;
        int height = 64;
        int frameCount = 3;
        int bytesPerPixel = 3;
        int frameSize = width * height * bytesPerPixel;
        int audioChunkSize = 1024;

        ByteArrayOutputStream moviContent = new ByteArrayOutputStream();
        for (int i = 0; i < frameCount; i++) {
            byte[] chunkId = {'0', '0', 'd', 'c'};
            moviContent.write(chunkId);
            writeLE32(moviContent, frameSize);
            byte[] frameData = new byte[frameSize];
            java.util.Arrays.fill(frameData, (byte) (i * 50 + 10));
            moviContent.write(frameData);
        }

        byte[] audioChunkId = {'0', '1', 'w', 'b'};
        moviContent.write(audioChunkId);
        writeLE32(moviContent, audioChunkSize);
        byte[] audioData = new byte[audioChunkSize];
        java.util.Arrays.fill(audioData, (byte) 0x80);
        moviContent.write(audioData);

        byte[] moviBytes = moviContent.toByteArray();

        ByteArrayOutputStream hdrlContent = new ByteArrayOutputStream();

        byte[] avihChunkId = {'a', 'v', 'i', 'h'};
        hdrlContent.write(avihChunkId);
        writeLE32(hdrlContent, 56);
        byte[] avihData = new byte[56];
        writeLE32(avihData, 0, 33333);
        writeLE32(avihData, 4, 10000);
        writeLE32(avihData, 12, 0x10);
        writeLE32(avihData, 16, frameCount);
        writeLE32(avihData, 20, 0);
        writeLE32(avihData, 24, frameSize);
        writeLE32(avihData, 32, width);
        writeLE32(avihData, 36, height);
        hdrlContent.write(avihData);

        ByteArrayOutputStream strlContent = new ByteArrayOutputStream();

        byte[] strhChunkId = {'s', 't', 'r', 'h'};
        strlContent.write(strhChunkId);
        writeLE32(strlContent, 56);
        byte[] strhData = new byte[56];
        strhData[0] = 'v'; strhData[1] = 'i'; strhData[2] = 'd'; strhData[3] = 's';
        strhData[4] = 'M'; strhData[5] = 'J'; strhData[6] = 'P'; strhData[7] = 'G';
        writeLE32(strhData, 20, 1);
        writeLE32(strhData, 24, frameCount);
        writeLE32(strhData, 32, frameSize);
        writeLE32(strhData, 40, width);
        writeLE32(strhData, 44, height);
        strlContent.write(strhData);

        byte[] strfChunkId = {'s', 't', 'r', 'f'};
        strlContent.write(strfChunkId);
        writeLE32(strlContent, 40);
        byte[] strfData = new byte[40];
        writeLE32(strfData, 0, 40);
        writeLE32(strfData, 4, width);
        writeLE32(strfData, 8, height);
        writeLE16(strfData, 12, 1);
        writeLE16(strfData, 14, 24);
        strfData[16] = 'M'; strfData[17] = 'J'; strfData[18] = 'P'; strfData[19] = 'G';
        writeLE32(strfData, 20, frameSize);
        strlContent.write(strfData);

        byte[] strlBytes = strlContent.toByteArray();

        byte[] strlListType = {'s', 't', 'r', 'l'};
        hdrlContent.write(LIST_TAG);
        writeLE32(hdrlContent, 4 + strlBytes.length);
        hdrlContent.write(strlListType);
        hdrlContent.write(strlBytes);

        byte[] hdrlBytes = hdrlContent.toByteArray();

        int riffContentSize = 4 + // 'AVI '
                8 + hdrlBytes.length + // LIST hdrl
                8 + 4 + moviBytes.length; // LIST movi

        baos.write(RIFF_TAG);
        writeLE32(baos, riffContentSize);
        baos.write(AVI_TAG);
        baos.write(LIST_TAG);
        writeLE32(baos, 4 + hdrlBytes.length);
        baos.write(HDRL_TAG);
        baos.write(hdrlBytes);
        baos.write(LIST_TAG);
        writeLE32(baos, 4 + moviBytes.length);
        baos.write(MOVI_TAG);
        baos.write(moviBytes);

        return baos.toByteArray();
    }

    private static final byte[] RIFF_TAG = {'R', 'I', 'F', 'F'};
    private static final byte[] AVI_TAG = {'A', 'V', 'I', ' '};
    private static final byte[] LIST_TAG = {'L', 'I', 'S', 'T'};
    private static final byte[] HDRL_TAG = {'h', 'd', 'r', 'l'};
    private static final byte[] MOVI_TAG = {'m', 'o', 'v', 'i'};

    private static void writeLE32(ByteArrayOutputStream baos, int value) {
        baos.write(value & 0xFF);
        baos.write((value >> 8) & 0xFF);
        baos.write((value >> 16) & 0xFF);
        baos.write((value >> 24) & 0xFF);
    }

    private static void writeLE32(byte[] data, int offset, int value) {
        data[offset] = (byte) (value & 0xFF);
        data[offset + 1] = (byte) ((value >> 8) & 0xFF);
        data[offset + 2] = (byte) ((value >> 16) & 0xFF);
        data[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private static void writeLE16(byte[] data, int offset, int value) {
        data[offset] = (byte) (value & 0xFF);
        data[offset + 1] = (byte) ((value >> 8) & 0xFF);
    }
}
