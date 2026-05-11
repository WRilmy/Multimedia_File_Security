package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * WAV文件解析和选择性加密工具
 */
@Slf4j
public class WavSelectiveEncryptionUtil {

    @Data
    public static class WavInfo {
        private int fileSize;
        private int fmtChunkSize;
        private short audioFormat;
        private short numChannels;
        private int sampleRate;
        private int byteRate;
        private short blockAlign;
        private short bitsPerSample;
        private int dataChunkSize;
        private int dataOffset;

        @Override
        public String toString() {
            return String.format("WAV[channels=%d, sampleRate=%d, bitsPerSample=%d, dataSize=%d]",
                    numChannels, sampleRate, bitsPerSample, dataChunkSize);
        }
    }

    /**
     * 验证WAV格式
     */
    public static boolean isValidWav(byte[] wavData) {
        if (wavData.length < 44) return false;

        if (!"RIFF".equals(new String(wavData, 0, 4, StandardCharsets.US_ASCII))) {
            return false;
        }

        int totalSize = ByteBuffer.wrap(wavData, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (totalSize + 8 > wavData.length) {
            return false;
        }

        if (!"WAVE".equals(new String(wavData, 8, 4, StandardCharsets.US_ASCII))) {
            return false;
        }

        int offset = 12;
        boolean foundFmt = false;
        while (offset + 8 <= wavData.length) {
            String chunkId = new String(wavData, offset, 4, StandardCharsets.US_ASCII);
            int chunkSize = ByteBuffer.wrap(wavData, offset + 4, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .getInt();

            if ("fmt ".equals(chunkId)) {
                if (offset + chunkSize + 8 > wavData.length) return false;
                foundFmt = true;
            }

            if ("data".equals(chunkId)) {
                return foundFmt;
            }

            offset += chunkSize + 8;
        }

        return false;
    }

    /**
     * 解析WAV文件信息
     */
    public static WavInfo parseWav(byte[] wavData) throws IOException {
        if (!isValidWav(wavData)) {
            throw new IllegalArgumentException("无效的WAV文件");
        }

        WavInfo info = new WavInfo();
        ByteBuffer buf = ByteBuffer.wrap(wavData).order(ByteOrder.LITTLE_ENDIAN);

        info.setFileSize(buf.getInt(4) + 8);

        int offset = 12;
        while (offset + 8 <= wavData.length) {
            String chunkId = new String(wavData, offset, 4, StandardCharsets.US_ASCII);
            int chunkSize = ByteBuffer.wrap(wavData, offset + 4, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            if ("fmt ".equals(chunkId)) {
                info.setFmtChunkSize(chunkSize);
                ByteBuffer fmtBuf = ByteBuffer.wrap(wavData, offset + 8, Math.min(chunkSize, 40))
                        .order(ByteOrder.LITTLE_ENDIAN);
                info.setAudioFormat(fmtBuf.getShort());
                info.setNumChannels(fmtBuf.getShort());
                info.setSampleRate(fmtBuf.getInt());
                info.setByteRate(fmtBuf.getInt());
                info.setBlockAlign(fmtBuf.getShort());
                info.setBitsPerSample(fmtBuf.getShort());
            } else if ("data".equals(chunkId)) {
                info.setDataChunkSize(chunkSize);
                info.setDataOffset(offset + 8);
                break;
            }

            offset += chunkSize + 8;
        }

        return info;
    }

    /**
     * 使用超混沌系统对WAV文件进行选择性加密
     * 保持文件头完整，只对PCM数据进行异或扰动
     */
    public static byte[] selectiveEncryptWav(byte[] wavData, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        WavInfo info = parseWav(wavData);
        
        // 克隆原始数据
        byte[] result = Arrays.copyOf(wavData, wavData.length);
        
        // 计算PCM数据长度
        int pcmDataLength = info.getDataChunkSize();
        int pcmStart = info.getDataOffset();
        
        if (pcmStart + pcmDataLength > wavData.length) {
            throw new IllegalArgumentException("WAV数据长度异常");
        }
        
        // 提取PCM数据
        byte[] pcmData = Arrays.copyOfRange(wavData, pcmStart, pcmStart + pcmDataLength);
        
        // 使用超混沌系统生成密钥流并异或
        byte[] encryptedPcm = HyperchaoticChenUtil.xorWithKeyStream(pcmData, config);
        
        // 将加密后的PCM数据写回
        System.arraycopy(encryptedPcm, 0, result, pcmStart, encryptedPcm.length);
        
        return result;
    }

    /**
     * 对WAV文件进行全文件加密
     * 注意：全文件加密后文件将无法直接播放，需要解密后才能播放
     */
    public static byte[] fullEncryptWav(byte[] wavData, HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        return HyperchaoticChenUtil.xorWithKeyStream(wavData, config);
    }

    /**
     * 解密WAV文件（与加密过程相同，因为是异或操作）
     */
    public static byte[] decryptWav(byte[] encryptedWavData, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        if (isValidWav(encryptedWavData)) {
            // 选择性加密的WAV（仍保持WAV格式）
            return selectiveEncryptWav(encryptedWavData, config);
        } else {
            // 全文件加密的WAV
            return HyperchaoticChenUtil.xorWithKeyStream(encryptedWavData, config);
        }
    }
}