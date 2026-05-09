package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
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

    // WAV文件签名
    private static final byte[] WAV_RIFF_SIGNATURE = {'R', 'I', 'F', 'F'};
    private static final byte[] WAV_WAVE_SIGNATURE = {'W', 'A', 'V', 'E'};
    private static final byte[] WAV_FMT_SIGNATURE = {'f', 'm', 't', ' '};
    private static final byte[] WAV_DATA_SIGNATURE = {'d', 'a', 't', 'a'};

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
        if (wavData.length < 44) return false;  // WAV最小长度至少44字节

        // 1. 检查RIFF头
        if (!"RIFF".equals(new String(wavData, 0, 4, StandardCharsets.US_ASCII))) {
            return false;
        }

        // 2. 检查总长度
        int totalSize = ByteBuffer.wrap(wavData, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (totalSize + 8 != wavData.length) {
            return false;  // 实际长度与声明不符
        }

        // 3. 检查WAVE标识
        if (!"WAVE".equals(new String(wavData, 8, 4, StandardCharsets.US_ASCII))) {
            return false;
        }

        // 4. 查找并检查"fmt "子块
        int offset = 12;
        boolean foundFmt = false;
        while (offset + 8 <= wavData.length) {
            String chunkId = new String(wavData, offset, 4, StandardCharsets.US_ASCII);
            int chunkSize = ByteBuffer.wrap(wavData, offset + 4, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .getInt();

            if ("fmt ".equals(chunkId)) {
                if (offset + chunkSize + 8 > wavData.length) return false;
                // 可进一步检查音频格式、采样率等
                foundFmt = true;
            }

            if ("data".equals(chunkId)) {
                return foundFmt;  // 找到data块且之前找到了fmt块
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
        ByteArrayInputStream bis = new ByteArrayInputStream(wavData);
        DataInputStream dis = new DataInputStream(bis);

        // 跳过RIFF标记
        dis.skipBytes(4);
        // 文件大小
        info.setFileSize(dis.readInt() + 8);
        // 跳过WAVE标记
        dis.skipBytes(4);

        // 寻找fmt块
        while (dis.available() > 0) {
            byte[] chunkId = new byte[4];
            dis.readFully(chunkId);
            int chunkSize = dis.readInt();

            if (Arrays.equals(chunkId, WAV_FMT_SIGNATURE)) {
                // 解析fmt块
                info.setFmtChunkSize(chunkSize);
                info.setAudioFormat(dis.readShort());
                info.setNumChannels(dis.readShort());
                info.setSampleRate(dis.readInt());
                info.setByteRate(dis.readInt());
                info.setBlockAlign(dis.readShort());
                info.setBitsPerSample(dis.readShort());
                // 跳过额外数据
                if (chunkSize > 16) {
                    dis.skipBytes(chunkSize - 16);
                }
            } else if (Arrays.equals(chunkId, WAV_DATA_SIGNATURE)) {
                // 找到data块
                info.setDataChunkSize(chunkSize);
                info.setDataOffset(dis.read() - 4); // 记录data块开始位置
                break;
            } else {
                // 跳过其他块
                dis.skipBytes(chunkSize);
            }
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