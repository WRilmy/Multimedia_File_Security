package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * MP3文件解析和选择性加密工具
 */
@Slf4j
public class Mp3SelectiveEncryptionUtil {

    // MP3帧同步字
    private static final int MP3_SYNC_WORD = 0xFFE00000;
    private static final int MP3_SYNC_MASK = 0xFFE00000;

    @Data
    public static class Mp3FrameInfo {
        private int frameSync;
        private int version;
        private int layer;
        private int protection;
        private int bitrate;
        private int sampleRate;
        private int padding;
        private int privateBit;
        private int channelMode;
        private int modeExtension;
        private int copyright;
        private int original;
        private int emphasis;
        private int frameSize;
        private int startPos;

        @Override
        public String toString() {
            return String.format("MP3Frame[bitrate=%dkbps, sampleRate=%dHz, size=%dB]",
                    bitrate, sampleRate, frameSize);
        }

        // 1. 修复 SideInfoSize 的计算逻辑 (基于 Version 和 ChannelMode)
        public int getSideInfoSize() {
            // 注意：这里的 version 对应的是 MPEG Version: 0=2.5, 2=2, 3=1
            // 你的 parseFrameHeader 里 frame.setVersion((header >> 19) & 0x03);
            // 所以 version=3 代表 MPEG-1
            if (getVersion() == 3) { // MPEG-1
                return (getChannelMode() == 3) ? 17 : 32; // 单声道:17, 立体声:32
            } else { // MPEG-2 或 MPEG-2.5
                return (getChannelMode() == 3) ? 9 : 17;  // 单声道:9, 立体声:17
            }
        }

        // 2. 新增：计算主数据的起始偏移量 (这才是你应该在加密代码里调用的方法)
        // 结构: [Header 4B] + [CRC 0/2B] + [Side Info X B]
        public int getMainDataOffset() {
            int offset = 4; // 帧头固定4字节
            // 如果 Protection Bit = 0，表示有 CRC 校验（2字节）
            if (getProtection() == 0) {
                offset += 2;
            }
            // 加上侧信息的长度
            offset += getSideInfoSize();
            return offset;
        }
    }

    @Data
    public static class Mp3Info {
        private List<Mp3FrameInfo> frames = new ArrayList<>();
        private int id3v2Size;
        private int totalFrames;
        private int totalSize;

        @Override
        public String toString() {
            return String.format("MP3[frames=%d, id3v2Size=%d]", totalFrames, id3v2Size);
        }
    }

    /**
     * 验证MP3格式
     */
    public static boolean isValidMp3(byte[] mp3Data) {
        if (mp3Data.length < 4) return false;

        // 检查ID3v2标签
        if (mp3Data[0] == 'I' && mp3Data[1] == 'D' && mp3Data[2] == '3') {
            return true;
        }

        // 检查帧同步
        int sync = ((mp3Data[0] & 0xFF) << 24) | ((mp3Data[1] & 0xFF) << 16) |
                  ((mp3Data[2] & 0xFF) << 8) | (mp3Data[3] & 0xFF);
        return (sync & MP3_SYNC_MASK) == MP3_SYNC_WORD;
    }

    /**
     * 解析MP3文件信息
     */
    public static Mp3Info parseMp3(byte[] mp3Data) throws IOException {
        if (!isValidMp3(mp3Data)) {
            throw new IllegalArgumentException("无效的MP3文件");
        }

        Mp3Info info = new Mp3Info();
        ByteArrayInputStream bis = new ByteArrayInputStream(mp3Data);
        DataInputStream dis = new DataInputStream(bis);

        // 检查并跳过ID3v2标签
        if (mp3Data[0] == 'I' && mp3Data[1] == 'D' && mp3Data[2] == '3') {
            dis.skipBytes(3); // ID3
            dis.skipBytes(2); // 版本
            dis.skipBytes(1); // 标志
            // 计算ID3v2大小
            int size = ((mp3Data[6] & 0x7F) << 21) | ((mp3Data[7] & 0x7F) << 14) |
                       ((mp3Data[8] & 0x7F) << 7) | (mp3Data[9] & 0x7F);
            info.setId3v2Size(size + 10);
            dis.skipBytes(size);
        }

        // 解析MP3帧
        int currentPos = info.getId3v2Size();
        while (currentPos + 4 <= mp3Data.length) {
            int sync = ((mp3Data[currentPos] & 0xFF) << 24) |
                      ((mp3Data[currentPos + 1] & 0xFF) << 16) |
                      ((mp3Data[currentPos + 2] & 0xFF) << 8) |
                      (mp3Data[currentPos + 3] & 0xFF);

            if ((sync & MP3_SYNC_MASK) == MP3_SYNC_WORD) {
                Mp3FrameInfo frame = parseFrameHeader(mp3Data, currentPos);
                if (frame != null) {
                    info.getFrames().add(frame);
                    currentPos += frame.getFrameSize();
                } else {
                    currentPos++;
                }
            } else {
                currentPos++;
            }
        }

        info.setTotalFrames(info.getFrames().size());
        info.setTotalSize(mp3Data.length);
        return info;
    }

    /**
     * 解析MP3帧头
     */
    private static Mp3FrameInfo parseFrameHeader(byte[] data, int pos) {
        if (pos + 4 > data.length) return null;

        int header = ((data[pos] & 0xFF) << 24) | ((data[pos + 1] & 0xFF) << 16) |
                    ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);

        Mp3FrameInfo frame = new Mp3FrameInfo();
        frame.setFrameSync(header >> 21);
        frame.setVersion((header >> 19) & 0x03);
        frame.setLayer((header >> 17) & 0x03);
        frame.setProtection((header >> 16) & 0x01);

        // 比特率
        int bitrateIndex = (header >> 12) & 0x0F;
        int[] bitrates = {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0};
        frame.setBitrate(bitrates[bitrateIndex]);

        // 采样率
        int sampleRateIndex = (header >> 10) & 0x03;
        int[] sampleRates = {44100, 48000, 32000, 0};
        frame.setSampleRate(sampleRates[sampleRateIndex]);

        // 跳过无效帧（比特率或采样率为0）
        if (frame.getBitrate() == 0 || frame.getSampleRate() == 0) {
            return null;
        }

        frame.setPadding((header >> 9) & 0x01);
        frame.setPrivateBit((header >> 8) & 0x01);
        frame.setChannelMode((header >> 6) & 0x03);
        frame.setModeExtension((header >> 4) & 0x03);
        frame.setCopyright((header >> 3) & 0x01);
        frame.setOriginal((header >> 2) & 0x01);
        frame.setEmphasis(header & 0x03);

        // 计算帧大小
        int frameSize = 0;
        if (frame.getLayer() == 1) {
            frameSize = (12 * frame.getBitrate() * 1000 / frame.getSampleRate() + frame.getPadding()) * 4;
        } else {
            frameSize = 144 * frame.getBitrate() * 1000 / frame.getSampleRate() + frame.getPadding();
        }
        frame.setFrameSize(frameSize);
        frame.setStartPos(pos);

        // 跳过无效帧大小
        if (frameSize <= 0) {
            return null;
        }

        return frame;
    }

    /**
     * 使用超混沌系统对MP3文件进行选择性加密
     * 保留帧头(4B)+CRC(0/2B)+侧信息(9-32B)，只对主数据进行异或扰动
     * 同时加密ID3v2标签主体（保留10字节头），避免元信息泄露
     * 解码器能正确解析帧结构，但音频内容变为噪声
     */
    public static byte[] selectiveEncryptMp3(byte[] mp3Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        Mp3Info info = parseMp3(mp3Data);
        byte[] result = Arrays.copyOf(mp3Data, mp3Data.length);

        List<Mp3FrameInfo> frames = info.getFrames();

        // 1. 加密ID3v2标签主体（保留10字节头：ID3+版本+标志+大小）
        int id3v2Size = info.getId3v2Size();
        if (id3v2Size > 10) {
            int id3BodyStart = 10;
            int id3BodyLen = id3v2Size - 10;
            byte[] id3Body = Arrays.copyOfRange(mp3Data, id3BodyStart, id3BodyStart + id3BodyLen);
            byte[] encryptedId3 = HyperchaoticChenUtil.xorWithKeyStream(id3Body, config);
            System.arraycopy(encryptedId3, 0, result, id3BodyStart, encryptedId3.length);
            log.info("ID3v2标签主体已加密: 保留10字节头, {}字节主体加密完成", id3BodyLen);
        }

        // 2. 加密所有帧的主数据
        int encryptCount = 0;
        int skipCount = 0;

        for (Mp3FrameInfo frame : frames) {
            int frameStart = frame.getStartPos();
            int frameSize = frame.getFrameSize();
            int frameEnd = frameStart + frameSize;

            if (frameEnd > mp3Data.length) {
                skipCount++;
                continue;
            }

            int mainDataOffset = frame.getMainDataOffset();
            int mainDataStart = frameStart + mainDataOffset;

            if (mainDataStart >= frameEnd) {
                skipCount++;
                continue;
            }

            int mainDataLen = frameEnd - mainDataStart;
            byte[] mainData = Arrays.copyOfRange(mp3Data, mainDataStart, mainDataStart + mainDataLen);
            byte[] encryptedData = HyperchaoticChenUtil.xorWithKeyStream(mainData, config);
            System.arraycopy(encryptedData, 0, result, mainDataStart, encryptedData.length);
            encryptCount++;
        }

        log.info("MP3选择性加密完成: {}/{} 帧已加密, {} 帧跳过",
                encryptCount, frames.size(), skipCount);
        return result;
    }

    /**
     * 对MP3文件进行全文件加密
     */
    public static byte[] fullEncryptMp3(byte[] mp3Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        return HyperchaoticChenUtil.xorWithKeyStream(mp3Data, config);
    }

    /**
     * 解密MP3文件（与加密过程相同，因为是异或操作）
     * 保持帧头不加密，只解密帧数据部分
     */
    public static byte[] decryptMp3(byte[] encryptedMp3Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        if (isValidMp3(encryptedMp3Data)) {
            // 选择性加密的MP3（仍保持MP3格式）
            return selectiveEncryptMp3(encryptedMp3Data, config);
        } else {
            // 全文件加密的MP3
            return HyperchaoticChenUtil.xorWithKeyStream(encryptedMp3Data, config);
        }
    }
}