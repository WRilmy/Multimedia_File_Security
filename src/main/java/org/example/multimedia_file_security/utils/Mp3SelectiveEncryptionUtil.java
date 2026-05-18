package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class Mp3SelectiveEncryptionUtil {

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

        /**
         * 计算当前 MP3 帧的边信息长度。
         *
         * @return 边信息区字节数，无法识别时返回 0
         */
        public int getSideInfoSize() {
            if (getLayer() != 1) {
                return 0;
            }
            if (getVersion() == 3) {
                return (getChannelMode() == 3) ? 17 : 32;
            }
            return (getChannelMode() == 3) ? 9 : 17;
        }

        /**
         * 计算 MP3 帧中主数据区的起始偏移。
         *
         * @return 相对于当前帧起点的主数据偏移
         */
        public int getMainDataOffset() {
            int offset = 4;
            if (getProtection() == 0) {
                offset += 2;
            }
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
     * 判断输入数据是否具有 MP3 文件或 MP3 帧的基本特征。
     *
     * @param mp3Data 待检查的文件字节
     * @return 如果包含 ID3v2 头或可识别帧同步字则返回 true
     */
    public static boolean isValidMp3(byte[] mp3Data) {
        if (mp3Data == null || mp3Data.length < 4) {
            return false;
        }

        int start = 0;
        boolean hasId3 = hasId3v2Header(mp3Data);
        if (hasId3) {
            start = getId3v2TagSize(mp3Data);
            if (start < 0 || start >= mp3Data.length) {
                return false;
            }
        }

        int firstFrame = findNextFrame(mp3Data, start);
        if (firstFrame < 0) {
            return false;
        }

        // 没有 ID3 标签时，MP3 帧通常应从文件起始位置出现；否则在任意二进制数据中搜索同步字容易误判。
        if (!hasId3 && firstFrame != 0) {
            return false;
        }

        Mp3FrameInfo frame = parseFrameHeader(mp3Data, firstFrame);
        return frame != null && firstFrame + frame.getFrameSize() <= mp3Data.length;
    }

    /**
     * 解析 MP3 文件，跳过 ID3v2 标签后逐帧收集帧偏移、帧长和编码参数。
     *
     * @param mp3Data MP3 文件字节
     * @return MP3 结构信息
     * @throws IOException 当输入不是有效 MP3 数据时抛出
     */
    public static Mp3Info parseMp3(byte[] mp3Data) throws IOException {
        if (!isValidMp3(mp3Data)) {
            throw new IllegalArgumentException("Invalid MP3 file");
        }

        Mp3Info info = new Mp3Info();
        if (hasId3v2Header(mp3Data)) {
            int id3v2Size = getId3v2TagSize(mp3Data);
            if (id3v2Size < 0 || id3v2Size > mp3Data.length) {
                throw new IllegalArgumentException("Invalid MP3 file");
            }
            info.setId3v2Size(id3v2Size);
        }

        int currentPos = info.getId3v2Size();
        while (currentPos + 4 <= mp3Data.length) {
            int header = readInt(mp3Data, currentPos);
            if ((header & MP3_SYNC_MASK) == MP3_SYNC_WORD) {
                Mp3FrameInfo frame = parseFrameHeader(mp3Data, currentPos);
                if (frame != null) {
                    info.getFrames().add(frame);
                    currentPos += frame.getFrameSize();
                    continue;
                }
            }
            currentPos++;
        }

        info.setTotalFrames(info.getFrames().size());
        info.setTotalSize(mp3Data.length);
        return info;
    }

    private static final int[][] BITRATES = {
            {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
            {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
            {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},
            {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
            {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}
    };

    private static final int[][] SAMPLE_RATES = {
            {44100, 48000, 32000, 0},
            {22050, 24000, 16000, 0},
            {11025, 12000, 8000, 0}
    };

    /**
     * 判断文件开头是否存在 ID3v2 标签。
     *
     * @param data 文件字节
     * @return 存在 ID3v2 标签则返回 true
     */
    private static boolean hasId3v2Header(byte[] data) {
        return data.length >= 10 && data[0] == 'I' && data[1] == 'D' && data[2] == '3';
    }

    /**
     * 读取 ID3v2 标签的完整长度。
     *
     * @param data 文件字节
     * @return ID3v2 标签总长度，不存在时返回 0
     */
    private static int getId3v2TagSize(byte[] data) {
        if (!hasId3v2Header(data)) {
            return 0;
        }
        int bodySize = ((data[6] & 0x7F) << 21) |
                ((data[7] & 0x7F) << 14) |
                ((data[8] & 0x7F) << 7) |
                (data[9] & 0x7F);
        int totalSize = bodySize + 10;
        boolean hasFooter = data[3] == 4 && (data[5] & 0x10) != 0;
        return hasFooter ? totalSize + 10 : totalSize;
    }

    /**
     * 从指定位置开始查找下一个可解析的 MP3 帧头。
     *
     * @param data MP3 文件字节
     * @param start 起始搜索偏移
     * @return 帧头偏移，未找到时返回 -1
     */
    private static int findNextFrame(byte[] data, int start) {
        int currentPos = Math.max(0, start);
        while (currentPos + 4 <= data.length) {
            int header = readInt(data, currentPos);
            if ((header & MP3_SYNC_MASK) == MP3_SYNC_WORD && parseFrameHeader(data, currentPos) != null) {
                return currentPos;
            }
            currentPos++;
        }
        return -1;
    }

    /**
     * 从指定偏移读取大端序 32 位整数。
     *
     * @param data 数据字节
     * @param pos 起始偏移
     * @return 大端序整数值
     */
    private static int readInt(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 24) |
                ((data[pos + 1] & 0xFF) << 16) |
                ((data[pos + 2] & 0xFF) << 8) |
                (data[pos + 3] & 0xFF);
    }

    /**
     * 根据 MP3 版本、层级和码率索引查表得到码率。
     *
     * @param version MPEG 版本标识
     * @param layer 音频层级标识
     * @param bitrateIndex 码率索引
     * @return 码率，单位 kbps
     */
    private static int getBitrate(int version, int layer, int bitrateIndex) {
        int tableIndex;
        if (version == 3) {
            tableIndex = 3 - layer;
        } else {
            tableIndex = layer == 3 ? 3 : 4;
        }
        if (tableIndex < 0 || tableIndex >= BITRATES.length) {
            return 0;
        }
        if (bitrateIndex < 0 || bitrateIndex >= BITRATES[tableIndex].length) {
            return 0;
        }
        return BITRATES[tableIndex][bitrateIndex];
    }

    /**
     * 根据 MPEG 版本和采样率索引查表得到采样率。
     *
     * @param version MPEG 版本标识
     * @param sampleRateIndex 采样率索引
     * @return 采样率，单位 Hz
     */
    private static int getSampleRate(int version, int sampleRateIndex) {
        int tableIndex;
        if (version == 3) {
            tableIndex = 0;
        } else if (version == 2) {
            tableIndex = 1;
        } else {
            tableIndex = 2;
        }
        if (sampleRateIndex < 0 || sampleRateIndex >= SAMPLE_RATES[tableIndex].length) {
            return 0;
        }
        return SAMPLE_RATES[tableIndex][sampleRateIndex];
    }

    /**
     * 解析单个 MP3 帧头，计算帧长、码率、采样率和声道模式。
     *
     * @param data MP3 文件字节
     * @param pos 帧头偏移
     * @return 可识别帧信息，无法识别时返回 null
     */
    private static Mp3FrameInfo parseFrameHeader(byte[] data, int pos) {
        if (pos + 4 > data.length) {
            return null;
        }

        int header = readInt(data, pos);
        Mp3FrameInfo frame = new Mp3FrameInfo();
        frame.setFrameSync(header >> 21);
        frame.setVersion((header >> 19) & 0x03);
        frame.setLayer((header >> 17) & 0x03);
        frame.setProtection((header >> 16) & 0x01);

        if ((header & MP3_SYNC_MASK) != MP3_SYNC_WORD || frame.getVersion() == 1 || frame.getLayer() == 0) {
            return null;
        }

        int bitrateIndex = (header >> 12) & 0x0F;
        int sampleRateIndex = (header >> 10) & 0x03;
        frame.setBitrate(getBitrate(frame.getVersion(), frame.getLayer(), bitrateIndex));
        frame.setSampleRate(getSampleRate(frame.getVersion(), sampleRateIndex));

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

        int frameSize;
        if (frame.getLayer() == 3) {
            frameSize = (12 * frame.getBitrate() * 1000 / frame.getSampleRate() + frame.getPadding()) * 4;
        } else if (frame.getLayer() == 1 && frame.getVersion() != 3) {
            frameSize = 72 * frame.getBitrate() * 1000 / frame.getSampleRate() + frame.getPadding();
        } else {
            frameSize = 144 * frame.getBitrate() * 1000 / frame.getSampleRate() + frame.getPadding();
        }

        int mainDataOffset = 4 + (frame.getProtection() == 0 ? 2 : 0) + frame.getSideInfoSize();
        if (frameSize <= mainDataOffset || pos + frameSize > data.length) {
            return null;
        }

        frame.setFrameSize(frameSize);
        frame.setStartPos(pos);
        return frame;
    }

    /**
     * 对 MP3 文件执行结构保持型选择性加密。
     * <p>
     * 方法保留 ID3 标签、帧头和边信息，只对帧主数据区做连续密钥流 XOR，
     * 从而尽量保持播放器识别能力，同时破坏实际音频内容。
     * </p>
     *
     * @param mp3Data MP3 文件字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 加密后的 MP3 字节
     * @throws IOException 当 MP3 结构解析失败时抛出
     */
    public static byte[] selectiveEncryptMp3(byte[] mp3Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) throws IOException {
        Mp3Info info = parseMp3(mp3Data);
        byte[] result = Arrays.copyOf(mp3Data, mp3Data.length);
        List<Mp3FrameInfo> frames = info.getFrames();
        HyperchaoticChenOptimizedUtil.KeyStreamGenerator keyStream =
                new HyperchaoticChenOptimizedUtil.KeyStreamGenerator(config);

        if (info.getId3v2Size() > 0) {
            log.info("MP3 ID3v2 tag preserved: {} bytes", info.getId3v2Size());
        }

        int encryptCount = 0;
        int skipCount = 0;
        for (int i = 0; i < frames.size(); i++) {
            Mp3FrameInfo frame = frames.get(i);
            // The first audio frame can carry Xing/Info/VBRI/LAME metadata used by strict players.
            if (i == 0) {
                skipCount++;
                continue;
            }

            int frameStart = frame.getStartPos();
            int frameEnd = frameStart + frame.getFrameSize();
            int mainDataStart = frameStart + frame.getMainDataOffset();

            if (frameEnd > mp3Data.length || mainDataStart >= frameEnd) {
                skipCount++;
                continue;
            }

            int mainDataLen = frameEnd - mainDataStart;
            keyStream.xorInPlace(result, mainDataStart, mainDataLen);
            encryptCount++;
        }

        log.info("MP3 selective encryption completed: {}/{} frames encrypted, {} frames skipped",
                encryptCount, frames.size(), skipCount);
        return result;
    }

    /**
     * 对 MP3 文件整体执行超混沌 XOR 加密。
     *
     * @param mp3Data MP3 文件字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 全文件 XOR 后的字节
     */
    public static byte[] fullEncryptMp3(byte[] mp3Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) {
        return HyperchaoticChenOptimizedUtil.xorWithKeyStream(mp3Data, config);
    }

    /**
     * 根据 MP3 密文是否仍可识别，选择结构保持解密或全文件 XOR 解密。
     *
     * @param encryptedMp3Data MP3 密文字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 解密后的字节
     * @throws IOException 当 MP3 结构解析失败时抛出
     */
    public static byte[] decryptMp3(byte[] encryptedMp3Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) throws IOException {
        if (isValidMp3(encryptedMp3Data)) {
            return selectiveEncryptMp3(encryptedMp3Data, config);
        }
        return HyperchaoticChenOptimizedUtil.xorWithKeyStream(encryptedMp3Data, config);
    }
}
