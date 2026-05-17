package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class Mp4SelectiveEncryptionUtil {

    private static final byte[] FTYP = {'f', 't', 'y', 'p'};
    private static final byte[] MOOV = {'m', 'o', 'o', 'v'};
    private static final byte[] MDAT = {'m', 'd', 'a', 't'};
    private static final byte[] TRAK = {'t', 'r', 'a', 'k'};
    private static final byte[] MDIA = {'m', 'd', 'i', 'a'};
    private static final byte[] HDLR = {'h', 'd', 'l', 'r'};
    private static final byte[] MINF = {'m', 'i', 'n', 'f'};
    private static final byte[] STBL = {'s', 't', 'b', 'l'};
    private static final byte[] STSD = {'s', 't', 's', 'd'};
    private static final byte[] STCO = {'s', 't', 'c', 'o'};
    private static final byte[] CO64 = {'c', 'o', '6', '4'};
    private static final byte[] STSZ = {'s', 't', 's', 'z'};
    private static final byte[] STSC = {'s', 't', 's', 'c'};
    private static final byte[] VIDE = {'v', 'i', 'd', 'e'};
    private static final byte[] SOUN = {'s', 'o', 'u', 'n'};

    private static final int NAL_TYPE_MASK = 0x1F;
    private static final int NAL_TYPE_IDR = 5;
    private static final int NAL_TYPE_SLICE = 1;
    private static final int HEVC_TRAIL_N = 0;
    private static final int HEVC_RASL_R = 9;
    private static final int HEVC_BLA_W_LP = 16;
    private static final int HEVC_RSV_IRAP_VCL23 = 23;

    private enum VideoCodec {
        H264, HEVC, OTHER
    }

    private enum AudioCodec {
        AAC, MP3, OTHER
    }

    @Data
    public static class MediaSample {
        private long offset;
        private int size;
    }

    @Data
    public static class Mp4Info {
        private long mdatDataOffset;
        private long mdatDataEnd;
        private boolean isH264;
        private VideoCodec videoCodec = VideoCodec.OTHER;
        private AudioCodec audioCodec = AudioCodec.OTHER;
        private int naluLengthSize = 4;
        private List<MediaSample> videoSamples = new ArrayList<>();
        private List<MediaSample> audioSamples = new ArrayList<>();
    }

    /**
     * 判断输入数据是否具有 MP4/ISO BMFF 的 ftyp 文件类型盒。
     *
     * @param data 待检查的文件字节
     * @return 如果第一个盒包含 ftyp 标识则返回 true
     */
    public static boolean isValidMp4(byte[] data) {
        if (data.length < 8) return false;
        return Arrays.equals(Arrays.copyOfRange(data, 4, 8), FTYP);
    }

    /**
     * 解析 MP4 容器，提取 mdat 数据范围、轨道类型、编解码信息和音视频 sample 表。
     *
     * @param data MP4 文件字节
     * @return MP4 结构信息
     * @throws IOException 当输入不是有效 MP4 数据时抛出
     */
    public static Mp4Info parseMp4(byte[] data) throws IOException {
        if (!isValidMp4(data)) {
            throw new IllegalArgumentException("无效的MP4文件");
        }

        Mp4Info info = new Mp4Info();

        long pos = 0;
        while (pos + 8 <= data.length) {
            long boxSize = readBE32(data, (int) pos);
            byte[] boxType = Arrays.copyOfRange(data, (int) pos + 4, (int) pos + 8);

            if (boxSize == 1) {
                if (pos + 16 > data.length) break;
                boxSize = readBE64(data, (int) pos + 8);
            } else if (boxSize == 0) {
                boxSize = data.length - pos;
            }
            if (boxSize < 8) break;

            if (Arrays.equals(boxType, MDAT)) {
                info.setMdatDataOffset(pos + 8);
                info.setMdatDataEnd(pos + boxSize);
            } else if (Arrays.equals(boxType, MOOV)) {
                parseMoov(data, (int) pos + 8, (int) (pos + boxSize), info);
            }

            pos += boxSize;
            if (pos <= 0 || pos > data.length) break;
        }

        log.info("MP4解析: h264={}, naluLenSize={}, videoSamples={}, mdat=[{},{}]",
                info.isH264(), info.getNaluLengthSize(), info.getVideoSamples().size(),
                info.getMdatDataOffset(), info.getMdatDataEnd());

        return info;
    }

    /**
     * 解析 moov 盒，向下查找每个 trak 轨道。
     *
     * @param data MP4 文件字节
     * @param start moov 内容起始偏移
     * @param end moov 内容结束偏移
     * @param info 解析结果承载对象
     */
    private static void parseMoov(byte[] data, int start, int end, Mp4Info info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, TRAK)) {
                parseTrak(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }
    }

    /**
     * 解析单个 trak 轨道，识别视频轨或音频轨后进入对应解析流程。
     *
     * @param data MP4 文件字节
     * @param start trak 内容起始偏移
     * @param end trak 内容结束偏移
     * @param info 解析结果承载对象
     */
    private static void parseTrak(byte[] data, int start, int end, Mp4Info info) {
        int mdiaStart = -1, mdiaEnd = -1;

        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, MDIA)) {
                mdiaStart = pos + 8;
                mdiaEnd = pos + boxSize;
            }

            pos += boxSize;
        }

        if (mdiaStart < 0) return;

        TrackType trackType = checkTrackHandler(data, mdiaStart, mdiaEnd);
        if (trackType == TrackType.VIDEO) {
            log.info("找到视频轨道");
            parseMdiaForVideo(data, mdiaStart, mdiaEnd, info);
        } else if (trackType == TrackType.AUDIO) {
            log.info("找到音频轨道");
            parseMdiaForAudio(data, mdiaStart, mdiaEnd, info);
        }
    }

    private enum TrackType {
        VIDEO, AUDIO, OTHER
    }

    /**
     * 从 hdlr 盒读取 handler type，判断轨道类型。
     *
     * @param data MP4 文件字节
     * @param start mdia 内容起始偏移
     * @param end mdia 内容结束偏移
     * @return 视频、音频或其他轨道类型
     */
    private static TrackType checkTrackHandler(byte[] data, int start, int end) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, HDLR)) {
                int handlerOffset = pos + 8 + 4 + 4;
                if (handlerOffset + 4 <= data.length) {
                    byte[] handlerType = Arrays.copyOfRange(data, handlerOffset, handlerOffset + 4);
                    if (Arrays.equals(handlerType, VIDE)) {
                        return TrackType.VIDEO;
                    } else if (Arrays.equals(handlerType, SOUN)) {
                        return TrackType.AUDIO;
                    }
                }
            }

            pos += boxSize;
        }
        return TrackType.OTHER;
    }

    private static void parseMdiaForVideo(byte[] data, int start, int end, Mp4Info info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, MINF)) {
                parseMinfForVideo(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }
    }

    private static void parseMdiaForAudio(byte[] data, int start, int end, Mp4Info info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, MINF)) {
                parseMinfForAudio(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }
    }

    private static void parseMinfForVideo(byte[] data, int start, int end, Mp4Info info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, STBL)) {
                parseStblForVideo(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }
    }

    private static void parseMinfForAudio(byte[] data, int start, int end, Mp4Info info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, STBL)) {
                parseStblForAudio(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }
    }

    /**
     * 解析视频轨的 stbl 采样表，读取 sample 偏移、大小和编码配置。
     *
     * @param data MP4 文件字节
     * @param start stbl 内容起始偏移
     * @param end stbl 内容结束偏移
     * @param info 解析结果承载对象
     */
    private static void parseStblForVideo(byte[] data, int start, int end, Mp4Info info) {
        int[] chunkOffsets = null;
        int[] sampleSizes = null;
        int[] stscData = null;

        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, STCO)) {
                chunkOffsets = parseStco(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, CO64)) {
                chunkOffsets = parseCo64(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, STSZ)) {
                sampleSizes = parseStsz(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, STSC)) {
                stscData = parseStsc(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, STSD)) {
                findCodecConfig(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }

        if (chunkOffsets != null && sampleSizes != null) {
            buildVideoSamples(chunkOffsets, sampleSizes, stscData, info);
        }
    }

    /**
     * 解析音频轨的 stbl 采样表，读取 sample 偏移、大小和音频编码配置。
     *
     * @param data MP4 文件字节
     * @param start stbl 内容起始偏移
     * @param end stbl 内容结束偏移
     * @param info 解析结果承载对象
     */
    private static void parseStblForAudio(byte[] data, int start, int end, Mp4Info info) {
        int[] chunkOffsets = null;
        int[] sampleSizes = null;
        int[] stscData = null;

        int pos = start;
        while (pos + 8 <= end && pos + 8 <= data.length) {
            int boxSize = readBE32(data, pos);
            byte[] boxType = Arrays.copyOfRange(data, pos + 4, pos + 8);

            if (boxSize < 8 || pos + boxSize > end) { pos++; continue; }

            if (Arrays.equals(boxType, STCO)) {
                chunkOffsets = parseStco(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, CO64)) {
                chunkOffsets = parseCo64(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, STSZ)) {
                sampleSizes = parseStsz(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, STSC)) {
                stscData = parseStsc(data, pos + 8, boxSize - 8);
            } else if (Arrays.equals(boxType, STSD)) {
                findAudioCodecConfig(data, pos + 8, pos + boxSize, info);
            }

            pos += boxSize;
        }

        if (chunkOffsets != null && sampleSizes != null) {
            buildAudioSamples(chunkOffsets, sampleSizes, stscData, info);
        }
    }

    /**
     * 在视频 sample description 中查找 avcC 或 hvcC 配置盒。
     *
     * @param data MP4 文件字节
     * @param start stsd 内容起始偏移
     * @param end stsd 内容结束偏移
     * @param info 解析结果承载对象
     */
    private static void findCodecConfig(byte[] data, int start, int end, Mp4Info info) {
        if (start + 8 > end) return;

        int entryCount = readBE32(data, start + 4);
        int pos = start + 8;

        for (int i = 0; i < entryCount && pos + 8 <= end; i++) {
            int entrySize = readBE32(data, pos);
            if (entrySize < 8 || pos + entrySize > end) break;

            int scanStart = pos + 8 + 6 + 2;
            int scanEnd = pos + entrySize;

            for (int j = scanStart; j + 8 <= scanEnd && j + 8 <= data.length; j++) {
                int potentialSize = readBE32(data, j);
                if (potentialSize < 8 || j + potentialSize > scanEnd) continue;

                byte[] t = Arrays.copyOfRange(data, j + 4, j + 8);
                if (Arrays.equals(t, new byte[]{'a', 'v', 'c', 'C'})) {
                    info.setH264(true);
                    info.setVideoCodec(VideoCodec.H264);
                    if (j + 13 <= data.length) {
                        info.setNaluLengthSize((data[j + 12] & 0x03) + 1);
                    }
                    log.info("找到avcC: naluLengthSize={}", info.getNaluLengthSize());
                    return;
                }
                if (Arrays.equals(t, new byte[]{'h', 'v', 'c', 'C'})) {
                    info.setH264(false);
                    info.setVideoCodec(VideoCodec.HEVC);
                    if (j + 30 <= data.length) {
                        info.setNaluLengthSize((data[j + 29] & 0x03) + 1);
                    } else {
                        info.setNaluLengthSize(4);
                    }
                    log.info("找到hvcC: HEVC编码");
                    return;
                }
            }

            pos += entrySize;
        }
    }

    /**
     * 在音频 sample description 中识别 AAC、MP3 或其他音频编码。
     *
     * @param data MP4 文件字节
     * @param start stsd 内容起始偏移
     * @param end stsd 内容结束偏移
     * @param info 解析结果承载对象
     */
    private static void findAudioCodecConfig(byte[] data, int start, int end, Mp4Info info) {
        if (start + 8 > end) return;

        int entryCount = readBE32(data, start + 4);
        int pos = start + 8;

        for (int i = 0; i < entryCount && pos + 8 <= end; i++) {
            int entrySize = readBE32(data, pos);
            if (entrySize < 8 || pos + entrySize > end) break;

            byte[] format = Arrays.copyOfRange(data, pos + 4, pos + 8);
            if (Arrays.equals(format, new byte[]{'m', 'p', '4', 'a'})) {
                info.setAudioCodec(AudioCodec.AAC);
                log.info("找到MP4音频编码: mp4a/AAC");
            } else if (Arrays.equals(format, new byte[]{'.', 'm', 'p', '3'}) ||
                    Arrays.equals(format, new byte[]{'m', 'p', '3', ' '})) {
                info.setAudioCodec(AudioCodec.MP3);
                log.info("找到MP4音频编码: MP3");
            } else {
                info.setAudioCodec(AudioCodec.OTHER);
                log.info("找到MP4音频编码: {}", new String(format, StandardCharsets.US_ASCII));
            }

            pos += entrySize;
        }
    }

    private static int[] parseStco(byte[] data, int start, int size) {
        if (size < 8) return null;
        int count = readBE32(data, start + 4);
        if (count <= 0 || count > 100000) return null;
        int[] result = new int[count];
        for (int i = 0; i < count; i++) {
            int off = start + 8 + i * 4;
            if (off + 4 > start + size) break;
            result[i] = readBE32(data, off);
        }
        return result;
    }

    private static int[] parseCo64(byte[] data, int start, int size) {
        if (size < 8) return null;
        int count = readBE32(data, start + 4);
        if (count <= 0 || count > 100000) return null;
        int[] result = new int[count];
        for (int i = 0; i < count; i++) {
            int off = start + 8 + i * 8;
            if (off + 8 > start + size) break;
            result[i] = (int) readBE64(data, off);
        }
        return result;
    }

    private static int[] parseStsz(byte[] data, int start, int size) {
        if (size < 12) return null;
        int defaultSize = readBE32(data, start + 4);
        int count = readBE32(data, start + 8);
        if (count <= 0 || count > 1000000) return null;

        if (defaultSize != 0) {
            int[] result = new int[count];
            Arrays.fill(result, defaultSize);
            return result;
        }

        int[] result = new int[count];
        for (int i = 0; i < count; i++) {
            int off = start + 12 + i * 4;
            if (off + 4 > start + size) break;
            result[i] = readBE32(data, off);
        }
        return result;
    }

    private static int[] parseStsc(byte[] data, int start, int size) {
        if (size < 8) return null;
        int count = readBE32(data, start + 4);
        if (count <= 0 || count > 100000) return null;
        int[] result = new int[count * 4];
        for (int i = 0; i < count; i++) {
            int off = start + 8 + i * 12;
            if (off + 12 > start + size) break;
            result[i * 4] = readBE32(data, off);
            result[i * 4 + 1] = readBE32(data, off + 4);
            result[i * 4 + 2] = readBE32(data, off + 8);
            result[i * 4 + 3] = 0;
        }
        return result;
    }

    /**
     * 根据 stco/co64、stsz、stsc 表构建视频 sample 的实际文件偏移。
     *
     * @param chunkOffsets chunk 起始偏移数组
     * @param sampleSizes sample 大小数组
     * @param stscData sample-to-chunk 表数据
     * @param info 解析结果承载对象
     */
    private static void buildVideoSamples(int[] chunkOffsets, int[] sampleSizes, int[] stscData, Mp4Info info) {
        int totalChunks = chunkOffsets.length;
        int totalSamples = sampleSizes.length;

        int[] spc = new int[totalChunks];
        if (stscData == null || stscData.length == 0) {
            for (int i = 0; i < totalChunks; i++) spc[i] = 1;
        } else {
            int entryCount = stscData.length / 4;
            for (int e = 0; e < entryCount; e++) {
                int firstChunk = stscData[e * 4];
                int samplesPerChunk = stscData[e * 4 + 1];
                int lastChunk = (e + 1 < entryCount) ? stscData[(e + 1) * 4] : totalChunks + 1;
                for (int c = firstChunk; c < lastChunk && c <= totalChunks; c++) {
                    spc[c - 1] = samplesPerChunk;
                }
            }
        }

        int sampleIdx = 0;
        for (int chunkIdx = 0; chunkIdx < totalChunks && sampleIdx < totalSamples; chunkIdx++) {
            long offset = chunkOffsets[chunkIdx];
            int count = spc[chunkIdx] > 0 ? spc[chunkIdx] : 1;

            for (int i = 0; i < count && sampleIdx < totalSamples; i++) {
                MediaSample vs = new MediaSample();
                vs.setOffset(offset);
                vs.setSize(sampleSizes[sampleIdx]);
                info.getVideoSamples().add(vs);
                offset += sampleSizes[sampleIdx];
                sampleIdx++;
            }
        }

        log.info("构建视频采样: {}个chunk, {}个sample", totalChunks, info.getVideoSamples().size());
    }

    /**
     * 根据 stco/co64、stsz、stsc 表构建音频 sample 的实际文件偏移。
     *
     * @param chunkOffsets chunk 起始偏移数组
     * @param sampleSizes sample 大小数组
     * @param stscData sample-to-chunk 表数据
     * @param info 解析结果承载对象
     */
    private static void buildAudioSamples(int[] chunkOffsets, int[] sampleSizes, int[] stscData, Mp4Info info) {
        int totalChunks = chunkOffsets.length;
        int totalSamples = sampleSizes.length;

        int[] spc = new int[totalChunks];
        if (stscData == null || stscData.length == 0) {
            for (int i = 0; i < totalChunks; i++) spc[i] = 1;
        } else {
            int entryCount = stscData.length / 4;
            for (int e = 0; e < entryCount; e++) {
                int firstChunk = stscData[e * 4];
                int samplesPerChunk = stscData[e * 4 + 1];
                int lastChunk = (e + 1 < entryCount) ? stscData[(e + 1) * 4] : totalChunks + 1;
                for (int c = firstChunk; c < lastChunk && c <= totalChunks; c++) {
                    spc[c - 1] = samplesPerChunk;
                }
            }
        }

        int sampleIdx = 0;
        for (int chunkIdx = 0; chunkIdx < totalChunks && sampleIdx < totalSamples; chunkIdx++) {
            long offset = chunkOffsets[chunkIdx];
            int count = spc[chunkIdx] > 0 ? spc[chunkIdx] : 1;

            for (int i = 0; i < count && sampleIdx < totalSamples; i++) {
                MediaSample as = new MediaSample();
                as.setOffset(offset);
                as.setSize(sampleSizes[sampleIdx]);
                info.getAudioSamples().add(as);
                offset += sampleSizes[sampleIdx];
                sampleIdx++;
            }
        }

        log.info("构建音频采样: {}个chunk, {}个sample", totalChunks, info.getAudioSamples().size());
    }

    /**
     * 对 MP4 文件执行结构保持型选择性加密。
     * <p>
     * 方法保留 ftyp、moov、mdat 盒结构和 sample 表，仅对 mdat 中可安全扰动的音视频 sample 载荷做连续密钥流 XOR。
     * 对 H.264/HEVC 会进一步保留 NALU 头部，降低破坏解码器结构识别的风险。
     * </p>
     *
     * @param mp4Data MP4 文件字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 加密后的 MP4 字节
     * @throws IOException 当 MP4 结构解析失败时抛出
     */
    public static byte[] selectiveEncryptMp4(byte[] mp4Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) throws IOException {
        Mp4Info info = parseMp4(mp4Data);

        if (info.getVideoSamples().isEmpty()) {
            log.warn("MP4 video samples were not found; returning original data to preserve container structure");
            return Arrays.copyOf(mp4Data, mp4Data.length);
        }

        byte[] result = Arrays.copyOf(mp4Data, mp4Data.length);

        long mdatStart = info.getMdatDataOffset();
        long mdatEnd = info.getMdatDataEnd();
        int encryptedVideoCount = 0;
        int encryptedAudioCount = 0;
        HyperchaoticChenOptimizedUtil.KeyStreamGenerator keyStream =
                new HyperchaoticChenOptimizedUtil.KeyStreamGenerator(config);

        // 加密视频采样
        for (MediaSample sample : info.getVideoSamples()) {
            if (sample.getOffset() < mdatStart || sample.getOffset() + sample.getSize() > mdatEnd) {
                log.warn("视频采样偏移超出mdat: offset={}, size={}", sample.getOffset(), sample.getSize());
                continue;
            }

            int sStart = (int) sample.getOffset();
            int sSize = sample.getSize();

            if (info.getVideoCodec() == VideoCodec.H264) {
                encryptedVideoCount += encryptH264Sample(result, sStart, sSize, info.getNaluLengthSize(), keyStream);
            } else if (info.getVideoCodec() == VideoCodec.HEVC) {
                encryptedVideoCount += encryptHevcSample(result, sStart, sSize, info.getNaluLengthSize(), keyStream);
            } else {
                log.warn("Unsupported MP4 video codec for safe selective encryption; sample skipped at offset={}", sample.getOffset());
            }
        }

        // Audio is stored as samples referenced by moov tables. Keep all container
        // metadata unchanged and only disturb sample payload bytes inside mdat.
        for (MediaSample sample : info.getAudioSamples()) {
            if (sample.getOffset() < mdatStart || sample.getOffset() + sample.getSize() > mdatEnd) {
                log.warn("音频采样偏移超出mdat: offset={}, size={}", sample.getOffset(), sample.getSize());
                continue;
            }

            int sStart = (int) sample.getOffset();
            int sSize = sample.getSize();
            encryptedAudioCount += encryptAudioSample(result, sStart, sSize, info.getAudioCodec(), keyStream);
        }

        log.info("MP4选择性加密完成: 视频 {}/{} 个采样已加密, 音频 {}/{} 个采样已加密",
                encryptedVideoCount, info.getVideoSamples().size(),
                encryptedAudioCount, info.getAudioSamples().size());
        return result;
    }

    /**
     * 加密 H.264 sample 中的 VCL NALU 载荷。
     *
     * @param data 待原地修改的 MP4 字节
     * @param sampleStart sample 起始偏移
     * @param sampleSize sample 大小
     * @param naluLengthSize NALU 长度字段字节数
     * @param keyStream 连续密钥流生成器
     * @return 被加密的 NALU 数量
     */
    private static int encryptH264Sample(byte[] data, int sampleStart, int sampleSize,
                                         int naluLengthSize, HyperchaoticChenOptimizedUtil.KeyStreamGenerator keyStream) {
        int pos = sampleStart;
        int end = sampleStart + sampleSize;
        int encryptedNalus = 0;

        while (pos + naluLengthSize < end) {
            int naluLength = readNaluLength(data, pos, naluLengthSize);
            if (naluLength <= 0 || pos + naluLengthSize + naluLength > end) break;

            int naluDataStart = pos + naluLengthSize;
            int nalType = data[naluDataStart] & NAL_TYPE_MASK;

            if (nalType == NAL_TYPE_IDR || nalType == NAL_TYPE_SLICE) {
                int preserveBytes;
                if (naluLength < 16) {
                    preserveBytes = naluLength;
                } else if (naluLength < 128) {
                    preserveBytes = 16;
                } else {
                    preserveBytes = 64;
                }

                if (naluLength > preserveBytes) {
                    int encStart = naluDataStart + preserveBytes;
                    int encLen = naluLength - preserveBytes;
                    keyStream.xorInPlace(data, encStart, encLen);
                    encryptedNalus++;
                }
            }

            pos = naluDataStart + naluLength;
        }

        return encryptedNalus;
    }

    /**
     * 加密 HEVC sample 中的 VCL NALU 载荷。
     *
     * @param data 待原地修改的 MP4 字节
     * @param sampleStart sample 起始偏移
     * @param sampleSize sample 大小
     * @param naluLengthSize NALU 长度字段字节数
     * @param keyStream 连续密钥流生成器
     * @return 被加密的 NALU 数量
     */
    private static int encryptHevcSample(byte[] data, int sampleStart, int sampleSize,
                                         int naluLengthSize, HyperchaoticChenOptimizedUtil.KeyStreamGenerator keyStream) {
        int pos = sampleStart;
        int end = sampleStart + sampleSize;
        int encryptedNalus = 0;

        while (pos + naluLengthSize < end) {
            int naluLength = readNaluLength(data, pos, naluLengthSize);
            if (naluLength <= 2 || pos + naluLengthSize + naluLength > end) break;

            int naluDataStart = pos + naluLengthSize;
            int nalType = (data[naluDataStart] >> 1) & 0x3F;

            if (isHevcVclNal(nalType)) {
                int preserveBytes;
                if (naluLength < 24) {
                    preserveBytes = naluLength;
                } else if (naluLength < 128) {
                    preserveBytes = 24;
                } else {
                    preserveBytes = 96;
                }

                if (naluLength > preserveBytes) {
                    int encStart = naluDataStart + preserveBytes;
                    int encLen = naluLength - preserveBytes;
                    keyStream.xorInPlace(data, encStart, encLen);
                    encryptedNalus++;
                }
            }

            pos = naluDataStart + naluLength;
        }

        return encryptedNalus;
    }

    /**
     * 判断 HEVC NALU 类型是否属于承载图像内容的 VCL 类型。
     *
     * @param nalType HEVC NALU 类型
     * @return 是 VCL NALU 则返回 true
     */
    private static boolean isHevcVclNal(int nalType) {
        return (nalType >= HEVC_TRAIL_N && nalType <= HEVC_RASL_R) ||
                (nalType >= HEVC_BLA_W_LP && nalType <= HEVC_RSV_IRAP_VCL23);
    }

    /**
     * 按指定长度字段读取 NALU 长度。
     *
     * @param data 数据字节
     * @param pos 长度字段偏移
     * @param size 长度字段字节数
     * @return NALU 载荷长度
     */
    private static int readNaluLength(byte[] data, int pos, int size) {
        switch (size) {
            case 4: return readBE32(data, pos);
            case 2: return readBE16(data, pos);
            case 1: return data[pos] & 0xFF;
            default: return readBE32(data, pos);
        }
    }

    private static int encryptGenericSample(byte[] data, int sampleStart, int sampleSize,
                                            HyperchaoticChenOptimizedUtil.KeyStreamGenerator keyStream) {
        int preserveBytes = Math.min(sampleSize / 4, 128);
        if (sampleSize > preserveBytes) {
            keyStream.xorInPlace(data, sampleStart + preserveBytes, sampleSize - preserveBytes);
            return 1;
        }
        return 0;
    }

    /**
     * 加密音频采样。
     * 策略：保留音频帧头部（确保解码器能识别格式），对主体音频数据做异或加密。
     * 加密后音频呈现杂音/爆音/无声效果，但文件结构保持完整可被播放器解析。
     */
    private static int encryptAudioSample(byte[] data, int sampleStart, int sampleSize, AudioCodec audioCodec,
                                          HyperchaoticChenOptimizedUtil.KeyStreamGenerator keyStream) {
        if (sampleSize <= 16) {
            return 0;
        }

        // 音频采样保留头部字节数：
        // - 小于32字节：保留一半（短采样需要更多结构保留）
        // - 32-256字节：保留16字节
        // - 大于256字节：保留32字节（AAC/MP3等帧头通常在前几字节）
        int preserveBytes;
        if (audioCodec == AudioCodec.MP3) {
            preserveBytes = Math.min(sampleSize, sampleSize < 128 ? 16 : 32);
        } else if (audioCodec == AudioCodec.AAC) {
            preserveBytes = Math.min(sampleSize, sampleSize < 96 ? sampleSize / 2 : 24);
        } else {
            preserveBytes = Math.min(sampleSize, sampleSize < 128 ? sampleSize / 2 : 32);
        }

        if (sampleSize > preserveBytes) {
            int encStart = sampleStart + preserveBytes;
            int encLen = sampleSize - preserveBytes;
            keyStream.xorInPlace(data, encStart, encLen);
            return 1;
        }
        return 0;
    }

    /**
     * 对 MP4 选择性密文执行解密。
     *
     * @param encryptedMp4Data MP4 密文字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 解密后的 MP4 字节
     * @throws IOException 当 MP4 结构解析失败时抛出
     */
    public static byte[] selectiveDecryptMp4(byte[] encryptedMp4Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) throws IOException {
        if (!isValidMp4(encryptedMp4Data)) {
            log.warn("不是有效的MP4文件，回退到全文件解密");
            return HyperchaoticChenOptimizedUtil.xorWithKeyStream(encryptedMp4Data, config);
        }
        return selectiveEncryptMp4(encryptedMp4Data, config);
    }

    /**
     * 对 MP4 文件整体执行超混沌 XOR 加密。
     *
     * @param mp4Data MP4 文件字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 全文件 XOR 后的字节
     */
    public static byte[] fullEncryptMp4(byte[] mp4Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) {
        return HyperchaoticChenOptimizedUtil.xorWithKeyStream(mp4Data, config);
    }

    /**
     * 根据 MP4 密文是否仍可识别，选择结构保持解密或全文件 XOR 解密。
     *
     * @param encryptedMp4Data MP4 密文字节
     * @param config 改进版超混沌 Chen 密钥流配置
     * @return 解密后的字节
     * @throws IOException 当 MP4 结构解析失败时抛出
     */
    public static byte[] decryptMp4(byte[] encryptedMp4Data, HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) throws IOException {
        if (isValidMp4(encryptedMp4Data)) {
            return selectiveDecryptMp4(encryptedMp4Data, config);
        } else {
            return HyperchaoticChenOptimizedUtil.xorWithKeyStream(encryptedMp4Data, config);
        }
    }

    /**
     * 从指定偏移读取大端序 32 位整数。
     *
     * @param data 数据字节
     * @param offset 起始偏移
     * @return 大端序整数值
     */
    private static int readBE32(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
                ((data[offset + 1] & 0xFF) << 16) |
                ((data[offset + 2] & 0xFF) << 8) |
                (data[offset + 3] & 0xFF);
    }

    /**
     * 从指定偏移读取大端序 64 位整数。
     *
     * @param data 数据字节
     * @param offset 起始偏移
     * @return 大端序长整数值
     */
    private static long readBE64(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 56) |
                ((long) (data[offset + 1] & 0xFF) << 48) |
                ((long) (data[offset + 2] & 0xFF) << 40) |
                ((long) (data[offset + 3] & 0xFF) << 32) |
                ((long) (data[offset + 4] & 0xFF) << 24) |
                ((long) (data[offset + 5] & 0xFF) << 16) |
                ((long) (data[offset + 6] & 0xFF) << 8) |
                ((long) (data[offset + 7] & 0xFF));
    }

    /**
     * 从指定偏移读取大端序 16 位整数。
     *
     * @param data 数据字节
     * @param offset 起始偏移
     * @return 大端序短整数值
     */
    private static int readBE16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
