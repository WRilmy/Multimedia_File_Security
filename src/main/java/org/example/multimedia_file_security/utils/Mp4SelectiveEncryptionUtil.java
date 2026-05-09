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
        private int naluLengthSize = 4;
        private List<MediaSample> videoSamples = new ArrayList<>();
        private List<MediaSample> audioSamples = new ArrayList<>();
    }

    public static boolean isValidMp4(byte[] data) {
        if (data.length < 8) return false;
        return Arrays.equals(Arrays.copyOfRange(data, 4, 8), FTYP);
    }

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
            }

            pos += boxSize;
        }

        if (chunkOffsets != null && sampleSizes != null) {
            buildAudioSamples(chunkOffsets, sampleSizes, stscData, info);
        }
    }

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
                    if (j + 13 <= data.length) {
                        info.setNaluLengthSize((data[j + 12] & 0x03) + 1);
                    }
                    log.info("找到avcC: naluLengthSize={}", info.getNaluLengthSize());
                    return;
                }
                if (Arrays.equals(t, new byte[]{'h', 'v', 'c', 'C'})) {
                    info.setH264(false);
                    info.setNaluLengthSize(4);
                    log.info("找到hvcC: HEVC编码");
                    return;
                }
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

    public static byte[] selectiveEncryptMp4(byte[] mp4Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        Mp4Info info = parseMp4(mp4Data);

        if (info.getVideoSamples().isEmpty() && info.getAudioSamples().isEmpty()) {
            log.warn("MP4中未找到视频和音频采样数据，回退到全文件加密");
            return HyperchaoticChenUtil.xorWithKeyStream(mp4Data, config);
        }

        byte[] result = Arrays.copyOf(mp4Data, mp4Data.length);

        long mdatStart = info.getMdatDataOffset();
        long mdatEnd = info.getMdatDataEnd();
        int encryptedVideoCount = 0;
        int encryptedAudioCount = 0;

        // 加密视频采样
        for (MediaSample sample : info.getVideoSamples()) {
            if (sample.getOffset() < mdatStart || sample.getOffset() + sample.getSize() > mdatEnd) {
                log.warn("视频采样偏移超出mdat: offset={}, size={}", sample.getOffset(), sample.getSize());
                continue;
            }

            int sStart = (int) sample.getOffset();
            int sSize = sample.getSize();

            if (info.isH264()) {
                encryptedVideoCount += encryptH264Sample(result, sStart, sSize, info.getNaluLengthSize(), config);
            } else {
                encryptedVideoCount += encryptGenericSample(result, sStart, sSize, config);
            }
        }

        // 加密音频采样
        for (MediaSample sample : info.getAudioSamples()) {
            if (sample.getOffset() < mdatStart || sample.getOffset() + sample.getSize() > mdatEnd) {
                log.warn("音频采样偏移超出mdat: offset={}, size={}", sample.getOffset(), sample.getSize());
                continue;
            }

            int sStart = (int) sample.getOffset();
            int sSize = sample.getSize();
            encryptedAudioCount += encryptAudioSample(result, sStart, sSize, config);
        }

        log.info("MP4选择性加密完成: 视频 {}/{} 个采样已加密, 音频 {}/{} 个采样已加密",
                encryptedVideoCount, info.getVideoSamples().size(),
                encryptedAudioCount, info.getAudioSamples().size());
        return result;
    }

    private static int encryptH264Sample(byte[] data, int sampleStart, int sampleSize,
                                         int naluLengthSize, HyperchaoticChenUtil.ChenKeyStreamConfig config) {
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
                    byte[] payload = Arrays.copyOfRange(data, encStart, encStart + encLen);
                    byte[] encrypted = HyperchaoticChenUtil.xorWithKeyStream(payload, config);
                    System.arraycopy(encrypted, 0, data, encStart, encrypted.length);
                    encryptedNalus++;
                }
            }

            pos = naluDataStart + naluLength;
        }

        return encryptedNalus;
    }

    private static int readNaluLength(byte[] data, int pos, int size) {
        switch (size) {
            case 4: return readBE32(data, pos);
            case 2: return readBE16(data, pos);
            case 1: return data[pos] & 0xFF;
            default: return readBE32(data, pos);
        }
    }

    private static int encryptGenericSample(byte[] data, int sampleStart, int sampleSize,
                                            HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        int preserveBytes = Math.min(sampleSize / 4, 128);
        if (sampleSize > preserveBytes) {
            byte[] payload = Arrays.copyOfRange(data, sampleStart + preserveBytes, sampleStart + sampleSize);
            byte[] encrypted = HyperchaoticChenUtil.xorWithKeyStream(payload, config);
            System.arraycopy(encrypted, 0, data, sampleStart + preserveBytes, encrypted.length);
            return 1;
        }
        return 0;
    }

    /**
     * 加密音频采样。
     * 策略：保留音频帧头部（确保解码器能识别格式），对主体音频数据做异或加密。
     * 加密后音频呈现杂音/爆音/无声效果，但文件结构保持完整可被播放器解析。
     */
    private static int encryptAudioSample(byte[] data, int sampleStart, int sampleSize,
                                          HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        if (sampleSize <= 8) {
            return 0;
        }

        // 音频采样保留头部字节数：
        // - 小于32字节：保留一半（短采样需要更多结构保留）
        // - 32-256字节：保留16字节
        // - 大于256字节：保留32字节（AAC/MP3等帧头通常在前几字节）
        int preserveBytes;
        if (sampleSize < 32) {
            preserveBytes = sampleSize / 2;
        } else if (sampleSize < 256) {
            preserveBytes = 16;
        } else {
            preserveBytes = 32;
        }

        if (sampleSize > preserveBytes) {
            int encStart = sampleStart + preserveBytes;
            int encLen = sampleSize - preserveBytes;
            byte[] payload = Arrays.copyOfRange(data, encStart, encStart + encLen);
            byte[] encrypted = HyperchaoticChenUtil.xorWithKeyStream(payload, config);
            System.arraycopy(encrypted, 0, data, encStart, encrypted.length);
            return 1;
        }
        return 0;
    }

    public static byte[] selectiveDecryptMp4(byte[] encryptedMp4Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        if (!isValidMp4(encryptedMp4Data)) {
            log.warn("不是有效的MP4文件，回退到全文件解密");
            return HyperchaoticChenUtil.xorWithKeyStream(encryptedMp4Data, config);
        }
        return selectiveEncryptMp4(encryptedMp4Data, config);
    }

    public static byte[] fullEncryptMp4(byte[] mp4Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        return HyperchaoticChenUtil.xorWithKeyStream(mp4Data, config);
    }

    public static byte[] decryptMp4(byte[] encryptedMp4Data, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        if (isValidMp4(encryptedMp4Data)) {
            return selectiveDecryptMp4(encryptedMp4Data, config);
        } else {
            return HyperchaoticChenUtil.xorWithKeyStream(encryptedMp4Data, config);
        }
    }

    private static int readBE32(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
                ((data[offset + 1] & 0xFF) << 16) |
                ((data[offset + 2] & 0xFF) << 8) |
                (data[offset + 3] & 0xFF);
    }

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

    private static int readBE16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
