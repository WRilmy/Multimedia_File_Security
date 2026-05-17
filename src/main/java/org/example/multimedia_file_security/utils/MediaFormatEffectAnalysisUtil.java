package org.example.multimedia_file_security.utils;

import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 音视频格式保持与扰动率分析工具。
 */
public final class MediaFormatEffectAnalysisUtil {

    /**
     * 工具类不允许实例化。
     */
    private MediaFormatEffectAnalysisUtil() {
    }

    /**
     * 分析音视频选择性加密后的格式保持情况和字节扰动情况。
     *
     * @param originalData 原始文件字节
     * @param encryptedData 密文文件字节
     * @param filename 文件名
     * @return 前端可直接展示的分析结果
     */
    public static Map<String, Object> analyze(byte[] originalData, byte[] encryptedData, String filename) {
        String format = detectFormat(originalData, filename);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("format", format);
        result.put("filename", filename);
        result.put("originalSize", originalData == null ? 0 : originalData.length);
        result.put("encryptedSize", encryptedData == null ? 0 : encryptedData.length);
        result.put("originalSha256", sha256Hex(originalData));
        result.put("encryptedSha256", sha256Hex(encryptedData));
        result.put("originalRecognizable", isRecognizable(format, originalData));
        result.put("encryptedRecognizable", isRecognizable(format, encryptedData));

        MediaStructure originalStructure = parseStructure(format, originalData);
        MediaStructure encryptedStructure = parseStructure(format, encryptedData);
        result.put("structure", buildStructureMetrics(originalStructure, encryptedStructure));
        result.put("distortion", buildDistortionMetrics(originalData, encryptedData, originalStructure));
        result.put("conclusion", buildConclusion(result));
        return result;
    }

    /**
     * 根据文件内容和文件名判断媒体格式。
     *
     * @param data 文件字节
     * @param filename 文件名
     * @return 格式名称
     */
    private static String detectFormat(byte[] data, String filename) {
        String lowerName = filename == null ? "" : filename.toLowerCase();
        if (lowerName.endsWith(".avi") || AviSelectiveEncryptionUtil.isValidAvi(safeBytes(data))) {
            return "AVI";
        }
        if (lowerName.endsWith(".mp4") || Mp4SelectiveEncryptionUtil.isValidMp4(safeBytes(data))) {
            return "MP4";
        }
        if (lowerName.endsWith(".mp3") || Mp3SelectiveEncryptionUtil.isValidMp3(safeBytes(data))) {
            return "MP3";
        }
        if (lowerName.endsWith(".wav") || WavSelectiveEncryptionUtil.isValidWav(safeBytes(data))) {
            return "WAV";
        }
        return "UNKNOWN";
    }

    /**
     * 判断指定数据是否能被对应格式解析器识别。
     *
     * @param format 格式名称
     * @param data 文件字节
     * @return 是否可识别
     */
    private static boolean isRecognizable(String format, byte[] data) {
        byte[] safeData = safeBytes(data);
        return switch (format) {
            case "AVI" -> AviSelectiveEncryptionUtil.isValidAvi(safeData);
            case "MP4" -> Mp4SelectiveEncryptionUtil.isValidMp4(safeData);
            case "MP3" -> Mp3SelectiveEncryptionUtil.isValidMp3(safeData);
            case "WAV" -> WavSelectiveEncryptionUtil.isValidWav(safeData);
            default -> false;
        };
    }

    /**
     * 解析媒体结构信息。
     *
     * @param format 格式名称
     * @param data 文件字节
     * @return 媒体结构摘要
     */
    private static MediaStructure parseStructure(String format, byte[] data) {
        byte[] safeData = safeBytes(data);
        try {
            return switch (format) {
                case "AVI" -> parseAviStructure(safeData);
                case "MP4" -> parseMp4Structure(safeData);
                case "MP3" -> parseMp3Structure(safeData);
                case "WAV" -> parseWavStructure(safeData);
                default -> MediaStructure.empty(format);
            };
        } catch (Exception e) {
            return MediaStructure.empty(format);
        }
    }

    /**
     * 解析 AVI 的视频块和音频块信息。
     *
     * @param data AVI 字节
     * @return 媒体结构摘要
     */
    private static MediaStructure parseAviStructure(byte[] data) throws Exception {
        AviSelectiveEncryptionUtil.AviInfo info = AviSelectiveEncryptionUtil.parseAvi(data);
        MediaStructure structure = new MediaStructure("AVI");
        structure.videoUnits = info.getVideoFrameCount();
        structure.audioUnits = info.getAudioChunkCount();
        structure.videoBytes = info.getTotalVideoDataSize();
        structure.audioBytes = info.getTotalAudioDataSize();
        addAviRanges(structure.mediaRanges, info.getVideoChunks());
        addAviRanges(structure.mediaRanges, info.getAudioChunks());
        return structure;
    }

    /**
     * 解析 MP4 的视频采样和音频采样信息。
     *
     * @param data MP4 字节
     * @return 媒体结构摘要
     */
    private static MediaStructure parseMp4Structure(byte[] data) throws Exception {
        Mp4SelectiveEncryptionUtil.Mp4Info info = Mp4SelectiveEncryptionUtil.parseMp4(data);
        MediaStructure structure = new MediaStructure("MP4");
        structure.videoUnits = info.getVideoSamples().size();
        structure.audioUnits = info.getAudioSamples().size();
        addMp4Ranges(structure.mediaRanges, info.getVideoSamples());
        addMp4Ranges(structure.mediaRanges, info.getAudioSamples());
        structure.videoBytes = sumMp4SampleBytes(info.getVideoSamples());
        structure.audioBytes = sumMp4SampleBytes(info.getAudioSamples());
        return structure;
    }

    /**
     * 解析 MP3 的音频帧信息。
     *
     * @param data MP3 字节
     * @return 媒体结构摘要
     */
    private static MediaStructure parseMp3Structure(byte[] data) throws Exception {
        Mp3SelectiveEncryptionUtil.Mp3Info info = Mp3SelectiveEncryptionUtil.parseMp3(data);
        MediaStructure structure = new MediaStructure("MP3");
        structure.audioUnits = info.getTotalFrames();
        for (Mp3SelectiveEncryptionUtil.Mp3FrameInfo frame : info.getFrames()) {
            int start = frame.getStartPos();
            int length = frame.getFrameSize();
            structure.mediaRanges.add(new Range(start, length));
            structure.audioBytes += length;
        }
        return structure;
    }

    /**
     * 解析 WAV 的 PCM 数据区信息。
     *
     * @param data WAV 字节
     * @return 媒体结构摘要
     */
    private static MediaStructure parseWavStructure(byte[] data) throws Exception {
        WavSelectiveEncryptionUtil.WavInfo info = WavSelectiveEncryptionUtil.parseWav(data);
        MediaStructure structure = new MediaStructure("WAV");
        structure.audioUnits = 1;
        structure.audioBytes = info.getDataChunkSize();
        structure.mediaRanges.add(new Range(info.getDataOffset(), info.getDataChunkSize()));
        return structure;
    }

    /**
     * 构造媒体结构保持指标。
     *
     * @param original 原始文件结构
     * @param encrypted 密文文件结构
     * @return 结构保持指标
     */
    private static Map<String, Object> buildStructureMetrics(MediaStructure original, MediaStructure encrypted) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("originalVideoUnits", original.videoUnits);
        metrics.put("encryptedVideoUnits", encrypted.videoUnits);
        metrics.put("originalAudioUnits", original.audioUnits);
        metrics.put("encryptedAudioUnits", encrypted.audioUnits);
        metrics.put("originalMediaBytes", original.mediaBytes());
        metrics.put("encryptedMediaBytes", encrypted.mediaBytes());

        int originalUnits = original.videoUnits + original.audioUnits;
        int encryptedUnits = encrypted.videoUnits + encrypted.audioUnits;
        double unitRate = originalUnits == 0 ? 0.0 : Math.min(originalUnits, encryptedUnits) * 100.0 / originalUnits;
        double byteRate = original.mediaBytes() == 0 ? 0.0
                : Math.min(original.mediaBytes(), encrypted.mediaBytes()) * 100.0 / original.mediaBytes();
        double preservationRate = originalUnits == 0 ? byteRate : (unitRate * 0.7 + byteRate * 0.3);

        metrics.put("unitPreservationRate", round4(unitRate));
        metrics.put("mediaBytePreservationRate", round4(byteRate));
        metrics.put("structurePreservationRate", round4(preservationRate));
        return metrics;
    }

    /**
     * 构造字节扰动指标。
     *
     * @param originalData 原始文件字节
     * @param encryptedData 密文文件字节
     * @param structure 原始媒体结构
     * @return 扰动指标
     */
    private static Map<String, Object> buildDistortionMetrics(byte[] originalData, byte[] encryptedData,
                                                              MediaStructure structure) {
        int comparableLength = Math.min(lengthOf(originalData), lengthOf(encryptedData));
        long changedBytes = countChangedBytes(originalData, encryptedData, 0, comparableLength);
        long mediaChangedBytes = 0;
        long mediaComparableBytes = 0;
        for (Range range : structure.mediaRanges) {
            int start = Math.max(0, range.offset);
            int end = Math.min(comparableLength, range.offset + range.length);
            if (end > start) {
                mediaComparableBytes += end - start;
                mediaChangedBytes += countChangedBytes(originalData, encryptedData, start, end);
            }
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("comparableBytes", comparableLength);
        metrics.put("changedBytes", changedBytes);
        metrics.put("modifiedByteRate", round4(comparableLength == 0 ? 0.0 : changedBytes * 100.0 / comparableLength));
        metrics.put("mediaComparableBytes", mediaComparableBytes);
        metrics.put("mediaChangedBytes", mediaChangedBytes);
        metrics.put("mediaModifiedByteRate", round4(mediaComparableBytes == 0 ? 0.0
                : mediaChangedBytes * 100.0 / mediaComparableBytes));
        metrics.put("lengthChanged", lengthOf(originalData) != lengthOf(encryptedData));
        return metrics;
    }

    /**
     * 构造可读结论。
     *
     * @param result 分析结果
     * @return 结论文案
     */
    @SuppressWarnings("unchecked")
    private static String buildConclusion(Map<String, Object> result) {
        boolean recognizable = Boolean.TRUE.equals(result.get("encryptedRecognizable"));
        Map<String, Object> structure = (Map<String, Object>) result.get("structure");
        Map<String, Object> distortion = (Map<String, Object>) result.get("distortion");
        double structureRate = (Double) structure.get("structurePreservationRate");
        double modifiedRate = (Double) distortion.get("modifiedByteRate");

        if (recognizable && structureRate >= 99.0 && modifiedRate > 0.0) {
            return "密文仍保持格式可识别，媒体结构基本不变，同时文件字节已经发生扰动，符合选择性加密目标。";
        }
        if (!recognizable) {
            return "密文格式无法被当前解析器识别，更接近全文件加密结果，不适合作为格式保持型选择性加密证据。";
        }
        return "密文可识别，但结构保持率或扰动率不足，需要结合具体编码格式进一步检查。";
    }

    /**
     * 将 AVI 块列表转换为字节范围。
     *
     * @param ranges 目标范围列表
     * @param chunks AVI 块列表
     */
    private static void addAviRanges(List<Range> ranges, List<AviSelectiveEncryptionUtil.AviChunk> chunks) {
        for (AviSelectiveEncryptionUtil.AviChunk chunk : chunks) {
            ranges.add(new Range(chunk.getOffset(), chunk.getSize()));
        }
    }

    /**
     * 将 MP4 采样列表转换为字节范围。
     *
     * @param ranges 目标范围列表
     * @param samples MP4 采样列表
     */
    private static void addMp4Ranges(List<Range> ranges, List<Mp4SelectiveEncryptionUtil.MediaSample> samples) {
        for (Mp4SelectiveEncryptionUtil.MediaSample sample : samples) {
            ranges.add(new Range((int) sample.getOffset(), sample.getSize()));
        }
    }

    /**
     * 统计 MP4 采样字节数。
     *
     * @param samples MP4 采样列表
     * @return 采样总字节数
     */
    private static int sumMp4SampleBytes(List<Mp4SelectiveEncryptionUtil.MediaSample> samples) {
        int sum = 0;
        for (Mp4SelectiveEncryptionUtil.MediaSample sample : samples) {
            sum += sample.getSize();
        }
        return sum;
    }

    /**
     * 统计指定范围内发生变化的字节数。
     *
     * @param originalData 原始文件字节
     * @param encryptedData 密文文件字节
     * @param start 起始偏移
     * @param end 结束偏移
     * @return 变化字节数
     */
    private static long countChangedBytes(byte[] originalData, byte[] encryptedData, int start, int end) {
        long changed = 0;
        for (int i = start; i < end; i++) {
            if (originalData[i] != encryptedData[i]) {
                changed++;
            }
        }
        return changed;
    }

    /**
     * 计算 SHA-256 十六进制摘要。
     *
     * @param data 输入字节
     * @return 十六进制摘要
     */
    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(safeBytes(data));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b & 0xFF));
            }
            return builder.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 获取数组长度，空数组按 0 处理。
     *
     * @param data 字节数组
     * @return 数组长度
     */
    private static int lengthOf(byte[] data) {
        return data == null ? 0 : data.length;
    }

    /**
     * 将空引用转换为空数组。
     *
     * @param data 原始字节数组
     * @return 非空字节数组
     */
    private static byte[] safeBytes(byte[] data) {
        return data == null ? new byte[0] : data;
    }

    /**
     * 四位小数舍入。
     *
     * @param value 原始数值
     * @return 舍入后的数值
     */
    private static double round4(double value) {
        return Math.round(value * 10000.0) / 10000.0;
    }

    /**
     * 媒体结构摘要。
     */
    private static final class MediaStructure {
        private final String format;
        private int videoUnits;
        private int audioUnits;
        private int videoBytes;
        private int audioBytes;
        private final List<Range> mediaRanges = new java.util.ArrayList<>();

        /**
         * 创建媒体结构摘要。
         *
         * @param format 格式名称
         */
        private MediaStructure(String format) {
            this.format = format;
        }

        /**
         * 创建空结构摘要。
         *
         * @param format 格式名称
         * @return 空结构摘要
         */
        private static MediaStructure empty(String format) {
            return new MediaStructure(format);
        }

        /**
         * 计算媒体载荷总字节数。
         *
         * @return 媒体载荷总字节数
         */
        private int mediaBytes() {
            return videoBytes + audioBytes;
        }
    }

    /**
     * 文件内字节范围。
     */
    private static final class Range {
        private final int offset;
        private final int length;

        /**
         * 创建字节范围。
         *
         * @param offset 起始偏移
         * @param length 范围长度
         */
        private Range(int offset, int length) {
            this.offset = offset;
            this.length = length;
        }
    }
}
