package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class AviSelectiveEncryptionUtil {

    private static final byte[] RIFF_TAG = {'R', 'I', 'F', 'F'};
    private static final byte[] AVI_TAG = {'A', 'V', 'I', ' '};
    private static final byte[] LIST_TAG = {'L', 'I', 'S', 'T'};
    private static final byte[] HDRL_TAG = {'h', 'd', 'r', 'l'};
    private static final byte[] MOVI_TAG = {'m', 'o', 'v', 'i'};
    private static final byte[] REC__TAG = {'r', 'e', 'c', ' '};
    private static final byte[] IDX1_TAG = {'i', 'd', 'x', '1'};

    private static final byte[] VIDEO_CHUNK_ID_DC = {'0', '0', 'd', 'c'};
    private static final byte[] VIDEO_CHUNK_ID_DB = {'0', '0', 'd', 'b'};
    private static final byte[] AUDIO_CHUNK_ID_WB = {'0', '1', 'w', 'b'};

    @Data
    public static class AviChunk {
        private byte[] fourCC;
        private int size;
        private int offset;
        private byte[] data;

        public String fourCCStr() {
            return new String(fourCC, StandardCharsets.US_ASCII);
        }
    }

    @Data
    public static class AviInfo {
        private int fileSize;
        private int hdrlSize;
        private int hdrlOffset;
        private int moviSize;
        private int moviOffset;
        private int moviDataOffset;
        private int idx1Offset;
        private int idx1Size;
        private List<AviChunk> videoChunks = new ArrayList<>();
        private List<AviChunk> audioChunks = new ArrayList<>();
        private int totalVideoDataSize;
        private int totalAudioDataSize;
        private int videoFrameCount;
        private int audioChunkCount;

        @Override
        public String toString() {
            return String.format("AVI[fileSize=%d, videoFrames=%d, audioChunks=%d, videoDataSize=%d]",
                    fileSize, videoFrameCount, audioChunkCount, totalVideoDataSize);
        }
    }

    public static boolean isValidAvi(byte[] aviData) {
        if (aviData.length < 12) return false;
        for (int i = 0; i < 4; i++) {
            if (aviData[i] != RIFF_TAG[i]) return false;
        }
        for (int i = 0; i < 4; i++) {
            if (aviData[i + 8] != AVI_TAG[i]) return false;
        }
        return true;
    }

    public static AviInfo parseAvi(byte[] aviData) throws IOException {
        if (!isValidAvi(aviData)) {
            throw new IllegalArgumentException("无效的AVI文件");
        }

        AviInfo info = new AviInfo();
        info.setFileSize(readLE32(aviData, 4) + 8);

        int pos = 12;

        while (pos + 8 <= aviData.length) {
            byte[] tag = Arrays.copyOfRange(aviData, pos, pos + 4);
            int chunkSize = readLE32(aviData, pos + 4);

            if (Arrays.equals(tag, LIST_TAG)) {
                if (pos + 12 > aviData.length) break;
                byte[] listType = Arrays.copyOfRange(aviData, pos + 8, pos + 12);

                if (Arrays.equals(listType, HDRL_TAG)) {
                    info.setHdrlOffset(pos);
                    info.setHdrlSize(chunkSize + 8);
                } else if (Arrays.equals(listType, MOVI_TAG)) {
                    info.setMoviOffset(pos);
                    info.setMoviSize(chunkSize + 8);
                    info.setMoviDataOffset(pos + 12);
                    parseMoviList(aviData, pos + 12, pos + 8 + chunkSize, info);
                }

                pos += 8 + chunkSize;
            } else if (Arrays.equals(tag, IDX1_TAG)) {
                info.setIdx1Offset(pos);
                info.setIdx1Size(chunkSize);
                pos += 8 + chunkSize;
            } else {
                pos += 8 + chunkSize;
            }

            if (chunkSize % 2 != 0) pos++;
        }

        info.setVideoFrameCount(info.getVideoChunks().size());
        info.setAudioChunkCount(info.getAudioChunks().size());
        return info;
    }

    private static void parseMoviList(byte[] aviData, int start, int end, AviInfo info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= aviData.length) {
            byte[] chunkId = Arrays.copyOfRange(aviData, pos, pos + 4);
            int chunkSize = readLE32(aviData, pos + 4);

            if (chunkSize < 0 || pos + 8 + chunkSize > aviData.length) break;

            if (Arrays.equals(chunkId, LIST_TAG)) {
                if (pos + 12 <= aviData.length) {
                    byte[] recType = Arrays.copyOfRange(aviData, pos + 8, pos + 12);
                    if (Arrays.equals(recType, REC__TAG)) {
                        parseRecList(aviData, pos + 12, pos + 8 + chunkSize, info);
                    }
                }
                pos += 8 + chunkSize;
            } else {
                AviChunk chunk = new AviChunk();
                chunk.setFourCC(chunkId);
                chunk.setSize(chunkSize);
                chunk.setOffset(pos + 8);
                chunk.setData(Arrays.copyOfRange(aviData, pos + 8, pos + 8 + chunkSize));

                if (isVideoChunk(chunkId)) {
                    info.getVideoChunks().add(chunk);
                    info.setTotalVideoDataSize(info.getTotalVideoDataSize() + chunkSize);
                } else if (isAudioChunk(chunkId)) {
                    info.getAudioChunks().add(chunk);
                    info.setTotalAudioDataSize(info.getTotalAudioDataSize() + chunkSize);
                }

                pos += 8 + chunkSize;
            }

            if (chunkSize % 2 != 0) pos++;
        }
    }

    private static void parseRecList(byte[] aviData, int start, int end, AviInfo info) {
        int pos = start;
        while (pos + 8 <= end && pos + 8 <= aviData.length) {
            byte[] chunkId = Arrays.copyOfRange(aviData, pos, pos + 4);
            int chunkSize = readLE32(aviData, pos + 4);

            if (chunkSize < 0 || pos + 8 + chunkSize > aviData.length) break;

            AviChunk chunk = new AviChunk();
            chunk.setFourCC(chunkId);
            chunk.setSize(chunkSize);
            chunk.setOffset(pos + 8);
            chunk.setData(Arrays.copyOfRange(aviData, pos + 8, pos + 8 + chunkSize));

            if (isVideoChunk(chunkId)) {
                info.getVideoChunks().add(chunk);
                info.setTotalVideoDataSize(info.getTotalVideoDataSize() + chunkSize);
            } else if (isAudioChunk(chunkId)) {
                info.getAudioChunks().add(chunk);
                info.setTotalAudioDataSize(info.getTotalAudioDataSize() + chunkSize);
            }

            pos += 8 + chunkSize;
            if (chunkSize % 2 != 0) pos++;
        }
    }

    private static boolean isVideoChunk(byte[] chunkId) {
        return Arrays.equals(chunkId, VIDEO_CHUNK_ID_DC) || Arrays.equals(chunkId, VIDEO_CHUNK_ID_DB);
    }

    private static boolean isAudioChunk(byte[] chunkId) {
        return Arrays.equals(chunkId, AUDIO_CHUNK_ID_WB);
    }

    /**
     * 检测视频帧的编解码器帧头大小
     * AVI中常见编解码器的帧内部结构：
     * - MJPEG: 每帧是完整的JPEG图像，头部包含SOI/APP0/DQT/SOF0/DHT等标记
     * - MPEG-4: 帧头包含VOP header
     * - H.264: 帧头包含slice header
     * 需要保留帧头，只对压缩数据部分进行XOR扰动
     */
    private static int detectFrameHeaderSize(byte[] frameData) {
        if (frameData.length < 4) return 0;

        // MJPEG: 以 0xFF 0xD8 (SOI) 开头
        if ((frameData[0] & 0xFF) == 0xFF && (frameData[1] & 0xFF) == 0xD8) {
            return detectJpegHeaderSize(frameData);
        }

        // MPEG-4 / H.264: 帧头通常较小，保留前64字节
        return Math.min(64, frameData.length / 4);
    }

    /**
     * 检测JPEG帧头大小（用于MJPEG编码的AVI）
     * 扫描JPEG标记，找到SOS(Start of Scan)标记后的数据起始位置
     * SOS之后就是实际的压缩图像数据，可以安全地XOR扰动
     */
    private static int detectJpegHeaderSize(byte[] jpegData) {
        int pos = 2; // 跳过SOI标记 (0xFF 0xD8)
        while (pos + 1 < jpegData.length) {
            if ((jpegData[pos] & 0xFF) != 0xFF) {
                pos++;
                continue;
            }
            int marker = jpegData[pos + 1] & 0xFF;

            // SOS标记之后就是压缩数据
            if (marker == 0xDA) {
                // SOS段: 0xFF 0xDA + 长度(2字节) + 参数 + 压缩数据
                if (pos + 3 < jpegData.length) {
                    int sosLength = ((jpegData[pos + 2] & 0xFF) << 8) | (jpegData[pos + 3] & 0xFF);
                    return pos + 2 + sosLength;
                }
                return pos + 4;
            }

            // 跳过不需要的标记段
            if (marker >= 0xD0 && marker <= 0xD9) {
                // RST标记和SOI/EOI没有长度字段
                pos += 2;
            } else if (marker != 0x00 && pos + 3 < jpegData.length) {
                int segLength = ((jpegData[pos + 2] & 0xFF) << 8) | (jpegData[pos + 3] & 0xFF);
                pos += 2 + segLength;
            } else {
                pos += 2;
            }
        }
        // 未找到SOS，回退：保留前25%作为头部
        return Math.min(jpegData.length / 4, 512);
    }

    public static byte[] selectiveEncryptAvi(byte[] aviData, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        AviInfo info = parseAvi(aviData);

        if (info.getVideoChunks().isEmpty() && info.getAudioChunks().isEmpty()) {
            log.warn("AVI中未找到视频或音频帧数据，回退到全文件加密");
            return HyperchaoticChenUtil.xorWithKeyStream(aviData, config);
        }

        byte[] result = Arrays.copyOf(aviData, aviData.length);

        for (AviChunk chunk : info.getVideoChunks()) {
            int offset = chunk.getOffset();
            int size = chunk.getSize();
            byte[] frameData = Arrays.copyOfRange(aviData, offset, offset + size);

            int headerSize = detectFrameHeaderSize(frameData);
            if (size > headerSize) {
                byte[] payloadData = Arrays.copyOfRange(frameData, headerSize, size);
                byte[] encryptedPayload = HyperchaoticChenUtil.xorWithKeyStream(payloadData, config);
                System.arraycopy(encryptedPayload, 0, result, offset + headerSize, encryptedPayload.length);
            }
        }

        for (AviChunk chunk : info.getAudioChunks()) {
            int offset = chunk.getOffset();
            int size = chunk.getSize();

            int preserveBytes;
            if (size <= 8) {
                preserveBytes = size;
            } else if (size <= 32) {
                preserveBytes = 4;
            } else {
                preserveBytes = 8;
            }

            if (size > preserveBytes) {
                byte[] payloadData = Arrays.copyOfRange(aviData, offset + preserveBytes, offset + size);
                byte[] encryptedPayload = HyperchaoticChenUtil.xorWithKeyStream(payloadData, config);
                System.arraycopy(encryptedPayload, 0, result, offset + preserveBytes, encryptedPayload.length);
            }
        }

        log.info("AVI选择性加密完成: 视频帧{}个, 音频帧{}个", info.getVideoChunks().size(), info.getAudioChunks().size());

        return result;
    }

    public static byte[] selectiveDecryptAvi(byte[] encryptedAviData, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        if (!isValidAvi(encryptedAviData)) {
            log.warn("不是有效的AVI文件，回退到全文件解密");
            return HyperchaoticChenUtil.xorWithKeyStream(encryptedAviData, config);
        }

        // XOR加密的对称性：加密和解密使用相同的操作
        return selectiveEncryptAvi(encryptedAviData, config);
    }

    public static byte[] fullEncryptAvi(byte[] aviData, HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        return HyperchaoticChenUtil.xorWithKeyStream(aviData, config);
    }

    public static byte[] decryptAvi(byte[] encryptedAviData, HyperchaoticChenUtil.ChenKeyStreamConfig config) throws IOException {
        if (isValidAvi(encryptedAviData)) {
            return selectiveDecryptAvi(encryptedAviData, config);
        } else {
            return HyperchaoticChenUtil.xorWithKeyStream(encryptedAviData, config);
        }
    }

    private static int readLE32(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
                ((data[offset + 1] & 0xFF) << 8) |
                ((data[offset + 2] & 0xFF) << 16) |
                ((data[offset + 3] & 0xFF) << 24);
    }
}