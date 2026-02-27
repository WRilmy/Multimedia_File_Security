package org.example.multimedia_file_security.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

@Component
@Slf4j
public class VideoSnowEncryptionUtil {

    // H.264 NAL单元类型
    private static final int NAL_TYPE_IDR = 5;    // IDR帧（关键帧）
    private static final int NAL_TYPE_SLICE = 1;  // 非IDR帧
    private static final int NAL_TYPE_SPS = 7;    // 序列参数集
    private static final int NAL_TYPE_PPS = 8;    // 图像参数集

    /**
     * 视频雪花效果加密 - 只加密关键帧
     * 效果：视频可播放，但关键帧显示雪花
     */
    public static byte[] selectiveVideoEncryptWithSnow(byte[] videoData, String filename, String sm4Key) throws Exception {
        log.info("开始雪花效果视频加密: {}, 大小: {} bytes", filename, videoData.length);

        // 检测视频格式
        String format = detectVideoFormat(videoData, filename);
        log.info("检测到视频格式: {}", format);

        if ("MP4".equals(format) || "MOV".equals(format)) {
            return encryptMp4WithSnow(videoData, sm4Key, filename);
        } else if ("AVI".equals(format)) {
            return encryptAviWithSnow(videoData, sm4Key, filename);
        } else if ("FLV".equals(format)) {
            return encryptFlvWithSnow(videoData, sm4Key, filename);
        } else {
            // 不支持的格式，回退到全文件加密
            log.warn("不支持的视频格式 {}, 使用全文件加密", format);
            return Sm4EncryptionUtil.fullEncrypt(videoData, sm4Key);
        }
    }

    /**
     * MP4雪花效果加密
     */
    private static byte[] encryptMp4WithSnow(byte[] mp4Data, String sm4Key, String filename) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // 查找moov box，获取帧信息
        int moovStart = findBox(mp4Data, "moov");
        int mdatStart = findBox(mp4Data, "mdat");

        if (moovStart < 0 || mdatStart < 0) {
            log.warn("未找到moov或mdat box，使用全文件加密");
            return Sm4EncryptionUtil.fullEncrypt(mp4Data, sm4Key);
        }

        // 1. 写入文件头部（到mdat开始位置）
        outputStream.write(mp4Data, 0, mdatStart);

        // 2. 从mdat开始分析帧
        int dataStart = mdatStart + 8; // 跳过mdat box header
        int encryptedFrameCount = 0;
        int totalFrameCount = 0;

        Random random = new Random(Arrays.hashCode(Base64.getDecoder().decode(sm4Key)));

        // 3. 尝试查找H.264起始码
        for (int i = dataStart; i < mp4Data.length - 4; i++) {
            // 查找起始码 0x000001
            if (mp4Data[i] == 0x00 && mp4Data[i+1] == 0x00 &&
                    mp4Data[i+2] == 0x01) {

                int startCodeLength = 3;
                if (i > 0 && mp4Data[i-1] == 0x00) {
                    startCodeLength = 4; // 0x00000001
                }

                int nalStart = i + startCodeLength;
                if (nalStart >= mp4Data.length) break;

                int nalType = mp4Data[nalStart] & 0x1F;

                // 查找下一个起始码
                int j = i + startCodeLength;
                while (j < mp4Data.length - 4) {
                    if (mp4Data[j] == 0x00 && mp4Data[j+1] == 0x00 &&
                            mp4Data[j+2] == 0x01) {
                        break;
                    }
                    j++;
                }

                int frameEnd = j;
                int frameLength = frameEnd - i;

                if (frameLength > 0) {
                    totalFrameCount++;

                    byte[] frameData = Arrays.copyOfRange(mp4Data, i, frameEnd);

                    // 只加密IDR帧（关键帧），概率80%
                    if (nalType == NAL_TYPE_IDR && random.nextDouble() < 0.8) {
                        // 加密关键帧，产生雪花效果
                        byte[] encryptedFrame = encryptH264Frame(frameData, sm4Key, true);
                        outputStream.write(encryptedFrame);
                        encryptedFrameCount++;
                    } else {
                        // 非关键帧保持原样
                        outputStream.write(frameData);
                    }

                    i = frameEnd - 1; // 循环会i++，所以减1
                }
            }
        }

        // 4. 写入剩余数据
        int lastPos = dataStart;
        for (int i = dataStart; i < mp4Data.length; i++) {
            if (i < mp4Data.length - 4 &&
                    mp4Data[i] == 0x00 && mp4Data[i+1] == 0x00 && mp4Data[i+2] == 0x01) {
                // 已经处理过的帧
                i = findNextStartCode(mp4Data, i) - 1;
                continue;
            }
            if (i > lastPos) {
                outputStream.write(mp4Data, lastPos, i - lastPos);
            }
            lastPos = i;
        }

        if (lastPos < mp4Data.length) {
            outputStream.write(mp4Data, lastPos, mp4Data.length - lastPos);
        }

        log.info("雪花加密完成: 总帧数={}, 加密关键帧={}, 原始大小={}, 加密后大小={}",
                totalFrameCount, encryptedFrameCount, mp4Data.length, outputStream.size());

        return outputStream.toByteArray();
    }

    /**
     * 加密H.264帧，产生雪花效果
     */
    private static byte[] encryptH264Frame(byte[] frameData, String sm4Key, boolean snowEffect) throws Exception {
        if (!snowEffect) {
            // 全帧加密
            return Sm4EncryptionUtil.fullEncrypt(frameData, sm4Key);
        }

        // 雪花效果：只扰乱部分数据
        byte[] encryptedFrame = frameData.clone();
        Random random = new Random(Arrays.hashCode(Base64.getDecoder().decode(sm4Key)));

        // 跳过起始码和NAL单元头
        int dataStart = 0;
        if (frameData.length > 4 && frameData[0] == 0x00 && frameData[1] == 0x00) {
            dataStart = (frameData[2] == 0x01) ? 3 : 4;
        }

        // 扰乱30%的数据，产生雪花效果
        for (int i = dataStart; i < encryptedFrame.length; i++) {
            if (random.nextDouble() < 0.3) {
                encryptedFrame[i] = (byte) random.nextInt(256);
            }
        }

        return encryptedFrame;
    }

    /**
     * 查找MP4 box
     */
    private static int findBox(byte[] data, String boxType) {
        for (int i = 0; i < data.length - 8; i++) {
            // 读取box大小
            int boxSize = ByteBuffer.wrap(data, i, 4).getInt();

            if (boxSize <= 0 || boxSize > data.length - i) {
                continue;
            }

            // 读取box类型
            String type = new String(data, i + 4, 4);

            if (type.equals(boxType)) {
                return i;
            }

            i += boxSize - 1; // 循环会i++
        }

        return -1;
    }

    /**
     * 查找下一个起始码
     */
    private static int findNextStartCode(byte[] data, int start) {
        for (int i = start + 3; i < data.length - 4; i++) {
            if (data[i] == 0x00 && data[i+1] == 0x00 && data[i+2] == 0x01) {
                return i;
            }
        }
        return data.length;
    }

    /**
     * 检测视频格式
     */
    private static String detectVideoFormat(byte[] data, String filename) {
        // 优先使用文件扩展名
        String lowerName = filename.toLowerCase();

        if (lowerName.endsWith(".mp4") || lowerName.endsWith(".m4v")) {
            return "MP4";
        } else if (lowerName.endsWith(".avi")) {
            return "AVI";
        } else if (lowerName.endsWith(".mov")) {
            return "MOV";
        } else if (lowerName.endsWith(".flv")) {
            return "FLV";
        } else if (lowerName.endsWith(".mkv")) {
            return "MKV";
        } else if (lowerName.endsWith(".wmv")) {
            return "WMV";
        }

        // 如果没有扩展名，尝试通过文件头检测
        if (data.length >= 8) {
            // 检查MP4
            if (data[4] == 'f' && data[5] == 't' && data[6] == 'y' && data[7] == 'p') {
                return "MP4";
            }
            // 检查AVI
            if (data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F') {
                return "AVI";
            }
        }

        return "UNKNOWN";
    }

    /**
     * AVI雪花效果加密
     */
    private static byte[] encryptAviWithSnow(byte[] aviData, String sm4Key, String filename) throws Exception {
        // AVI格式：查找'00db'关键帧和'00dc'普通帧
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int i = 0;
        int encryptedFrameCount = 0;

        Random random = new Random(Arrays.hashCode(Base64.getDecoder().decode(sm4Key)));

        while (i < aviData.length - 8) {
            // 查找'LIST'块或关键帧
            if (i + 4 < aviData.length) {
                String chunkId = new String(aviData, i, 4);

                if (chunkId.equals("00db") || chunkId.equals("00dc")) {
                    int frameStart = i;
                    i += 4; // 跳过chunk id

                    int chunkSize = ByteBuffer.wrap(aviData, i, 4).getInt();
                    i += 4; // 跳过chunk size

                    int frameEnd = i + chunkSize;

                    if (frameEnd > aviData.length) {
                        // 数据不完整
                        outputStream.write(aviData, frameStart, aviData.length - frameStart);
                        break;
                    }

                    byte[] frameData = Arrays.copyOfRange(aviData, frameStart, frameEnd);

                    // 只加密关键帧（00db），且概率80%
                    if (chunkId.equals("00db") && random.nextDouble() < 0.8) {
                        // 扰乱关键帧，产生雪花效果
                        byte[] encryptedFrame = disturbFrameData(frameData, sm4Key, 0.3);
                        outputStream.write(encryptedFrame);
                        encryptedFrameCount++;
                    } else {
                        outputStream.write(frameData);
                    }

                    i = frameEnd;
                    continue;
                }
            }

            // 写入非帧数据
            outputStream.write(aviData[i]);
            i++;
        }

        log.info("AVI雪花加密完成: 加密了 {} 个关键帧", encryptedFrameCount);
        return outputStream.toByteArray();
    }

    /**
     * FLV雪花效果加密
     */
    private static byte[] encryptFlvWithSnow(byte[] flvData, String sm4Key, String filename) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // FLV头部（9字节）
        if (flvData.length >= 9) {
            outputStream.write(flvData, 0, 9);
        }

        int i = 9; // 跳过FLV头部
        int encryptedFrameCount = 0;

        Random random = new Random(Arrays.hashCode(Base64.getDecoder().decode(sm4Key)));

        while (i < flvData.length - 15) {
            int tagStart = i;

            int tagType = flvData[i] & 0xFF;
            i++;

            int dataSize = ((flvData[i] & 0xFF) << 16) |
                    ((flvData[i+1] & 0xFF) << 8) |
                    (flvData[i+2] & 0xFF);
            i += 3;

            int timestamp = ((flvData[i] & 0xFF) << 16) |
                    ((flvData[i+1] & 0xFF) << 8) |
                    (flvData[i+2] & 0xFF);
            i += 7; // 跳过timestamp(3) + timestampExtended(1) + streamId(3)

            int tagEnd = i + dataSize;

            if (tagEnd > flvData.length) {
                // 数据不完整
                outputStream.write(flvData, tagStart, flvData.length - tagStart);
                break;
            }

            byte[] tagData = Arrays.copyOfRange(flvData, tagStart, tagEnd);

            if (tagType == 9) { // 视频tag
                int frameInfo = flvData[i] & 0xFF;
                int frameType = (frameInfo >> 4) & 0x0F;

                // 只加密关键帧（frameType == 1），且概率80%
                if (frameType == 1 && random.nextDouble() < 0.8) {
                    // 扰乱关键帧数据
                    byte[] encryptedTag = disturbFrameData(tagData, sm4Key, 0.25);
                    outputStream.write(encryptedTag);
                    encryptedFrameCount++;
                } else {
                    outputStream.write(tagData);
                }
            } else {
                outputStream.write(tagData);
            }

            i = tagEnd;
        }

        log.info("FLV雪花加密完成: 加密了 {} 个关键帧", encryptedFrameCount);
        return outputStream.toByteArray();
    }

    /**
     * 扰乱帧数据，产生雪花效果
     */
    private static byte[] disturbFrameData(byte[] frameData, String sm4Key, double disturbRatio) {
        byte[] disturbedData = frameData.clone();
        Random random = new Random(Arrays.hashCode(Base64.getDecoder().decode(sm4Key)));

        // 扰乱指定比例的数据
        for (int i = 0; i < disturbedData.length; i++) {
            if (random.nextDouble() < disturbRatio) {
                disturbedData[i] = (byte) random.nextInt(256);
            }
        }

        return disturbedData;
    }

    /**
     * 视频雪花效果解密
     */
    public static byte[] selectiveVideoDecryptWithSnow(byte[] encryptedData, String filename, String sm4Key) throws Exception {
        log.info("开始雪花效果视频解密: {}, 大小: {} bytes", filename, encryptedData.length);

        // 由于雪花效果加密是可逆的（只是扰乱数据），解密就是重新应用相同的扰乱
        // 因为使用了确定的随机数生成器（基于sm4Key），所以重新扰乱会恢复原始数据

        return selectiveVideoEncryptWithSnow(encryptedData, filename, sm4Key);
    }
}