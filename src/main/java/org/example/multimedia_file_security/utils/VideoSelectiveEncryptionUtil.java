package org.example.multimedia_file_security.utils;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.zip.CRC32;

/**
 * 视频选择性加密工具类（支持H.264/AVC格式）
 * 参考PNG加密类的设计思路，实现在压缩域的选择性加密
 * 加密后的视频可以被播放器打开，但显示为雪花/马赛克
 * 解密后完全恢复原视频
 */
@Component
@Slf4j
public class VideoSelectiveEncryptionUtil {

    // H.264/AVC起始码（用于定位NAL单元）
    private static final byte[] START_CODE_3 = {0x00, 0x00, 0x01};
    private static final byte[] START_CODE_4 = {0x00, 0x00, 0x00, 0x01};

    // NAL单元类型掩码（nal_unit_type位于NAL头的最低5位）
    private static final int NAL_TYPE_MASK = 0x1F;

    // 重要的NAL单元类型
    private static final int NAL_TYPE_SLICE = 1;      // 非IDR图像的片
    private static final int NAL_TYPE_IDR_SLICE = 5;   // IDR图像的片（关键帧）
    private static final int NAL_TYPE_SEI = 6;         // 补充增强信息
    private static final int NAL_TYPE_SPS = 7;         // 序列参数集
    private static final int NAL_TYPE_PPS = 8;         // 图像参数集

    // 加密比例（控制雪花密度）
    private static final double ENCRYPT_RATIO = 0.99;    // 30%的语法元素被扰乱

    /**
     * NAL单元信息
     */
    @Data
    public static class NalUnit {
        private int startPos;           // 在文件中的起始位置
        private int length;             // 总长度（包含起始码和NAL头）
        private byte[] startCode;        // 起始码（3字节或4字节）
        private byte nalHeader;          // NAL头
        private int nalType;             // NAL单元类型
        private byte[] rbspData;         // RBSP数据（原始字节序列载荷，不含起始码和NAL头）
        private boolean isEncrypted;      // 是否已被加密

        public NalUnit(int startPos, byte[] startCode, byte nalHeader, byte[] rbspData) {
            this.startPos = startPos;
            this.startCode = startCode;
            this.nalHeader = nalHeader;
            this.nalType = nalHeader & NAL_TYPE_MASK;
            this.rbspData = rbspData;
            this.length = startCode.length + 1 + rbspData.length; // 起始码 + NAL头 + RBSP
            this.isEncrypted = false;
        }

        /**
         * 获取完整的NAL单元数据
         */
        public byte[] toByteArray() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(startCode);
                baos.write(nalHeader);
                baos.write(rbspData);
            } catch (IOException e) {
                log.error("组装NAL单元失败", e);
            }
            return baos.toByteArray();
        }
    }

    /**
     * 视频流信息
     */
    @Data
    public static class VideoInfo {
        private List<NalUnit> nalUnits = new ArrayList<>();    // 所有NAL单元
        private List<NalUnit> spsList = new ArrayList<>();      // SPS NAL单元
        private List<NalUnit> ppsList = new ArrayList<>();      // PPS NAL单元
        private List<NalUnit> sliceList = new ArrayList<>();    // 片层NAL单元（可加密）
        private int width;               // 视频宽度（从SPS解析）
        private int height;              // 视频高度（从SPS解析）
        private String profile;          // 编码档次
        private int level;               // 编码级别

        @Override
        public String toString() {
            return String.format("H.264视频[%dx%d, profile=%s, level=%d, NAL单元总数=%d, 可加密片层=%d]",
                    width, height, profile, level, nalUnits.size(), sliceList.size());
        }
    }

    /**
     * 验证是否为有效的H.264/AVC视频流
     */
    public static boolean isValidH264(byte[] videoData) {
        if (videoData.length < 8) return false;

        // 查找第一个起始码
        for (int i = 0; i < videoData.length - 4; i++) {
            if (videoData[i] == 0x00 && videoData[i + 1] == 0x00) {
                if (videoData[i + 2] == 0x01) {
                    return true; // 找到3字节起始码
                } else if (i + 3 < videoData.length &&
                        videoData[i + 2] == 0x00 && videoData[i + 3] == 0x01) {
                    return true; // 找到4字节起始码
                }
            }
        }
        return false;
    }

    /**
     * 解析H.264视频流
     */
    public static VideoInfo parseH264(byte[] videoData) throws IOException {
        if (!isValidH264(videoData)) {
            throw new IllegalArgumentException("无效的H.264视频流");
        }

        VideoInfo videoInfo = new VideoInfo();
        int position = 0;

        while (position < videoData.length) {
            // 查找起始码
            byte[] startCode = null;
            int startCodePos = -1;

            for (int i = position; i < videoData.length - 2; i++) {
                if (videoData[i] == 0x00 && videoData[i + 1] == 0x00) {
                    if (i + 2 < videoData.length && videoData[i + 2] == 0x01) {
                        startCode = START_CODE_3;
                        startCodePos = i;
                        break;
                    } else if (i + 3 < videoData.length &&
                            videoData[i + 2] == 0x00 && videoData[i + 3] == 0x01) {
                        startCode = START_CODE_4;
                        startCodePos = i;
                        break;
                    }
                }
            }

            if (startCodePos == -1) {
                break; // 没有更多起始码
            }

            // 更新position到起始码开始位置
            position = startCodePos;

            // 读取NAL头
            int nalHeaderPos = position + startCode.length;
            if (nalHeaderPos >= videoData.length) break;

            byte nalHeader = videoData[nalHeaderPos];
            int nalType = nalHeader & NAL_TYPE_MASK;

            // 查找下一个起始码，确定当前NAL单元的结束位置
            int nextStartCodePos = videoData.length;
            for (int i = nalHeaderPos + 1; i < videoData.length - 2; i++) {
                if (videoData[i] == 0x00 && videoData[i + 1] == 0x00) {
                    if (i + 2 < videoData.length && videoData[i + 2] == 0x01) {
                        nextStartCodePos = i;
                        break;
                    } else if (i + 3 < videoData.length &&
                            videoData[i + 2] == 0x00 && videoData[i + 3] == 0x01) {
                        nextStartCodePos = i;
                        break;
                    }
                }
            }

            // 提取RBSP数据（从NAL头之后到下一个起始码之前）
            int rbspStart = nalHeaderPos + 1;
            int rbspEnd = nextStartCodePos;
            byte[] rbspData = Arrays.copyOfRange(videoData, rbspStart, rbspEnd);

            // 创建NAL单元
            NalUnit nalUnit = new NalUnit(position, startCode, nalHeader, rbspData);
            videoInfo.getNalUnits().add(nalUnit);

            // 分类存储
            switch (nalType) {
                case NAL_TYPE_SPS:
                    videoInfo.getSpsList().add(nalUnit);
                    parseSps(nalUnit, videoInfo);
                    break;
                case NAL_TYPE_PPS:
                    videoInfo.getPpsList().add(nalUnit);
                    break;
                case NAL_TYPE_SLICE:
                case NAL_TYPE_IDR_SLICE:
                    videoInfo.getSliceList().add(nalUnit);
                    break;
            }

            // 移动到下一个起始码
            position = nextStartCodePos;
        }

        log.info("视频解析完成: {}", videoInfo);
        return videoInfo;
    }

    /**
     * 解析SPS（序列参数集）获取视频尺寸
     */
    private static void parseSps(NalUnit spsNal, VideoInfo videoInfo) {
        byte[] rbsp = spsNal.getRbspData();
        if (rbsp.length < 4) return;

        try {
            // 简化的SPS解析（实际需要完整的EBSP解码）
            // 这里仅提取profile和level
            int profileIdc = rbsp[0] & 0xFF;
            int levelIdc = rbsp[3] & 0xFF;

            String profileStr;
            switch (profileIdc) {
                case 66: profileStr = "Baseline"; break;
                case 77: profileStr = "Main"; break;
                case 100: profileStr = "High"; break;
                default: profileStr = "Unknown(" + profileIdc + ")";
            }

            videoInfo.setProfile(profileStr);
            videoInfo.setLevel(levelIdc);

            // 注意：完整解析宽高需要处理SPS中的seq_parameter_set_data
            // 这需要更复杂的EBSP到RBSP转换和指数哥伦布解码
            // 此处简化处理，实际项目中建议使用JCodec等成熟库
            log.debug("SPS解析: profile={}, level={}", profileStr, levelIdc);

        } catch (Exception e) {
            log.warn("SPS解析失败", e);
        }
    }

    /**
     * 选择性加密视频
     * @param videoData 原始视频数据
     * @param key 加密密钥（Base64编码的SM4密钥）
     * @return 加密后的视频数据
     */
    public static byte[] selectiveEncryptVideo(byte[] videoData, String key) throws Exception {
        log.info("开始视频选择性加密");

        if (!isValidH264(videoData)) {
            throw new IllegalArgumentException("无效的H.264视频流");
        }

        // 解析视频
        VideoInfo videoInfo = parseH264(videoData);

        if (videoInfo.getSliceList().isEmpty()) {
            log.warn("未找到可加密的片层NAL单元，返回原数据");
            return videoData;
        }

        // 使用密钥初始化随机数生成器
        byte[] keyBytes = Base64.getDecoder().decode(key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        int encryptedSlices = 0;

        // 对片层NAL单元进行选择性加密
        for (NalUnit slice : videoInfo.getSliceList()) {
            // 根据随机概率决定是否加密当前片
            if (random.nextDouble() < ENCRYPT_RATIO) {
                encryptSliceNAL(slice, random);
                slice.setEncrypted(true);
                encryptedSlices++;
            }
        }

        log.info("加密了 {}/{} 个片层NAL单元", encryptedSlices, videoInfo.getSliceList().size());

        // 重建视频
        return rebuildVideo(videoInfo, videoData);
    }

    /**
     * 选择性解密视频
     */
    public static byte[] selectiveDecryptVideo(byte[] encryptedVideoData, String key) throws Exception {
        log.info("开始视频选择性解密");

        // 解密过程与加密完全相同（异或的可逆性）
        return selectiveEncryptVideo(encryptedVideoData, key);
    }

    /**
     * 加密片层NAL单元
     * 核心：对变换系数符号位进行异或扰乱，保持数据长度不变
     */
    private static void encryptSliceNAL(NalUnit slice, Random random) {
        byte[] rbsp = slice.getRbspData();
        if (rbsp.length < 4) return;

        // H.264片层语法元素定位（简化版）
        // 实际需要解析片头（slice_header）找到系数数据的位置
        // 这里采用一种简化方法：扰乱RBSP中的非零字节，但避开起始码模拟预防字节

        int modifiedBytes = 0;
        boolean inEmulationPrevention = false;

        for (int i = 0; i < rbsp.length; i++) {
            // 检测起始码模拟预防字节（0x03）
            // H.264中，如果出现连续的0x00 0x00，会在后面插入0x03
            if (i >= 2 && rbsp[i - 2] == 0x00 && rbsp[i - 1] == 0x00 && rbsp[i] == 0x03) {
                inEmulationPrevention = true;
                continue;
            }

            if (inEmulationPrevention) {
                inEmulationPrevention = false;
                continue;
            }

            // 只扰乱非零字节，保持压缩效率
            if (rbsp[i] != 0 && random.nextDouble() < 0.5) {
                // 对字节进行异或，但避免产生0x00 0x00序列
                byte original = rbsp[i];
                byte modified;
                do {
                    modified = (byte) (original ^ (random.nextInt(255) + 1));
                } while (modified == 0 && i > 0 && rbsp[i - 1] == 0); // 避免产生连续的00

                rbsp[i] = modified;
                modifiedBytes++;
            }
        }

        log.debug("NAL单元类型 {} 中扰乱了 {} 字节", slice.getNalType(), modifiedBytes);
    }

    /**
     * 重建视频流
     */
    private static byte[] rebuildVideo(VideoInfo videoInfo, byte[] originalVideo) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            int currentPos = 0;

            for (NalUnit nal : videoInfo.getNalUnits()) {
                // 写入当前NAL单元之前的数据（如起始码之前的部分）
                if (nal.getStartPos() > currentPos) {
                    baos.write(Arrays.copyOfRange(originalVideo, currentPos, nal.getStartPos()));
                }

                // 写入当前NAL单元
                baos.write(nal.toByteArray());

                currentPos = nal.getStartPos() + nal.getLength();
            }

            // 写入剩余数据
            if (currentPos < originalVideo.length) {
                baos.write(Arrays.copyOfRange(originalVideo, currentPos, originalVideo.length));
            }

        } catch (IOException e) {
            log.error("重建视频失败", e);
        }

        return baos.toByteArray();
    }

    /**
     * 计算CRC32校验和（用于验证文件完整性）
     */
    public static long calculateCRC32(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }

    /**
     * 简化的视频加密方法（适用于测试）
     * 对指定的NAL类型进行加密
     */
    public static byte[] simpleEncryptVideo(byte[] videoData, String key, int... nalTypesToEncrypt) throws Exception {
        if (nalTypesToEncrypt.length == 0) {
            nalTypesToEncrypt = new int[]{NAL_TYPE_SLICE, NAL_TYPE_IDR_SLICE};
        }

        Set<Integer> targetTypes = new HashSet<>();
        for (int type : nalTypesToEncrypt) {
            targetTypes.add(type);
        }

        VideoInfo videoInfo = parseH264(videoData);
        byte[] keyBytes = Base64.getDecoder().decode(key);
        Random random = new Random(Arrays.hashCode(keyBytes));

        for (NalUnit nal : videoInfo.getNalUnits()) {
            if (targetTypes.contains(nal.getNalType())) {
                if (random.nextDouble() < ENCRYPT_RATIO) {
                    encryptSliceNAL(nal, random);
                }
            }
        }

        return rebuildVideo(videoInfo, videoData);
    }
}
