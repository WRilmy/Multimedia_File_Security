package org.example.multimedia_file_security;

import org.example.multimedia_file_security.utils.HyperchaoticChenUtil;
import org.example.multimedia_file_security.utils.Mp3SelectiveEncryptionUtil;
import org.example.multimedia_file_security.utils.Sm4EncryptionUtil;
import org.example.multimedia_file_security.utils.WavSelectiveEncryptionUtil;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 音频文件选择性加密测试
 */
public class AudioSelectiveEncryptionTest {

    private static final String TEST_WAV_FILE = "test.wav";
    private static final String TEST_MP3_FILE = "test.mp3";
    private static final String SM4_KEY = Base64.getEncoder().encodeToString("test123456789012".getBytes());

    /**
     * 测试WAV文件选择性加密
     */
    @Test
    public void testWavSelectiveEncryption() throws Exception {
        // 读取测试文件
        byte[] originalData = readFile(TEST_WAV_FILE);
        
        // 验证原始文件是有效的WAV
        assertTrue(WavSelectiveEncryptionUtil.isValidWav(originalData));
        
        // 使用超混沌系统进行选择性加密
        HyperchaoticChenUtil.ChenKeyStreamConfig config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();
        byte[] encryptedData = WavSelectiveEncryptionUtil.selectiveEncryptWav(originalData, config);
        
        // 验证加密后文件仍然是有效的WAV
        assertTrue(WavSelectiveEncryptionUtil.isValidWav(encryptedData));
        
        // 解密
        byte[] decryptedData = WavSelectiveEncryptionUtil.decryptWav(encryptedData, config);
        
        // 验证解密后与原始数据一致
        assertArrayEquals(originalData, decryptedData);
        
        System.out.println("WAV选择性加密测试通过");
    }

    /**
     * 测试MP3文件选择性加密
     */
    @Test
    public void testMp3SelectiveEncryption() throws Exception {
        // 读取测试文件
        byte[] originalData = readFile(TEST_MP3_FILE);
        
        // 验证原始文件是有效的MP3
        assertTrue(Mp3SelectiveEncryptionUtil.isValidMp3(originalData));
        
        // 使用超混沌系统进行选择性加密
        HyperchaoticChenUtil.ChenKeyStreamConfig config = HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();
        byte[] encryptedData = Mp3SelectiveEncryptionUtil.selectiveEncryptMp3(originalData, config);
        
        // 验证加密后文件仍然是有效的MP3
        assertTrue(Mp3SelectiveEncryptionUtil.isValidMp3(encryptedData));
        
        // 解密
        byte[] decryptedData = Mp3SelectiveEncryptionUtil.decryptMp3(encryptedData, config);
        
        // 验证解密后与原始数据一致
        assertArrayEquals(originalData, decryptedData);
        
        System.out.println("MP3选择性加密测试通过");
    }

    /**
     * 测试集成到Sm4EncryptionUtil的音频加密
     */
    @Test
    public void testAudioEncryptionIntegration() throws Exception {
        // 测试WAV
        byte[] wavData = readFile(TEST_WAV_FILE);
        byte[] encryptedWav = Sm4EncryptionUtil.fullEncrypt(wavData, SM4_KEY);
        byte[] decryptedWav = Sm4EncryptionUtil.fullDecrypt(encryptedWav, SM4_KEY);
        assertArrayEquals(wavData, decryptedWav);
        
        // 测试MP3
        byte[] mp3Data = readFile(TEST_MP3_FILE);
        byte[] encryptedMp3 = Sm4EncryptionUtil.fullEncrypt(mp3Data, SM4_KEY);
        byte[] decryptedMp3 = Sm4EncryptionUtil.fullDecrypt(encryptedMp3, SM4_KEY);
        assertArrayEquals(mp3Data, decryptedMp3);
        
        System.out.println("音频加密集成测试通过");
    }

    /**
     * 读取文件为字节数组
     */
    private byte[] readFile(String filename) throws Exception {
        File file = new File(filename);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return data;
        }
    }

    /**
     * 写入字节数组到文件
     */
    private void writeFile(String filename, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }
}