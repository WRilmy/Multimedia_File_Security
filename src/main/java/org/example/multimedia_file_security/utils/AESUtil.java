package org.example.multimedia_file_security.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Component
@Slf4j
public class AESUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // 128位认证标签
    private static final int IV_LENGTH = 12;   // 12字节IV（推荐值）
    private static final int KEY_SIZE = 256;   // AES-256



    // 系统级密钥，实际部署时应该从配置文件或环境变量读取
    private static final String SYSTEM_KEY = "MultimediaFileSecuritySystemKey2026";
    private static final String SYSTEM_SALT = "SystemSalt20260319";

    /**
     * 加密SM2私钥
     */
    public static String encryptPrivateKey(String sm2PrivateKey) throws Exception {
        // 1. 从系统密钥派生加密密钥
        SecretKey encryptionKey = deriveKeyFromPassword(SYSTEM_KEY, SYSTEM_SALT);

        // 2. 生成随机IV
        byte[] iv = generateIv();

        // 3. 初始化加密器
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmSpec);

        // 4. 加密私钥
        byte[] encryptedData = cipher.doFinal(sm2PrivateKey.getBytes());

        // 5. 组合 IV + 加密数据
        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * 解密SM2私钥
     */
    public static String decryptPrivateKey(String encryptedPrivateKey) throws Exception {
        // 1. 从系统密钥派生加密密钥
        SecretKey encryptionKey = deriveKeyFromPassword(SYSTEM_KEY, SYSTEM_SALT);

        // 2. 解码Base64
        byte[] data = Base64.getDecoder().decode(encryptedPrivateKey);

        // 3. 提取IV
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(data, 0, iv, 0, iv.length);

        // 4. 提取加密数据
        byte[] encryptedData = new byte[data.length - iv.length];
        System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);

        // 5. 初始化解密器
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, gcmSpec);

        // 6. 解密私钥
        byte[] decryptedData = cipher.doFinal(encryptedData);

        return new String(decryptedData);
    }

    /**
     * 从用户密码派生加密密钥
     */
    private static SecretKey deriveKeyFromPassword(String password, String salt) throws Exception {
        // 使用KeyDerivationUtil进行密钥派生
        return KeyDerivationUtil.deriveKeyFromPassword(password, salt);
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
