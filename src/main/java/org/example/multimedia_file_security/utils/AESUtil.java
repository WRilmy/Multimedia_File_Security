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

    private static final String masterKeyBase64 = "MultimediaFIleSecurity";

    /**
     * 加密SM2私钥
     */
    public static String encryptPrivateKey(String sm2PrivateKey) throws Exception {
        // 1. 从用户密码派生加密密钥
        SecretKey encryptionKey = deriveKeyFromPassword(masterKeyBase64);

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
        // 1. 从用户密码派生加密密钥
        SecretKey encryptionKey = deriveKeyFromPassword(masterKeyBase64);

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
    private static SecretKey deriveKeyFromPassword(String password) throws Exception {
        // 使用PBKDF2（密码派生函数）从密码生成密钥
        String salt = "fixed-salt-or-from-config"; // 应该从配置读取
        int iterations = 100000;

        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                password.toCharArray(),
                salt.getBytes(),
                iterations,
                KEY_SIZE
        );

        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
