package org.example.multimedia_file_security.utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 密钥派生工具类
 * 使用PBKDF2算法从密码或随机数据派生密钥
 */
public class KeyDerivationUtil {

    private static final String ALGORITHM = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 256; // AES-256
    private static final int SALT_SIZE = 16; // 128位盐值
    private static final int ITERATIONS = 100000; // 迭代次数

    /**
     * 生成随机盐值
     * @return Base64编码的盐值
     */
    public static String generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * 从密码派生密钥
     * @param password 用户密码
     * @param salt 盐值
     * @return 派生的AES密钥
     * @throws Exception 密钥派生异常
     */
    public static SecretKey deriveKeyFromPassword(String password, String salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                Base64.getDecoder().decode(salt),
                ITERATIONS,
                KEY_SIZE
        );

        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * 从随机数据派生密钥（用于系统级密钥）
     * @param seed 种子数据
     * @param salt 盐值
     * @return 派生的AES密钥
     * @throws Exception 密钥派生异常
     */
    public static SecretKey deriveKeyFromSeed(String seed, String salt) throws Exception {
        return deriveKeyFromPassword(seed, salt);
    }

    /**
     * 生成随机密钥（用于临时会话）
     * @return Base64编码的随机密钥
     * @throws Exception 密钥生成异常
     */
    public static String generateRandomKey() throws Exception {
        javax.crypto.KeyGenerator keyGenerator = javax.crypto.KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        SecretKey key = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 从Base64字符串恢复密钥
     * @param keyBase64 Base64编码的密钥
     * @return AES密钥
     */
    public static SecretKey restoreKeyFromBase64(String keyBase64) {
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * 验证密钥强度
     * @param password 密码
     * @return 是否强密码
     */
    public static boolean isStrongPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }
        
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            if (Character.isLowerCase(c)) hasLower = true;
            if (Character.isDigit(c)) hasDigit = true;
            if (!Character.isLetterOrDigit(c)) hasSpecial = true;
        }
        
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
}
