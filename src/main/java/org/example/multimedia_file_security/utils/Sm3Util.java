package org.example.multimedia_file_security.utils;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

/**
 * SM3文件哈希计算工具类
 * 使用国密SM3算法进行文件完整性验证
 */
@Component
public class Sm3Util {

    static {
        // 注册BouncyCastle安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 计算输入流的SM3哈希值
     * @param inputStream 输入流
     * @return 64字符的十六进制哈希字符串
     * @throws IOException 流读取异常
     */
    public static String calculateFileHash(InputStream inputStream) throws IOException {
        SM3Digest digest = new SM3Digest();
        byte[] buffer = new byte[8192]; // 8KB缓冲区
        int bytesRead;

        try (InputStream is = inputStream) {
            while ((bytesRead = is.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }

            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return bytesToHex(hash);
        }
    }

    /**
     * 计算字节数组的SM3哈希值
     * @param data 字节数组
     * @return 64字符的十六进制哈希字符串
     */
    public static String calculateHash(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return bytesToHex(hash);
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
