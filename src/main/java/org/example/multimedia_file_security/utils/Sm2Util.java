package org.example.multimedia_file_security.utils;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SM4;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;

@Component
@Slf4j
public class Sm2Util {

    /**
     * 生成SM2密钥对
     * @return [0]=公钥(Base64), [1]=加密后的私钥(Base64)
     */
    public String[] generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(256, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 公钥
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // 私钥（先用一个临时密钥加密存储）
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String encryptedPrivateKey = encryptPrivateKey(privateKey);

        return new String[]{publicKey, encryptedPrivateKey};
    }

    /**
     * 加密私钥（实际项目中应使用更安全的方式）
     */
    private String encryptPrivateKey(String privateKey) {
        // 这里使用一个固定的密钥加密，实际项目应该使用更安全的方案
        // 例如：使用用户密码派生密钥，或使用KMS服务
        SM4 sm4 = SmUtil.sm4("1234567890123456".getBytes());
        return sm4.encryptBase64(privateKey);
    }

    /**
     * 解密私钥
     */
    public String decryptPrivateKey(String encryptedPrivateKey) {
        SM4 sm4 = SmUtil.sm4("1234567890123456".getBytes());
        return sm4.decryptStr(encryptedPrivateKey);
    }

    /**
     * 使用公钥加密数据
     */
    public String encryptWithPublicKey(String data, String publicKey) {
        SM2 sm2 = SmUtil.sm2(null, publicKey);
        return sm2.encryptBase64(data, KeyType.PublicKey);
    }

    /**
     * 使用私钥解密数据
     */
    public String decryptWithPrivateKey(String encryptedData, String privateKey) {
        SM2 sm2 = SmUtil.sm2(privateKey, null);
        return sm2.decryptStr(encryptedData, KeyType.PrivateKey);
    }
}
