package org.example.multimedia_file_security.utils;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@Slf4j
public class Sm2Util {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // SM2曲线参数
    private static final String CURVE_NAME = "sm2p256v1";
    private static final ECNamedCurveParameterSpec SM2_CURVE = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
    private static final ECCurve CURVE = SM2_CURVE.getCurve();

    /**
     * 生成SM2密钥对
     * @return [0]=公钥(Base64), [1]=加密后的私钥(Base64)
     */
    public static String[] generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(256, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 公钥
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // 私钥
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        return new String[]{publicKey, privateKey};
    }

    /**
     * 使用公钥加密数据
     */
    public static String encryptWithPublicKey(String data, String publicKey) {
        SM2 sm2 = SmUtil.sm2(null, publicKey);
        return sm2.encryptBase64(data, KeyType.PublicKey);
    }

    /**
     * 使用私钥解密数据
     */
    public static String decryptWithPrivateKey(String encryptedData, String privateKey) {
        SM2 sm2 = SmUtil.sm2(privateKey, null);
        return sm2.decryptStr(encryptedData, KeyType.PrivateKey);
    }

    /**
     * 使用SM2私钥签名数据
     */
    public static String signWithSm2(String data, String privateKey) throws Exception {
        Signature signature = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString(),
                BouncyCastleProvider.PROVIDER_NAME
        );

        PrivateKey privateKey2 = base64ToPrivateKey(privateKey);

        signature.initSign(privateKey2);
        signature.update(data.getBytes());

        byte[] signBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signBytes);
    }

    /**
     * 使用SM2公钥验证签名
     */
    public static boolean verifyWithSm2(String data, String sign, String publicKey) throws Exception {
        Signature signature = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString(),
                BouncyCastleProvider.PROVIDER_NAME
        );

        PublicKey publicKey2 = base64ToPublicKey(publicKey);

        signature.initVerify(publicKey2);
        signature.update(data.getBytes());

        return signature.verify(Base64.getDecoder().decode(sign));
    }

    /**
     * 从Base64字符串恢复私钥
     */
    public static PrivateKey base64ToPrivateKey(String base64PrivateKey) throws Exception {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey.trim());

            // 调试：打印密钥信息
            log.debug("私钥字节长度: {}", keyBytes.length);
            log.debug("私钥Hex: {}", bytesToHex(keyBytes));

            // 尝试解析为PKCS8格式
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            return privateKey;

        } catch (Exception e) {
            log.error("解析私钥失败: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * 从Base64字符串恢复公钥
     */
    public static PublicKey base64ToPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey.trim());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePublic(keySpec);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
