package org.example.multimedia_file_security.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

public class Sm4Util {

    /**
     * 静态代码块用于注册Bouncy Castle安全提供者。
     * 这是使用Bouncy Castle实现SM4等算法前的必要步骤[1,2](@ref)。
     */
    static {
        // 判断是否已经注册过，避免重复注册
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 生成SM4算法所需的秘密密钥。
     * SM4的密钥长度固定为128位（16字节）[1,5,6](@ref)。
     *
     * @return 生成的SM4密钥
     * @throws Exception 如果获取算法实例或生成密钥失败则抛出异常
     */
    public static SecretKey generateSm4Key() throws Exception {
        // 1. 获取SM4算法的密钥生成器实例，并指定使用Bouncy Castle提供者[1,2](@ref)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", "BC"); // 或使用 BouncyCastleProvider.PROVIDER_NAME

        // 2. 初始化密钥生成器，明确指定密钥长度为128位[1,6](@ref)
        // 也可以传入一个SecureRandom实例来指定随机数源，例如：keyGenerator.init(128, new SecureRandom());
        keyGenerator.init(128);

        // 3. 生成并返回密钥
        return keyGenerator.generateKey();
    }

}