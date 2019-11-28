package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import org.junit.Assert;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Map;

/**
 * **1、对称加密与非对称加密**
 * <p>
 * 对称加密：
 * 加密与解密需要使用相同的密钥，或者加密密钥和解密密钥是简单可以换算。
 * 常见的对称加密：DES、3DES、AES、RC5、RC6等等
 * 优缺点：速度快效率高、网络传输中不安全
 * <p>
 * 非对称加密：
 * 需要一对密钥：一个是私人密钥，另一个则是公开密钥。公钥加密只能使用私钥解密，私钥加密只能使用公钥解码。一般公钥是公开的，私钥是服务器私有的。
 * 常见的非加密算法：RSA、
 * 优缺点：安全性高，加解密效率低
 * <p>
 * 中和方案：
 * DES的密钥通过非对称加密传输，
 */
@SpringBootTest
class DemoApplicationTests {


    @Test
    void contextLoads() {
        try {
            Map<String, Object> keys = RSAUtils.genKeyPair();
            String privateKey = RSAUtils.getPrivateKey(keys);
            String publicKey = RSAUtils.getPublicKey(keys);

            String encryptStr = RSAUtils.encryptByPrivateKeyAndEncode("wgl", privateKey);
            String decryptStrs = RSAUtils.decodeAndDecryptByPublicKey2Str(encryptStr, publicKey);
            System.out.println(decryptStrs);
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
    }
}
