package com.example.demo;


import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * <p>
 * RSA公钥/私钥/签名工具包
 * </p>
 * <p>
 *
 * </p>
 * <p>
 * 字符串格式的密钥在未在特殊说明情况下都为BASE64编码格式<br/>
 * 由于非对称加密速度极其缓慢，一般文件不使用它来加密而是使用对称加密，<br/>
 * 非对称加密算法可以用来对对称加密的密钥加密，这样保证密钥的安全也就保证了数据的安全
 * </p>
 *
 * @author wechart
 * @version 1.0
 * @date 2016-4-26
 */
public class RSAUtils {

    public static final String KEY_ALGORITHM = "RSA";                   //加密算法RSA

    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";      //签名算法

    private static final String PUBLIC_KEY = "RSAPublicKey";            //获取公钥的KEY

    private static final String PRIVATE_KEY = "RSAPrivateKey";          //获取私钥的KEY

    private static final int MAX_ENCRYPT_BLOCK = 117;                   //RSA最大加密明文大小

    private static final int MAX_DECRYPT_BLOCK = 128;                   //RSA最大解密密文大小

    /**
     * <p>
     * 生成密钥对(公钥和私钥)
     * </p>
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * <p>
     * 用私钥对信息生成数字签名
     * </p>
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }

    /**
     * <p>
     * 校验数字签名
     * </p>
     *
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));
    }

    /** */
    /**
     * <P>
     * 私钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /** */
    /**
     * <p>
     * 解码后公钥解密返回字符串
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String decodeAndDecryptByPublicKey2Str(String encryptedData, String publicKey) throws Exception {
        return new String(decodeAndDecryptByPublicKey(encryptedData, publicKey), "UTF-8");
    }

    /** */
    /**
     * <p>
     * 解码后公钥解密返回数组
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decodeAndDecryptByPublicKey(String encryptedData, String publicKey) throws Exception {
        return decryptByPublicKey(Base64Utils.decode(encryptedData), publicKey);
    }

    /** */
    /**
     * <p>
     * 公钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    public static String encryptByPublicKeyAndEncode(String data, String publicKey) throws Exception {
        return Base64Utils.encode(encryptByPublicKey(data, publicKey));
    }

    /**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param data       源数据（String）
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(String data, String publicKey) throws Exception {
        return encryptByPublicKey(data.getBytes("UTF-8"), publicKey);
    }
    /** */
    /**
     * <p>
     * 公钥加密
     * </p>
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * <p>
     * 私钥加密并且编码
     * </p>
     *
     * @param data       源数据（String）
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKeyAndEncode(String data, String privateKey) throws Exception {
        return Base64Utils.encode(encryptByPrivateKey(data, privateKey));
    }

    /**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param data       源数据（String）
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(String data, String privateKey) throws Exception {
        return encryptByPrivateKey(data.getBytes("UTF-8"), privateKey);
    }

    /**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param data       源数据(Byte[])
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    private static byte[] encryptByPrivateKey(byte[] data, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * <p>
     * 获取私钥
     * </p>
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    /**
     * <p>
     * 获取公钥
     * </p>
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    public static PublicKey loadPublicKeyByFile(String filepath) throws Exception {
        try {
            //通过证书,获取公钥
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate c = cf.generateCertificate(new FileInputStream(filepath));
            PublicKey publicKey = c.getPublicKey();
            return publicKey;
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }

    public static PrivateKey loadPrivateKeyByFile(String filepath, String alias, String password) throws Exception {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(filepath), password.toCharArray());

            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
            return privateKey;
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        }
    }

    public static void main(String[] args) {
        String serverAlias = "";
        String clientAlias = "acosta";

        String serverPassword = "";
        String clientPassword = "acosta";

//      String serverPrivateKey = "d:\\server.keystore";
//      String serverPublicKey = "d:\\server.cer";

        String clientPrivateKey = "E:\\TestCER\\RSATest04\\acosta.keystore";
        String clientPublicKey = "E:\\TestCER\\RSATest04\\acosta.cer";
//
//      String serverPublicString = "";
//      String serverPrivateString = "";
        String clientPublicString = "";
        String clientPrivateString = "";


        String orgString = "{\"ret\":\"0\",\"ExpireTime\":\"2015/10/28 23:59:59\",\"rettxt\":\"OK\",\"Token\":\"69296128A59798E2D423D3B1A9F766F4\"}'";

        String encryptString = "";
        String decryptString = "";

//      RSAPublicKey srvPubKey = null;
        RSAPublicKey cltPubKey = null;
//      RSAPrivateKey srvPriKey = null;
        RSAPrivateKey cltPriKey = null;

        try {
            //1- 客户端公钥
            cltPubKey = (RSAPublicKey) RSAUtils.loadPublicKeyByFile(clientPublicKey);

            //2- 客户端私钥
            cltPriKey = (RSAPrivateKey) RSAUtils.loadPrivateKeyByFile(clientPrivateKey, clientAlias, clientPassword);

//          //3- 服务端公钥
//          srvPubKey = (RSAPublicKey) RSAUtils.loadPublicKeyByFile(serverPublicKey);
//
//          //4- 服务端私钥
//          srvPriKey = (RSAPrivateKey) RSAUtils.loadPrivateKeyByFile(serverPrivateKey, serverAlias, serverPassword);

            System.out.println("\nclientPublicString:\n" + Base64Utils.encode(cltPubKey.getEncoded()) + "\n");
            System.out.println("\nclientPrivateString:\n" + Base64Utils.encode(cltPriKey.getEncoded()) + "\n");
//          System.out.println("\nserverPublicString:\n"+Base64Utils.encode(srvPubKey.getEncoded())+"\n");
//          System.out.println("\nserverPrivateString:\n"+Base64Utils.encode(srvPriKey.getEncoded())+"\n");
        } catch (Exception e) {
            e.printStackTrace();
        }

//      System.out.println("\n=============================== Step-1:客户端私钥加密-服务端公钥解密\n");
//      //客户端私钥加密-服务端公钥解密
//      try{
//          byte[] data = orgString.getBytes();
//
//          byte[] encodedData = RSAUtils.encryptByPrivateKey(data, Base64Utils.encode(cltPriKey.getEncoded()));
//          encryptString = new String(encodedData);
//
//          byte[] decodedData = RSAUtils.decryptByPublicKey(encodedData, Base64Utils.encode(srvPubKey.getEncoded()));
//          decryptString = new String(decodedData);
//
//          System.out.println("orginalString:"+orgString);
//          System.out.println("encrypString:"+encryptString);
//          System.out.println("decryptString:"+decryptString);
//      }catch(Exception e){
//          System.err.println("Step-1 解密失败!");
//      }
//
//      System.out.println("\n=============================== Step-2:服务端私钥加密-客户端公钥解密\n");
//      //服务端私钥加密-客户端公钥解密
//      try{
//
//
//          byte[] data = orgString.getBytes();
//
//          byte[] encodedData = RSAUtils.encryptByPrivateKey(data, Base64Utils.encode(srvPriKey.getEncoded()));
//          encryptString = new String(encodedData);
//
//          byte[] decodedData = RSAUtils.decryptByPublicKey(encodedData, Base64Utils.encode(cltPubKey.getEncoded()));
//          decryptString = new String(decodedData);
//
//          System.out.println("orginalString:"+orgString);
//          System.out.println("encrypString:"+encryptString);
//          System.out.println("decryptString:"+decryptString);
//      }catch(Exception e){
//          System.err.println("Step-2 解密失败!");
//      }

        System.out.println("\n=============================== Step-3:客户端私钥加密-客户端公钥解密\n");

        String orgString2 = "";
        //客户端私钥加密-客户端公钥解密
        try {
            byte[] data = orgString.getBytes();

            byte[] encodedData = RSAUtils.encryptByPrivateKey(data, Base64Utils.encode(cltPriKey.getEncoded()));
            encryptString = new String(encodedData);

            byte[] decodedData = RSAUtils.decryptByPublicKey(encodedData, Base64Utils.encode(cltPubKey.getEncoded()));
            decryptString = new String(decodedData);

            System.out.println("orginalString:" + orgString);
            System.out.println("encrypString:" + encryptString);
            System.out.println("decryptString:" + decryptString);
        } catch (Exception e) {
            System.err.println("Step-3  解密失败!");
        }
//
//      System.out.println("\n=============================== Step-4:服务端私钥加密-服务端公钥解密\n");
//      //服务端私钥加密-服务端公钥解密
//      try{
//
//          byte[] data = orgString.getBytes();
//
//          byte[] encodedData = RSAUtils.encryptByPrivateKey(data, Base64Utils.encode(srvPriKey.getEncoded()));
//          encryptString = new String(encodedData);
//
//          byte[] decodedData = RSAUtils.decryptByPublicKey(encodedData, Base64Utils.encode(srvPubKey.getEncoded()));
//          decryptString = new String(decodedData);
//
//          System.out.println("orginalString:"+orgString);
//          System.out.println("encrypString:"+encryptString);
//          System.out.println("decryptString:"+decryptString);
//      }catch(Exception e){
//          System.err.println("Step-4 解密失败!");
//      }
//
    }

}
