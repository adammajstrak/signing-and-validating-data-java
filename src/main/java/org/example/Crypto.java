package org.example;

import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public final class Crypto {
    public static String signData(String text, String keyStorePath, String keyStorePassword) throws Exception {
        var keyStore = getKeyStore(keyStorePath, keyStorePassword);
        var privateKey = (PrivateKey) keyStore.getKey("test", "Test".toCharArray());

        var dataToValidate = text.getBytes("UTF8");

        var sig = Signature.getInstance("SHA512WithRSA");
        sig.initSign(privateKey);
        sig.update(dataToValidate);
        var signatureBytes = sig.sign();
        var signature = Base64.encodeBase64String(signatureBytes);
        return signature;
    }

    public static boolean verifyData(String text, String signature, String keyStorePath, String keyStorePassword) throws Exception {
        var keyStore = getKeyStore(keyStorePath, keyStorePassword);
        var publicKey = keyStore.getCertificate("test").getPublicKey();
        var sig = Signature.getInstance("SHA512WithRSA");

        var dataToValidate = text.getBytes("UTF8");

        sig.initVerify(publicKey);
        sig.update(dataToValidate);
        return sig.verify(Base64.decodeBase64(signature));
    }

    public static boolean verifyDataWitPublicKey(String text, String signature, String publicKeyPath) throws Exception {
        var key = new String(Files.readAllBytes(new File(publicKeyPath).toPath()));
        var publicKeyPem = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyPem));
        var publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

        var sig = Signature.getInstance("SHA512WithRSA");

        var dataToValidate = text.getBytes("UTF8");

        sig.initVerify(publicKey);
        sig.update(dataToValidate);
        return sig.verify(Base64.decodeBase64(signature));
    }

    private static KeyStore getKeyStore(String path, String password) throws Exception {
        FileInputStream keyStoreStream = new FileInputStream(path);
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(keyStoreStream, password.toCharArray());
        return keyStore;
    }
}
